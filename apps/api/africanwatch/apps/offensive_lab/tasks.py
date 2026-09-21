"""Celery jobs for authorized security assessments."""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
from time import monotonic

from celery import shared_task
from django.conf import settings
from django.db import transaction
from django.utils import timezone

logger = logging.getLogger("africanwatch.offensive_lab")


def canonical_scope(engagement) -> list[dict]:
    return list(
        engagement.targets.select_related("asset")
        .filter(enabled=True)
        .values("asset_id", "asset__asset_type", "asset__value")
        .order_by("asset_id")
    )


def scope_hash(engagement) -> str:
    payload = json.dumps(canonical_scope(engagement), sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_event(job, event_type: str, payload: dict) -> None:
    from .models import AssessmentEvent
    previous = AssessmentEvent.objects.filter(job=job).order_by("-id").first()
    previous_hash = previous.event_hash if previous else ""
    body = json.dumps({"event_type": event_type, "payload": payload, "previous_hash": previous_hash}, sort_keys=True, ensure_ascii=False, default=str)
    event_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    AssessmentEvent.objects.create(job=job, event_type=event_type, payload=payload, previous_hash=previous_hash, event_hash=event_hash)


def persist_findings(job, findings: list[dict]) -> int:
    from .models import AssessmentFinding
    count = 0
    for finding in findings[:100]:
        canonical = json.dumps({
            "category": finding.get("category"), "title": finding.get("title"), "evidence": finding.get("evidence", {}),
        }, sort_keys=True, ensure_ascii=False, default=str)
        fp = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        AssessmentFinding.objects.update_or_create(
            job=job,
            fingerprint=fp,
            defaults={
                "severity": str(finding.get("severity", "info"))[:10],
                "category": str(finding.get("category", "general"))[:80],
                "title": str(finding.get("title", "Finding"))[:255],
                "description": str(finding.get("description", ""))[:5000],
                "evidence": finding.get("evidence") or {},
                "remediation": str(finding.get("remediation", ""))[:5000],
                "confidence": float(finding.get("confidence", 1.0) or 1.0),
            },
        )
        count += 1
    return count


@shared_task(bind=True, max_retries=24, queue="scans", time_limit=180, soft_time_limit=165)
def run_assessment(self, job_id: str):
    from africanwatch.apps.offensive_lab.models import AssessmentJob
    from africanwatch.apps.offensive_lab.runner import run_profile

    started = monotonic()
    with transaction.atomic():
        job = AssessmentJob.objects.select_for_update().select_related("target__asset").get(id=job_id)
        # Lock the engagement row so two workers cannot pass the concurrency ceiling simultaneously.
        from africanwatch.apps.offensive_lab.models import Engagement
        engagement = Engagement.objects.select_for_update().get(id=job.engagement_id)
        job.engagement = engagement
        current_scope = scope_hash(engagement)
        if job.status == AssessmentJob.Status.CANCELLED:
            return {"status": "cancelled"}
        if not engagement.is_active_now or not job.target.enabled or not job.target.asset.is_active or not job.target.asset.scan_enabled:
            job.status = AssessmentJob.Status.BLOCKED
            job.error_message = "Engagement, actif ou cible non autorisé(e)."
            job.completed_at = timezone.now()
            job.save(update_fields=["status", "error_message", "completed_at"])
            append_event(job, "blocked", {"reason": job.error_message})
            return {"status": "blocked"}
        if current_scope != job.scope_hash_at_launch:
            job.status = AssessmentJob.Status.BLOCKED
            job.error_message = "Le périmètre a changé depuis le lancement ; nouvelle approbation requise."
            job.completed_at = timezone.now()
            job.save(update_fields=["status", "error_message", "completed_at"])
            append_event(job, "blocked_scope_changed", {"expected": job.scope_hash_at_launch, "actual": current_scope})
            return {"status": "blocked"}
        if engagement.lab_mode and not getattr(settings, "LAB_MODE", False):
            job.status = AssessmentJob.Status.BLOCKED
            job.error_message = "Mode LAB non activé côté serveur."
            job.completed_at = timezone.now()
            job.save(update_fields=["status", "error_message", "completed_at"])
            append_event(job, "blocked_lab_policy", {})
            return {"status": "blocked"}

        running_count = AssessmentJob.objects.filter(
            engagement=engagement, status=AssessmentJob.Status.RUNNING
        ).exclude(id=job.id).count()
        if running_count >= engagement.max_concurrent_jobs:
            append_event(job, "concurrency_wait", {"running": running_count, "limit": engagement.max_concurrent_jobs})
            raise self.retry(
                countdown=max(1, int(getattr(settings, "SECURITY_ASSESSMENT_CONCURRENCY_RETRY_SECONDS", 5))),
                exc=RuntimeError("Engagement concurrency ceiling reached"),
            )

        job.status = AssessmentJob.Status.RUNNING
        job.started_at = timezone.now()
        job.execution_nonce = secrets.token_hex(32)
        job.command_summary = f"profile={job.profile}; registered_asset={job.target.asset.id}; non_interactive=true"
        job.save(update_fields=["status", "started_at", "execution_nonce", "command_summary"])
        append_event(job, "started", {"profile": job.profile, "scope_hash": current_scope})

    try:
        target = job.target.asset.value
        result = run_profile(job.profile, target, allow_private=bool(engagement.lab_mode and getattr(settings, "LAB_MODE", False)))
        findings = result.get("findings") or []
        digest = hashlib.sha256(json.dumps(result, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")).hexdigest()
        duration = round(monotonic() - started, 3)
        with transaction.atomic():
            job = AssessmentJob.objects.select_for_update().get(id=job_id)
            # A cancellation can race with a long-running scanner. Never let a
            # completed worker resurrect a job that an operator already cancelled.
            if job.status == AssessmentJob.Status.CANCELLED:
                append_event(job, "discarded_after_cancel", {"result_sha256": digest})
                return {"status": "cancelled"}
            job.result = result
            job.stdout = str(result.get("ports", {}).get("stdout", ""))[:80_000]
            job.stderr = str(result.get("ports", {}).get("stderr", ""))[:20_000]
            job.result_sha256 = digest
            job.duration_seconds = duration
            job.status = AssessmentJob.Status.COMPLETED
            job.completed_at = timezone.now()
            job.save(update_fields=["result", "stdout", "stderr", "result_sha256", "duration_seconds", "status", "completed_at"])
            persisted = persist_findings(job, findings)
            append_event(job, "completed", {"result_sha256": digest, "finding_count": persisted, "duration_seconds": duration})
        logger.info("Assessment %s completed for %s", job_id, target)
        return {"status": AssessmentJob.Status.COMPLETED, "sha256": digest, "finding_count": len(findings)}
    except AssessmentJob.DoesNotExist:
        return {"status": "missing"}
    except Exception as exc:
        logger.exception("Assessment failed: %s", job_id)
        with transaction.atomic():
            job = AssessmentJob.objects.select_for_update().get(id=job_id)
            job.status = AssessmentJob.Status.FAILED
            job.error_message = str(exc)[:1000]
            job.duration_seconds = round(monotonic() - started, 3)
            job.completed_at = timezone.now()
            job.save(update_fields=["status", "error_message", "duration_seconds", "completed_at"])
            append_event(job, "failed", {"error": str(exc)[:500]})
        raise self.retry(exc=exc)
