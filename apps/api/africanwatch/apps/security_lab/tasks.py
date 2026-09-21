from __future__ import annotations
import hashlib
import json
import time
from celery import shared_task
from django.utils import timezone


def _persist_findings(review, findings):
    from .models import SecurityFinding
    count = 0
    for f in findings[:150]:
        payload = json.dumps({"framework": f.get("framework"), "control_id": f.get("control_id"), "title": f.get("title"), "evidence": f.get("evidence", {})}, sort_keys=True, ensure_ascii=False, default=str)
        fp = hashlib.sha256(payload.encode()).hexdigest()
        SecurityFinding.objects.update_or_create(review=review, fingerprint=fp, defaults={
            "framework": str(f.get("framework", ""))[:40], "control_id": str(f.get("control_id", ""))[:80],
            "severity": str(f.get("severity", "info"))[:10], "title": str(f.get("title", "Finding"))[:255],
            "description": str(f.get("description", ""))[:5000], "evidence": f.get("evidence") or {},
            "remediation": str(f.get("remediation", ""))[:5000], "confidence": float(f.get("confidence", 1.0) or 1.0),
        })
        count += 1
    review.findings_count = count
    review.save(update_fields=["findings_count"])
    return count


@shared_task(bind=True, queue="security_lab", max_retries=2, time_limit=360, soft_time_limit=330)
def run_security_review(self, review_id: str):
    from .models import SecurityReview
    from .owasp import web_review, api_review
    from .db_audit import postgres_posture
    from .local_tools import local_sast, local_container, local_secrets, credential_audit, remote_auth_plan, injection_test_plan, availability
    review = SecurityReview.objects.select_related("asset", "organization").get(id=review_id)
    if review.status == SecurityReview.Status.RUNNING:
        return
    review.status = SecurityReview.Status.RUNNING
    review.started_at = timezone.now()
    review.save(update_fields=["status", "started_at"])
    start = time.monotonic()
    try:
        profile = review.profile
        if profile == SecurityReview.Profile.OWASP_WEB:
            if not review.asset:
                raise ValueError("Un actif est requis")
            result = web_review(review.asset.value, allow_private=False)
        elif profile == SecurityReview.Profile.OWASP_API:
            payload = review.input_ref or ""
            if payload.lstrip().startswith(("http://", "https://")):
                from africanwatch.security.outbound import safe_get
                response = safe_get(payload, timeout=10.0, max_bytes=500_000)
                payload = response.text
            result = api_review(payload)
        elif profile == SecurityReview.Profile.DB_POSTURE:
            result = postgres_posture(review.input_ref, review.organization_id)
        elif profile == SecurityReview.Profile.DB_CODE_SURFACE:
            result = local_sast(review.organization_id, review.input_ref)
        elif profile == SecurityReview.Profile.LOCAL_CODE:
            result = local_sast(review.organization_id, review.input_ref)
        elif profile == SecurityReview.Profile.LOCAL_CONTAINER:
            result = local_container(review.organization_id, review.input_ref)
        elif profile == SecurityReview.Profile.LOCAL_SECRETS:
            result = local_secrets(review.organization_id, review.input_ref)
        elif profile == SecurityReview.Profile.LOCAL_CREDENTIAL:
            parts = (review.input_ref or "").split("::", 1)
            result = credential_audit(review.organization_id, parts[0], parts[1] if len(parts) == 2 else "")
        elif profile == SecurityReview.Profile.ZAP_BASELINE_PLAN:
            result = {"plan": "docker run --rm -t zaproxy/zap-stable zap-baseline.py -t <AUTHORIZED_TARGET>", "mode": "plan-only", "tool": "zap", "execution": False}
        elif profile == SecurityReview.Profile.HYDRA_READINESS:
            target, service = ((review.input_ref or "").split("::", 1) + ["http-post-form"])[:2]
            result = remote_auth_plan(target, service)
        elif profile == SecurityReview.Profile.SQLMAP_READINESS:
            result = injection_test_plan(review.input_ref)
        elif profile == SecurityReview.Profile.TOOLCHAIN:
            result = {"tools": availability()}
        else:
            raise ValueError("Profil inconnu")
        review.result = result
        _persist_findings(review, result.get("findings", []))
        review.status = SecurityReview.Status.COMPLETED
        review.completed_at = timezone.now()
        review.duration_seconds = round(time.monotonic()-start, 3)
        review.save(update_fields=["result", "status", "completed_at", "duration_seconds"])
        return {"status": review.status, "review_id": str(review.id)}
    except Exception as exc:
        review.status = SecurityReview.Status.FAILED
        review.error_message = str(exc)[:4000]
        review.completed_at = timezone.now()
        review.duration_seconds = round(time.monotonic()-start, 3)
        review.save(update_fields=["status", "error_message", "completed_at", "duration_seconds"])
        raise
