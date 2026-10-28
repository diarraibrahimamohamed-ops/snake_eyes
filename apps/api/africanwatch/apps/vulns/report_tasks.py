"""Asynchronous, offline processing of imported scanner reports."""
import hashlib
import json
import logging

from celery import shared_task
from django.db import transaction
from django.utils import timezone

logger = logging.getLogger("africanwatch.vulns.reports")


def _asset_key(value):
    value = str(value or "").strip()
    if not value:
        return ""
    # No DNS lookups or URL fetches are performed during matching.
    return value.rstrip("/").lower()


def _finding_fingerprint(finding):
    stable = {
        key: finding.get(key)
        for key in ("scanner", "external_asset", "title", "cve_id", "affected_component", "evidence")
    }
    payload = json.dumps(stable, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _match_asset(organization, external_asset):
    from africanwatch.apps.organizations.models import Asset

    key = _asset_key(external_asset)
    if not key:
        return None
    # Exact, tenant-scoped matching only. Never create assets from untrusted reports.
    candidates = Asset.objects.filter(organization=organization, is_active=True).only(
        "id", "value", "asset_type", "ip_addresses"
    )
    for asset in candidates.iterator():
        if _asset_key(asset.value) == key:
            return asset
        ips = asset.ip_addresses if isinstance(asset.ip_addresses, list) else []
        if any(_asset_key(ip) == key for ip in ips):
            return asset
    return None


def _severity_counts(findings):
    counts = {key: 0 for key in ("info", "low", "medium", "high", "critical")}
    for item in findings:
        severity = item.get("severity", "info")
        counts[severity if severity in counts else "info"] += 1
    return counts


@shared_task(bind=True, max_retries=2, queue="scans")
def process_report_ingestion(self, report_id: str):
    """Parse a stored report offline and normalize evidence for one tenant."""
    from africanwatch.apps.organizations.models import AuditLog
    from africanwatch.apps.vulns.models import ReportFinding, ReportIngestion, Vulnerability

    try:
        report = ReportIngestion.objects.select_related("organization", "uploaded_by").get(id=report_id)
    except ReportIngestion.DoesNotExist:
        return {"status": "not_found", "report_id": str(report_id)}

    if report.status == ReportIngestion.Status.COMPLETED:
        return {"status": "already_completed", "report_id": str(report.id)}

    report.status = ReportIngestion.Status.PROCESSING
    report.started_at = timezone.now()
    report.error_message = ""
    report.save(update_fields=["status", "started_at", "error_message", "updated_at"])

    try:
        from africanwatch.apps.vulns.report_parsers import (
            MAX_REPORT_BYTES,
            ReportParseError,
            parse_report,
            sha256_bytes,
        )
        raw = report.report_file.read(MAX_REPORT_BYTES + 1)
        if not raw or len(raw) > MAX_REPORT_BYTES:
            raise ReportParseError("Fichier vide ou supérieur à la limite de 10 Mio.")
        digest = sha256_bytes(raw)
        if digest != report.sha256:
            raise ReportParseError("L'empreinte SHA-256 du fichier ne correspond plus à l'original.")
        findings = parse_report(report.source_type, raw)

        linked = 0
        unmatched = 0
        counts = _severity_counts(findings)
        with transaction.atomic():
            for item in findings:
                fingerprint = _finding_fingerprint(item)
                asset = _match_asset(report.organization, item.get("external_asset"))
                vulnerability = None
                if asset is not None:
                    # Link evidence to an existing vulnerability where possible. A report is
                    # not allowed to overwrite analyst-managed status/remediation fields.
                    lookup = {"asset": asset, "title": item["title"]}
                    if item.get("cve_id"):
                        lookup = {"asset": asset, "cve_id": item["cve_id"], "title": item["title"]}
                    vulnerability = Vulnerability.objects.filter(**lookup).first()
                    if vulnerability is None:
                        vulnerability = Vulnerability.objects.create(
                            asset=asset,
                            cve_id=item.get("cve_id", ""),
                            cvss_score=item.get("cvss_score"),
                            severity=item.get("severity", "info"),
                            title=item["title"][:500],
                            description=item.get("description", "")[:5000],
                            affected_component=item.get("affected_component", "")[:255],
                            scanner=item.get("scanner", "")[:50],
                            raw_output={"source": "external_report", "evidence": item.get("evidence", {})},
                            references=item.get("references", [])[:20],
                            tags=["imported-report"],
                        )
                    linked += 1
                else:
                    unmatched += 1

                ReportFinding.objects.get_or_create(
                    report=report,
                    fingerprint=fingerprint,
                    defaults={
                        "asset": asset,
                        "vulnerability": vulnerability,
                        "external_asset": item.get("external_asset", "")[:500],
                        "scanner": item.get("scanner", "")[:50],
                        "cve_id": item.get("cve_id", "")[:30],
                        "cvss_score": item.get("cvss_score"),
                        "severity": item.get("severity", "info"),
                        "title": item.get("title", "Finding")[:500],
                        "description": item.get("description", "")[:5000],
                        "affected_component": item.get("affected_component", "")[:255],
                        "remediation": item.get("remediation", "")[:5000],
                        "references": item.get("references", [])[:20],
                        "evidence": item.get("evidence", {}) if isinstance(item.get("evidence"), dict) else {},
                    },
                )

            report.status = ReportIngestion.Status.COMPLETED
            report.total_findings = len(findings)
            report.linked_findings = linked
            report.unmatched_findings = unmatched
            report.summary = {"by_severity": counts, "matching_policy": "exact_tenant_asset_match_only"}
            report.completed_at = timezone.now()
            report.save(update_fields=[
                "status", "total_findings", "linked_findings", "unmatched_findings",
                "summary", "completed_at", "updated_at",
            ])
            AuditLog.objects.create(
                user=report.uploaded_by,
                organization=report.organization,
                action="report_ingestion_completed",
                resource_type="report_ingestion",
                resource_id=str(report.id),
                details={
                    "source_type": report.source_type,
                    "sha256": report.sha256,
                    "total_findings": len(findings),
                    "linked_findings": linked,
                    "unmatched_findings": unmatched,
                },
                success=True,
            )
        return {"status": "completed", "report_id": str(report.id), "findings": len(findings),
                "linked": linked, "unmatched": unmatched}
    except Exception as exc:
        logger.exception("Report ingestion failed: %s", report.id)
        report.status = ReportIngestion.Status.FAILED
        # Parser errors are safe to show; unexpected exceptions may contain paths,
        # SQL fragments or infrastructure details and must stay in server logs.
        try:
            from africanwatch.apps.vulns.report_parsers import ReportParseError
            safe_message = str(exc)[:500] if isinstance(exc, ReportParseError) else (
                "Le traitement a échoué. Consultez les journaux techniques avec la référence du rapport."
            )
        except Exception:
            safe_message = "Le traitement a échoué. Consultez les journaux techniques avec la référence du rapport."
        report.error_message = safe_message
        report.completed_at = timezone.now()
        report.save(update_fields=["status", "error_message", "completed_at", "updated_at"])
        return {"status": "failed", "report_id": str(report.id), "error": report.error_message}
