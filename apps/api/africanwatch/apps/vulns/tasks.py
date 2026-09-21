"""AfricaWatch — Vulnerability Management Tasks"""
import logging
from celery import shared_task
from django.utils import timezone

logger = logging.getLogger("africanwatch.vulns")


@shared_task(bind=True, max_retries=2, queue="scans")
def scan_asset(self, asset_id: str, scan_type: str = "full", triggered_by: str | None = None):
    """Lance un scan de vulnérabilités sur un actif."""
    from africanwatch.apps.organizations.models import Asset
    from africanwatch.apps.vulns.models import Vulnerability, ScanJob
    try:
        asset = Asset.objects.get(id=asset_id)
        from africanwatch.apps.vulns.models import ScanJob
        job = ScanJob.objects.create(
            asset=asset, scan_type=scan_type,
            status=ScanJob.Status.RUNNING, started_at=timezone.now(),
            triggered_by_id=triggered_by if triggered_by else None,
        )
        findings = []
        if asset.asset_type in ["domain","url","application","ip"]:
            findings.extend(_run_nuclei(asset))
        if asset.asset_type in ["ip","ip_range"]:
            findings.extend(_run_nmap(asset))

        for f in findings:
            Vulnerability.objects.update_or_create(
                asset=asset, cve_id=f.get("cve_id",""), title=f["title"],
                defaults={
                    "severity": f["severity"], "description": f.get("description",""),
                    "affected_component": f.get("component",""),
                    "cvss_score": f.get("cvss_score"),
                    "scanner": f.get("scanner","nuclei"),
                    "raw_output": f, "references": f.get("references",[]),
                }
            )
        critical = sum(1 for f in findings if f["severity"]=="critical")
        high = sum(1 for f in findings if f["severity"]=="high")
        medium = sum(1 for f in findings if f["severity"]=="medium")
        low = sum(1 for f in findings if f["severity"] in ["low","info"])

        job.status = ScanJob.Status.COMPLETED
        job.completed_at = timezone.now()
        job.findings_count = len(findings)
        job.critical_count = critical
        job.high_count = high
        job.medium_count = medium
        job.low_count = low
        job.save()

        risk_score = min(100, critical*25 + high*10 + medium*3 + low)
        asset.risk_score = risk_score
        asset.last_scanned_at = timezone.now()
        asset.save(update_fields=["risk_score","last_scanned_at"])

        logger.info(f"Scan {asset.name}: {len(findings)} findings, risk={risk_score}")
        return {"asset": asset.name, "findings": len(findings), "risk_score": risk_score}

    except Exception as exc:
        from africanwatch.apps.vulns.models import ScanJob
        ScanJob.objects.filter(asset__id=asset_id, status="running").update(
            status="failed", error_message=str(exc)[:500], completed_at=timezone.now())
        logger.error(f"Scan error {asset_id}: {exc}")
        raise self.retry(exc=exc)


@shared_task(queue="scans")
def run_scheduled_scans():
    """Lance les scans planifiés sur tous les actifs actifs."""
    from africanwatch.apps.organizations.models import Asset
    from datetime import timedelta
    count = 0
    for asset in Asset.objects.filter(scan_enabled=True, is_active=True):
        if asset.last_scanned_at:
            if timezone.now() < asset.last_scanned_at + timedelta(hours=asset.scan_frequency_hours):
                continue
        scan_asset.delay(str(asset.id))
        count += 1
    logger.info(f"Scheduled scans: {count} assets")
    return {"scheduled": count}


def _run_nuclei(asset) -> list:
    import json
    import subprocess
    from django.conf import settings
    from africanwatch.security.outbound import validate_scan_target

    findings = []
    try:
        allow_private = bool(getattr(settings, "LAB_MODE", False))
        validate_scan_target(asset.value, allow_private=allow_private)
        cmd = [
            "nuclei", "-u", asset.value, "-jsonl", "-silent", "-rate-limit", "10",
            "-concurrency", "1", "-retries", "0", "-timeout", "5",
            "-severity", "info,low,medium", "-tags", "misconfig,exposure,ssl,tech",
            "-exclude-tags", "dos,fuzz,intrusive,bruteforce,exploit,rce,sqli,ssrf,lfi,rfi,xxe,deserialization",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False, shell=False)
        for line in result.stdout.splitlines()[:100]:
            try:
                f = json.loads(line)
                info = f.get("info", {})
                severity = str(info.get("severity", "info")).lower()
                if severity not in {"info", "low", "medium"}:
                    continue
                c = info.get("classification") or {}
                cve_list = c.get("cve-id", []) if isinstance(c, dict) else []
                findings.append({
                    "title": str(info.get("name", "Unknown"))[:500],
                    "severity": severity,
                    "description": str(info.get("description", ""))[:5000],
                    "cve_id": cve_list[0] if cve_list else "",
                    "cvss_score": c.get("cvss-score") if isinstance(c, dict) else None,
                    "scanner": "nuclei-safe",
                    "references": info.get("reference", []) if isinstance(info.get("reference", []), list) else [],
                    "tags": info.get("tags", []),
                })
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
    except FileNotFoundError:
        logger.warning("nuclei non installé — scan ignoré")
    except Exception as e:
        logger.error(f"Nuclei error: {e}")
    return findings


def _run_nmap(asset) -> list:
    import ipaddress
    import subprocess
    from django.conf import settings
    from africanwatch.security.outbound import validate_scan_target

    findings = []
    try:
        allow_private = bool(getattr(settings, "LAB_MODE", False))
        if asset.asset_type == "ip_range":
            network = ipaddress.ip_network(asset.value, strict=False)
            # Broad active ranges are intentionally LAB-only and bounded to /28 (14 usable addresses).
            if not allow_private or network.prefixlen < 28:
                logger.warning("ip_range refusé hors LAB ou au-delà de /28: %s", asset.value)
                return findings
        validate_scan_target(asset.value, allow_private=allow_private)
        cmd = [
            "nmap", "-sT", "-sV", "--version-light", "--open", "-T3", "--max-retries", "1",
            "--host-timeout", "60s", "--top-ports", "100", "-oX", "-", asset.value,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False, shell=False)
        output = result.stdout[:80_000]
        if "23/tcp" in output and "open" in output:
            findings.append({"title":"Telnet exposé","severity":"high","description":"Telnet non chiffré détecté","scanner":"nmap-safe"})
        if "21/tcp" in output and "open" in output:
            findings.append({"title":"FTP exposé","severity":"medium","description":"FTP transmet potentiellement les échanges en clair","scanner":"nmap-safe"})
        if "3389/tcp" in output and "open" in output:
            findings.append({"title":"RDP exposé","severity":"high","description":"RDP est accessible depuis la surface testée","scanner":"nmap-safe"})
        if "2375/tcp" in output and "open" in output:
            findings.append({"title":"Docker API exposée","severity":"high","description":"Le port HTTP du Docker daemon est accessible","scanner":"nmap-safe"})
    except FileNotFoundError:
        logger.warning("nmap non installé — scan ignoré")
    except Exception as e:
        logger.error(f"Nmap error: {e}")
    return findings
