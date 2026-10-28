"""AfricaWatch — Vulnerability Management Models"""
import uuid
from django.db import models
from africanwatch.apps.organizations.models import TimeStampedModel, Asset, User

class Vulnerability(TimeStampedModel):
    class Severity(models.TextChoices):
        INFO="info","Info"; LOW="low","Faible"; MEDIUM="medium","Moyen"
        HIGH="high","Élevé"; CRITICAL="critical","Critique"
    class Status(models.TextChoices):
        OPEN="open","Ouvert"; IN_PROGRESS="in_progress","En cours"
        REMEDIATED="remediated","Corrigé"; ACCEPTED="accepted","Accepté"
        FALSE_POSITIVE="false_positive","Faux positif"

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="vulnerabilities")
    cve_id = models.CharField(max_length=30, blank=True, db_index=True)
    cvss_score = models.FloatField(null=True, blank=True)
    severity = models.CharField(max_length=10, choices=Severity.choices, db_index=True)
    title = models.CharField(max_length=500)
    description = models.TextField()
    affected_component = models.CharField(max_length=255, blank=True)
    affected_version = models.CharField(max_length=100, blank=True)
    fixed_version = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN, db_index=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    remediated_at = models.DateTimeField(null=True, blank=True)
    remediation_notes = models.TextField(blank=True)
    scanner = models.CharField(max_length=50, blank=True)
    raw_output = models.JSONField(default=dict, blank=True)
    references = models.JSONField(default=list, blank=True)
    is_exploitable = models.BooleanField(default=False)
    exploit_available = models.BooleanField(default=False)
    tags = models.JSONField(default=list, blank=True)
    class Meta:
        ordering = ["-cvss_score","-severity"]
        verbose_name = "Vulnérabilité"
        indexes = [models.Index(fields=["asset","status"],name="vuln_asset_status")]
    def __str__(self): return f"{self.cve_id or self.title} [{self.severity}]"

class ScanJob(TimeStampedModel):
    class Status(models.TextChoices):
        PENDING="pending","En attente"; RUNNING="running","En cours"
        COMPLETED="completed","Terminé"; FAILED="failed","Échoué"
    class ScanType(models.TextChoices):
        NETWORK="network","Réseau"; WEB="web","Application Web"; FULL="full","Complet"

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="scan_jobs")
    scan_type = models.CharField(max_length=20, choices=ScanType.choices, default=ScanType.FULL)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    findings_count = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    error_message = models.TextField(blank=True)
    triggered_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    class Meta:
        ordering = ["-created_at"]
    def __str__(self): return f"Scan {self.scan_type} — {self.asset.name} [{self.status}]"


def report_upload_path(instance, filename):
    """Store report evidence by tenant and report UUID, never by user-supplied path."""
    from pathlib import PurePath
    suffix = PurePath(filename or "").suffix.lower()
    if suffix not in {".xml", ".json", ".jsonl", ".ndjson", ".csv", ".nessus"}:
        suffix = ".bin"
    return f"reports/{instance.organization_id}/{instance.id}/source{suffix}"


class ReportIngestion(TimeStampedModel):
    """External scanner report imported for defensive, offline processing."""

    class SourceType(models.TextChoices):
        NMAP_XML = "nmap_xml", "Nmap XML"
        NUCLEI_JSON = "nuclei_json", "Nuclei JSON"
        NUCLEI_JSONL = "nuclei_jsonl", "Nuclei JSONL"
        NESSUS_XML = "nessus_xml", "Nessus XML"
        SHODAN_JSON = "shodan_json", "Shodan JSON"
        SHODAN_CSV = "shodan_csv", "Shodan CSV"

    class Status(models.TextChoices):
        PENDING = "pending", "En attente"
        PROCESSING = "processing", "Traitement"
        COMPLETED = "completed", "Terminé"
        FAILED = "failed", "Échec"

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="report_ingestions"
    )
    uploaded_by = models.ForeignKey(
        "organizations.User", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="uploaded_security_reports",
    )
    source_type = models.CharField(max_length=20, choices=SourceType.choices)
    report_file = models.FileField(upload_to=report_upload_path, max_length=500)
    original_filename = models.CharField(max_length=255)
    sha256 = models.CharField(max_length=64)
    size_bytes = models.PositiveBigIntegerField()
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING, db_index=True)
    total_findings = models.PositiveIntegerField(default=0)
    linked_findings = models.PositiveIntegerField(default=0)
    unmatched_findings = models.PositiveIntegerField(default=0)
    summary = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(fields=["organization", "sha256"], name="uniq_report_org_sha256"),
        ]
        indexes = [
            models.Index(fields=["organization", "status"], name="report_org_status"),
        ]

    def __str__(self):
        return f"{self.original_filename} [{self.status}]"


class ReportFinding(TimeStampedModel):
    """Normalized evidence extracted from an uploaded report; asset linkage is optional."""

    report = models.ForeignKey(ReportIngestion, on_delete=models.CASCADE, related_name="findings")
    asset = models.ForeignKey(
        Asset, on_delete=models.SET_NULL, null=True, blank=True, related_name="imported_report_findings"
    )
    vulnerability = models.ForeignKey(
        Vulnerability, on_delete=models.SET_NULL, null=True, blank=True, related_name="imported_evidence"
    )
    fingerprint = models.CharField(max_length=64)
    external_asset = models.CharField(max_length=500, blank=True)
    scanner = models.CharField(max_length=50, blank=True)
    cve_id = models.CharField(max_length=30, blank=True, db_index=True)
    cvss_score = models.FloatField(null=True, blank=True)
    severity = models.CharField(max_length=10, choices=Vulnerability.Severity.choices, default="info", db_index=True)
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    affected_component = models.CharField(max_length=255, blank=True)
    remediation = models.TextField(blank=True)
    references = models.JSONField(default=list, blank=True)
    evidence = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-severity", "title"]
        constraints = [
            models.UniqueConstraint(fields=["report", "fingerprint"], name="uniq_report_finding_fp"),
        ]
        indexes = [
            models.Index(fields=["report", "severity"], name="report_finding_severity"),
            models.Index(fields=["asset", "severity"], name="report_asset_severity"),
        ]

    def __str__(self):
        return f"{self.title} [{self.severity}]"
