from django.db import models
from django.utils import timezone
from africanwatch.apps.organizations.models import Organization, Asset, User, TimeStampedModel


class SecurityReview(TimeStampedModel):
    class Profile(models.TextChoices):
        OWASP_WEB = "owasp_web", "OWASP Web 2025"
        OWASP_API = "owasp_api", "OWASP API 2023"
        DB_POSTURE = "db_posture", "Database Posture"
        DB_CODE_SURFACE = "db_code_surface", "SQL/DB Code Surface"
        LOCAL_CODE = "local_code", "Local SAST / SCA"
        LOCAL_CONTAINER = "local_container", "Local Container/Image Audit"
        LOCAL_SECRETS = "local_secrets", "Local Secrets Audit"
        LOCAL_CREDENTIAL = "local_credential", "Offline Credential Audit"
        ZAP_BASELINE_PLAN = "zap_baseline_plan", "OWASP ZAP Baseline Plan"
        HYDRA_READINESS = "hydra_readiness", "Remote Auth Test Readiness"
        SQLMAP_READINESS = "sqlmap_readiness", "Injection Test Readiness"
        TOOLCHAIN = "toolchain", "Toolchain Health"

    class Status(models.TextChoices):
        QUEUED = "queued", "En attente"
        RUNNING = "running", "En cours"
        COMPLETED = "completed", "Terminée"
        FAILED = "failed", "Échec"
        BLOCKED = "blocked", "Bloquée"

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="security_reviews")
    asset = models.ForeignKey(Asset, null=True, blank=True, on_delete=models.SET_NULL, related_name="security_reviews")
    requested_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    profile = models.CharField(max_length=40, choices=Profile.choices)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.QUEUED)
    authorization_reference = models.CharField(max_length=255, blank=True)
    input_ref = models.TextField(blank=True)
    tool = models.CharField(max_length=50, blank=True)
    result = models.JSONField(default=dict, blank=True)
    stdout = models.TextField(blank=True)
    stderr = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    findings_count = models.PositiveIntegerField(default=0)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.FloatField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["organization", "profile", "status"])]


class SecurityFinding(TimeStampedModel):
    class Severity(models.TextChoices):
        INFO = "info", "Information"
        LOW = "low", "Faible"
        MEDIUM = "medium", "Moyen"
        HIGH = "high", "Élevé"
        CRITICAL = "critical", "Critique"

    review = models.ForeignKey(SecurityReview, on_delete=models.CASCADE, related_name="findings")
    framework = models.CharField(max_length=40, blank=True)
    control_id = models.CharField(max_length=80, blank=True)
    severity = models.CharField(max_length=10, choices=Severity.choices, default=Severity.INFO)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    remediation = models.TextField(blank=True)
    confidence = models.FloatField(default=1.0)
    fingerprint = models.CharField(max_length=64)

    class Meta:
        ordering = ["-severity", "framework", "control_id", "title"]
        constraints = [models.UniqueConstraint(fields=["review", "fingerprint"], name="uniq_securityfinding_review_fp")]


class ToolDefinition(models.Model):
    slug = models.SlugField(max_length=80, unique=True)
    name = models.CharField(max_length=120)
    category = models.CharField(max_length=80)
    mode = models.CharField(max_length=30)
    description = models.TextField()
    executable = models.CharField(max_length=120, blank=True)
    safety_boundary = models.CharField(max_length=255)
    default_enabled = models.BooleanField(default=False)
    class Meta:
        ordering = ["category", "name"]
