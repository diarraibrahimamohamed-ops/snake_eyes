"""Authorized offensive-security assessment models."""
from django.db import models
from django.utils import timezone
from africanwatch.apps.organizations.models import Organization, Asset, User, TimeStampedModel


class Engagement(TimeStampedModel):
    class Status(models.TextChoices):
        DRAFT = "draft", "Brouillon"
        ACTIVE = "active", "Active"
        EXPIRED = "expired", "Expirée"
        CLOSED = "closed", "Clôturée"

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="security_engagements")
    name = models.CharField(max_length=255)
    authorization_reference = models.CharField(max_length=255)
    scope_hash = models.CharField(max_length=64, blank=True)
    starts_at = models.DateTimeField()
    ends_at = models.DateTimeField()
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.DRAFT)
    approved = models.BooleanField(default=False)
    approved_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="approved_engagements")
    approved_at = models.DateTimeField(null=True, blank=True)
    lab_mode = models.BooleanField(default=False)
    # Defensive/offensive-lab policy knobs. These are ceilings, not user inputs to scanners.
    max_targets = models.PositiveIntegerField(default=25)
    max_jobs_per_hour = models.PositiveIntegerField(default=20)
    max_concurrent_jobs = models.PositiveIntegerField(default=2)
    allowed_profiles = models.JSONField(default=list, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["organization", "status"])]

    @property
    def is_active_now(self):
        now = timezone.now()
        return self.status == self.Status.ACTIVE and self.approved and self.starts_at <= now <= self.ends_at


class EngagementTarget(TimeStampedModel):
    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE, related_name="targets")
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="engagement_targets")
    enabled = models.BooleanField(default=True)
    notes = models.TextField(blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["engagement", "asset"], name="uniq_engagement_asset")]


class AssessmentJob(TimeStampedModel):
    class Profile(models.TextChoices):
        DNS_RECON = "dns_recon", "Reconnaissance DNS"
        WEB_RECON = "web_recon", "Reconnaissance HTTP/TLS"
        PORT_RECON = "port_recon", "Découverte de services"
        COMBINED_RECON = "combined_recon", "Reconnaissance combinée"
        TLS_AUDIT = "tls_audit", "Audit TLS"
        DNS_POSTURE = "dns_posture", "Posture DNS"
        WEB_POSTURE = "web_posture", "Posture Web"
        EXPOSURE_AUDIT = "exposure_audit", "Audit d’exposition"
        ADVERSARY_RECON = "adversary_recon", "Reconnaissance orientée adversaire"
        EXPOSURE_CHAIN = "exposure_chain", "Chaîne d’exposition"
        NUCLEI_SAFE = "nuclei_safe", "Nuclei — contrôles non intrusifs"

    class Status(models.TextChoices):
        QUEUED = "queued", "En file"
        RUNNING = "running", "En cours"
        COMPLETED = "completed", "Terminée"
        FAILED = "failed", "Échec"
        BLOCKED = "blocked", "Bloquée"
        CANCELLED = "cancelled", "Annulée"

    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE, related_name="jobs")
    target = models.ForeignKey(EngagementTarget, on_delete=models.CASCADE, related_name="jobs")
    requested_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    profile = models.CharField(max_length=30, choices=Profile.choices)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.QUEUED)
    command_summary = models.CharField(max_length=500, blank=True)
    result = models.JSONField(default=dict, blank=True)
    stdout = models.TextField(blank=True)
    stderr = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    task_id = models.CharField(max_length=255, blank=True)
    scope_hash_at_launch = models.CharField(max_length=64, blank=True)
    execution_nonce = models.CharField(max_length=64, blank=True)
    result_sha256 = models.CharField(max_length=64, blank=True)
    duration_seconds = models.FloatField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["engagement", "status"])]


class AssessmentFinding(TimeStampedModel):
    class Severity(models.TextChoices):
        INFO = "info", "Information"
        LOW = "low", "Faible"
        MEDIUM = "medium", "Moyen"
        HIGH = "high", "Élevé"
        CRITICAL = "critical", "Critique"

    job = models.ForeignKey(AssessmentJob, on_delete=models.CASCADE, related_name="findings")
    fingerprint = models.CharField(max_length=64)
    severity = models.CharField(max_length=10, choices=Severity.choices, default=Severity.INFO)
    category = models.CharField(max_length=80)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    remediation = models.TextField(blank=True)
    confidence = models.FloatField(default=1.0)

    class Meta:
        ordering = ["-severity", "category", "title"]
        constraints = [models.UniqueConstraint(fields=["job", "fingerprint"], name="uniq_finding_job_fp")]
        indexes = [models.Index(fields=["job", "severity"])]


class AssessmentEvent(models.Model):
    id = models.BigAutoField(primary_key=True)
    job = models.ForeignKey(AssessmentJob, on_delete=models.CASCADE, related_name="events")
    event_type = models.CharField(max_length=50)
    payload = models.JSONField(default=dict, blank=True)
    previous_hash = models.CharField(max_length=64, blank=True)
    event_hash = models.CharField(max_length=64)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["id"]
        indexes = [models.Index(fields=["job", "timestamp"])]
