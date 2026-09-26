from django.db import models
from django.utils import timezone
from africanwatch.apps.organizations.models import Organization, User, Asset, TimeStampedModel

class CollectionTarget(TimeStampedModel):
    class Kind(models.TextChoices):
        DOMAIN = "domain", "Domaine"
        IP = "ip", "Adresse IP"
        URL = "url", "URL"
        EMAIL_DOMAIN = "email_domain", "Domaine email"
        ORGANIZATION = "organization", "Organisation"
        USERNAME_PUBLIC = "username_public", "Identifiant public"
        EMAIL = "email", "Adresse email publique"
        PHONE_PUBLIC = "phone_public", "Téléphone institutionnel public"
        SOCIAL_PUBLIC = "social_public", "Profil social public"
        ONION = "onion", "Service Onion"
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="collection_targets")
    asset = models.ForeignKey(Asset, null=True, blank=True, on_delete=models.SET_NULL, related_name="collection_targets")
    kind = models.CharField(max_length=30, choices=Kind.choices)
    value = models.CharField(max_length=500)
    label = models.CharField(max_length=255, blank=True)
    purpose = models.CharField(max_length=120, default="defensive_intelligence")
    authorization_reference = models.CharField(max_length=255)
    allowed = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    tags = models.JSONField(default=list, blank=True)
    class Meta:
        ordering = ["kind", "value"]
        constraints = [models.UniqueConstraint(fields=["organization", "kind", "value"], name="uniq_collection_target_org_kind_value")]

class CollectionSource(TimeStampedModel):
    class Kind(models.TextChoices):
        NEWS = "news", "Actualités"
        RSS = "rss", "RSS"
        WEB = "web", "Web public"
        SOCIAL_PUBLIC = "social_public", "Réseau social public"
        CERT = "cert", "CERT/Advisory"
        CT = "ct", "Certificate Transparency"
        RDAP = "rdap", "RDAP"
        ONION = "onion", "Source Onion"
        PUBLIC_API = "public_api", "API publique"
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="collection_sources")
    name = models.CharField(max_length=180)
    kind = models.CharField(max_length=30, choices=Kind.choices)
    url = models.CharField(max_length=2000)
    reliability = models.FloatField(default=0.5)
    languages = models.JSONField(default=list, blank=True)
    countries = models.JSONField(default=list, blank=True)
    allow_tor = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    notes = models.TextField(blank=True)
    class Meta:
        ordering = ["name"]
        constraints = [models.UniqueConstraint(fields=["organization", "url"], name="uniq_collection_source_org_url")]

class CollectionRun(TimeStampedModel):
    class Status(models.TextChoices):
        QUEUED = "queued", "En attente"
        RUNNING = "running", "En cours"
        COMPLETED = "completed", "Terminée"
        FAILED = "failed", "Échec"
        BLOCKED = "blocked", "Bloquée"
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="collection_runs")
    target = models.ForeignKey(CollectionTarget, on_delete=models.CASCADE, related_name="runs")
    requested_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    sources = models.ManyToManyField(CollectionSource, blank=True, related_name="runs")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.QUEUED)
    mode = models.CharField(max_length=30, default="passive")
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    result_summary = models.JSONField(default=dict, blank=True)
    evidence_root_hash = models.CharField(max_length=64, blank=True)
    error_message = models.TextField(blank=True)

class IntelligenceObservation(TimeStampedModel):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="intelligence_observations")
    run = models.ForeignKey(CollectionRun, null=True, blank=True, on_delete=models.SET_NULL, related_name="observations")
    source = models.ForeignKey(CollectionSource, null=True, blank=True, on_delete=models.SET_NULL, related_name="observations")
    source_label = models.CharField(max_length=255, blank=True)
    source_url = models.URLField(blank=True)
    title = models.CharField(max_length=500, blank=True)
    content = models.TextField()
    language = models.CharField(max_length=12, blank=True)
    published_at = models.DateTimeField(null=True, blank=True)
    retrieved_at = models.DateTimeField(default=timezone.now)
    content_sha256 = models.CharField(max_length=64, db_index=True)
    evidence_grade = models.CharField(max_length=2, default="C")
    source_reliability = models.FloatField(default=0.5)
    confidence = models.FloatField(default=0.5)
    relevance = models.FloatField(default=0.0)
    actionability_score = models.FloatField(default=0.0)
    classification = models.JSONField(default=dict, blank=True)
    entities = models.JSONField(default=dict, blank=True)
    iocs = models.JSONField(default=list, blank=True)
    provenance = models.JSONField(default=dict, blank=True)
    tlp = models.CharField(max_length=10, default="green")
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    corroboration_count = models.PositiveIntegerField(default=0)
    is_verified = models.BooleanField(default=False)
    class Meta:
        ordering = ["-retrieved_at"]
        constraints = [models.UniqueConstraint(fields=["organization", "content_sha256", "source_url"], name="uniq_intel_observation_content_source")]

class IntelligenceRelation(TimeStampedModel):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="intelligence_relations")
    left = models.ForeignKey(IntelligenceObservation, on_delete=models.CASCADE, related_name="relations_left")
    right = models.ForeignKey(IntelligenceObservation, on_delete=models.CASCADE, related_name="relations_right")
    relation_type = models.CharField(max_length=60)
    weight = models.FloatField(default=0.5)
    evidence = models.JSONField(default=dict, blank=True)

class ThreatForecast(TimeStampedModel):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="threat_forecasts")
    horizon_hours = models.PositiveIntegerField(default=168)
    generated_at = models.DateTimeField(default=timezone.now)
    signal_type = models.CharField(max_length=80)
    level = models.CharField(max_length=20)
    score = models.FloatField(default=0.0)
    confidence = models.FloatField(default=0.0)
    basis = models.JSONField(default=dict, blank=True)
    statement = models.TextField()
    model = models.CharField(max_length=80, default="deterministic-threat-trend-v1")
