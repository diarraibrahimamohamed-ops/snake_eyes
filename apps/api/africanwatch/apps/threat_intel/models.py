"""AfricaWatch — Threat Intelligence Models"""
import uuid
from django.db import models
from django.utils import timezone
from africanwatch.apps.organizations.models import Organization, TimeStampedModel


class ThreatFeed(TimeStampedModel):
    class FeedType(models.TextChoices):
        MISP = "misp", "MISP"
        OTX = "otx", "AlienVault OTX"
        TAXII = "taxii", "TAXII 2.x"
        CSV = "csv", "CSV"
        JSON = "json", "JSON"
        PLAINTEXT = "plaintext", "Texte plain"
        CUSTOM_API = "custom_api", "API personnalisée"

    class Status(models.TextChoices):
        ACTIVE = "active", "Actif"
        ERROR = "error", "Erreur"
        DISABLED = "disabled", "Désactivé"
        PENDING = "pending", "En attente"

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    feed_type = models.CharField(max_length=20, choices=FeedType.choices)
    url = models.URLField()
    api_key = models.CharField(max_length=255, blank=True)
    api_key_header = models.CharField(max_length=100, default="X-API-Key")
    is_public = models.BooleanField(default=True)
    is_african_specific = models.BooleanField(default=False)
    fetch_frequency_hours = models.IntegerField(default=6)
    last_fetched_at = models.DateTimeField(null=True, blank=True)
    last_ioc_count = models.IntegerField(default=0)
    total_iocs_imported = models.IntegerField(default=0)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    last_error = models.TextField(blank=True)
    tlp_level = models.CharField(max_length=10, default="white")
    tags = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["name"]
        verbose_name = "Flux de renseignement"

    def __str__(self):
        return f"{self.name} ({self.feed_type})"


class IOC(TimeStampedModel):
    class IOCType(models.TextChoices):
        IP = "ip", "Adresse IP"
        IP_RANGE = "ip_range", "Plage IP"
        DOMAIN = "domain", "Domaine"
        URL = "url", "URL"
        MD5 = "md5", "Hash MD5"
        SHA1 = "sha1", "Hash SHA-1"
        SHA256 = "sha256", "Hash SHA-256"
        EMAIL = "email", "Email"
        FILE_PATH = "file_path", "Chemin fichier"
        REGISTRY_KEY = "registry_key", "Clé registre"
        ASN = "asn", "ASN"
        CVE = "cve", "CVE"
        BITCOIN_ADDRESS = "btc", "Bitcoin"
        YARA_RULE = "yara", "YARA"

    class Severity(models.TextChoices):
        INFO = "info", "Information"
        LOW = "low", "Faible"
        MEDIUM = "medium", "Moyen"
        HIGH = "high", "Élevé"
        CRITICAL = "critical", "Critique"

    class TLPLevel(models.TextChoices):
        WHITE = "white", "TLP:WHITE"
        GREEN = "green", "TLP:GREEN"
        AMBER = "amber", "TLP:AMBER"
        RED = "red", "TLP:RED"

    ioc_type = models.CharField(max_length=20, choices=IOCType.choices, db_index=True)
    value = models.CharField(max_length=2048, db_index=True)
    value_normalized = models.CharField(max_length=2048, db_index=True)
    severity = models.CharField(max_length=10, choices=Severity.choices, default=Severity.MEDIUM, db_index=True)
    confidence = models.IntegerField(default=50)
    tlp_level = models.CharField(max_length=10, choices=TLPLevel.choices, default=TLPLevel.GREEN)
    feed = models.ForeignKey(ThreatFeed, on_delete=models.SET_NULL, null=True, blank=True, related_name="iocs")
    source_organization = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True, related_name="submitted_iocs")
    source_reference = models.URLField(blank=True)
    reporter_name = models.CharField(max_length=255, blank=True)
    is_african_threat = models.BooleanField(default=False, db_index=True)
    african_countries_targeted = models.JSONField(default=list, blank=True)
    first_seen = models.DateTimeField(db_index=True)
    last_seen = models.DateTimeField(db_index=True)
    expiry_date = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True, db_index=True)
    description = models.TextField(blank=True)
    tags = models.JSONField(default=list, blank=True)
    malware_families = models.JSONField(default=list, blank=True)
    attack_patterns = models.JSONField(default=list, blank=True)
    country_code = models.CharField(max_length=3, blank=True, db_index=True)
    country_name = models.CharField(max_length=100, blank=True)
    asn = models.CharField(max_length=20, blank=True)
    asn_name = models.CharField(max_length=255, blank=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    mitre_tactics = models.JSONField(default=list, blank=True)
    mitre_techniques = models.JSONField(default=list, blank=True)
    hit_count = models.IntegerField(default=0)
    false_positive_count = models.IntegerField(default=0)
    raw_data = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "IOC"
        ordering = ["-last_seen", "-confidence"]
        unique_together = [["ioc_type", "value_normalized"]]
        indexes = [
            models.Index(fields=["ioc_type", "severity"]),
            models.Index(fields=["is_active", "is_african_threat"]),
            models.Index(fields=["country_code"]),
        ]

    def __str__(self):
        return f"[{self.ioc_type.upper()}] {self.value} ({self.severity})"

    def save(self, *args, **kwargs):
        self.value_normalized = self._normalize()
        super().save(*args, **kwargs)

    def _normalize(self):
        v = self.value.strip().lower()
        if self.ioc_type == self.IOCType.DOMAIN:
            return v.lstrip("www.")
        return v

    @property
    def is_expired(self):
        return bool(self.expiry_date and timezone.now() > self.expiry_date)


class ThreatActor(TimeStampedModel):
    class Motivation(models.TextChoices):
        FINANCIAL = "financial", "Financière"
        ESPIONAGE = "espionage", "Espionnage"
        HACKTIVISM = "hacktivism", "Hacktivisme"
        DISRUPTION = "disruption", "Disruption"
        TERRORISM = "terrorism", "Terrorisme"
        UNKNOWN = "unknown", "Inconnue"

    class Sophistication(models.TextChoices):
        MINIMAL = "minimal", "Minimale"
        INTERMEDIATE = "intermediate", "Intermédiaire"
        ADVANCED = "advanced", "Avancée"
        EXPERT = "expert", "Expert/APT"

    name = models.CharField(max_length=255, unique=True)
    aliases = models.JSONField(default=list, blank=True)
    description = models.TextField(blank=True)
    motivation = models.CharField(max_length=20, choices=Motivation.choices, default=Motivation.UNKNOWN)
    sophistication = models.CharField(max_length=20, choices=Sophistication.choices, default=Sophistication.INTERMEDIATE)
    country_of_origin = models.CharField(max_length=3, blank=True)
    targets_africa = models.BooleanField(default=False, db_index=True)
    target_countries = models.JSONField(default=list, blank=True)
    target_sectors = models.JSONField(default=list, blank=True)
    known_tools = models.JSONField(default=list, blank=True)
    known_techniques = models.JSONField(default=list, blank=True)
    first_seen = models.DateField(null=True, blank=True)
    last_activity = models.DateField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    references = models.JSONField(default=list, blank=True)
    iocs = models.ManyToManyField(IOC, blank=True, related_name="threat_actors")

    class Meta:
        ordering = ["-last_activity"]
        verbose_name = "Acteur de menace"

    def __str__(self):
        return self.name


class Campaign(TimeStampedModel):
    name = models.CharField(max_length=255)
    description = models.TextField()
    threat_actor = models.ForeignKey(ThreatActor, on_delete=models.SET_NULL, null=True, blank=True, related_name="campaigns")
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    is_ongoing = models.BooleanField(default=True)
    target_countries = models.JSONField(default=list, blank=True)
    target_sectors = models.JSONField(default=list, blank=True)
    iocs = models.ManyToManyField(IOC, blank=True, related_name="campaigns")
    mitre_tactics = models.JSONField(default=list, blank=True)
    mitre_techniques = models.JSONField(default=list, blank=True)
    severity = models.CharField(max_length=10, default="high")
    references = models.JSONField(default=list, blank=True)
    tlp_level = models.CharField(max_length=10, default="green")

    class Meta:
        ordering = ["-start_date"]
        verbose_name = "Campagne"

    def __str__(self):
        return self.name


class ThreatReport(TimeStampedModel):
    class ReportType(models.TextChoices):
        TECHNICAL = "technical", "Technique"
        STRATEGIC = "strategic", "Stratégique"
        TACTICAL = "tactical", "Tactique"
        COUNTRY = "country", "Rapport pays"
        SECTOR = "sector", "Rapport secteur"

    title = models.CharField(max_length=500)
    report_type = models.CharField(max_length=20, choices=ReportType.choices)
    summary = models.TextField()
    content = models.TextField()
    author = models.CharField(max_length=255, blank=True)
    organization = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True)
    published_at = models.DateTimeField(null=True, blank=True)
    is_public = models.BooleanField(default=False)
    tlp_level = models.CharField(max_length=10, default="green")
    campaigns = models.ManyToManyField(Campaign, blank=True)
    iocs = models.ManyToManyField(IOC, blank=True)
    tags = models.JSONField(default=list, blank=True)
    pdf_file = models.FileField(upload_to="reports/", blank=True, null=True)

    class Meta:
        ordering = ["-published_at"]
        verbose_name = "Rapport Threat Intel"

    def __str__(self):
        return self.title
