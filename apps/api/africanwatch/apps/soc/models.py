"""AfricaWatch — SOC Models"""
import uuid
from django.db import models
from africanwatch.apps.organizations.models import Organization, TimeStampedModel, User


class DetectionRule(TimeStampedModel):
    class RuleType(models.TextChoices):
        SIGMA = "sigma", "Sigma"
        YARA = "yara", "YARA"
        CUSTOM = "custom", "Custom"
    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        DISABLED = "disabled", "Désactivée"
        TESTING = "testing", "En test"
    name = models.CharField(max_length=255)
    rule_type = models.CharField(max_length=20, choices=RuleType.choices)
    description = models.TextField(blank=True)
    content = models.TextField()
    severity = models.CharField(max_length=10, default="medium")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)
    mitre_tactics = models.JSONField(default=list, blank=True)
    mitre_techniques = models.JSONField(default=list, blank=True)
    tags = models.JSONField(default=list, blank=True)
    false_positive_rate = models.FloatField(default=0.0)
    hit_count = models.IntegerField(default=0)
    author = models.CharField(max_length=255, blank=True)
    references = models.JSONField(default=list, blank=True)
    is_african_specific = models.BooleanField(default=False)
    class Meta:
        ordering = ["-severity","name"]
        verbose_name = "Règle de détection"
    def __str__(self): return f"[{self.rule_type}] {self.name}"


class Alert(TimeStampedModel):
    class Severity(models.TextChoices):
        LOW = "low", "Faible"; MEDIUM = "medium", "Moyen"
        HIGH = "high", "Élevé"; CRITICAL = "critical", "Critique"
    class Status(models.TextChoices):
        NEW = "new", "Nouvelle"; ACKNOWLEDGED = "acknowledged", "Acquittée"
        INVESTIGATING = "investigating", "En investigation"
        ESCALATED = "escalated", "Escaladée"
        FALSE_POSITIVE = "false_positive", "Faux positif"
        RESOLVED = "resolved", "Résolue"
    class Source(models.TextChoices):
        WAZUH = "wazuh", "Wazuh"; SURICATA = "suricata", "Suricata"
        ZEEK = "zeek", "Zeek"; CUSTOM_RULE = "custom_rule", "Règle custom"
        THREAT_INTEL = "threat_intel", "Threat Intelligence"
        OSINT = "osint", "OSINT"; MANUAL = "manual", "Manuel"

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="alerts")
    rule = models.ForeignKey(DetectionRule, on_delete=models.SET_NULL, null=True, blank=True, related_name="alerts")
    title = models.CharField(max_length=500)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=Severity.choices, db_index=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.NEW, db_index=True)
    source = models.CharField(max_length=20, choices=Source.choices)
    raw_log = models.JSONField(default=dict)
    enriched_data = models.JSONField(default=dict)
    src_ip = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    dst_ip = models.GenericIPAddressField(null=True, blank=True)
    src_port = models.IntegerField(null=True, blank=True)
    dst_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=20, blank=True)
    hostname = models.CharField(max_length=255, blank=True)
    related_iocs = models.ManyToManyField("threat_intel.IOC", blank=True, related_name="alerts")
    mitre_tactics = models.JSONField(default=list, blank=True)
    mitre_techniques = models.JSONField(default=list, blank=True)
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_alerts")
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    acknowledged_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="acknowledged_alerts")
    resolved_at = models.DateTimeField(null=True, blank=True)
    tags = models.JSONField(default=list, blank=True)
    notes = models.TextField(blank=True)
    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Alerte"
        indexes = [models.Index(fields=["organization","status","severity"], name="alert_org_status_sev")]
    def __str__(self): return f"[{self.severity.upper()}] {self.title}"


class Incident(TimeStampedModel):
    class Severity(models.TextChoices):
        LOW = "low","Faible"; MEDIUM = "medium","Moyen"
        HIGH = "high","Élevé"; CRITICAL = "critical","Critique"
    class Status(models.TextChoices):
        OPEN = "open","Ouvert"; INVESTIGATING = "investigating","En investigation"
        CONTAINED = "contained","Contenu"; ERADICATED = "eradicated","Éradiqué"
        RECOVERED = "recovered","Récupéré"; CLOSED = "closed","Fermé"
        FALSE_POSITIVE = "false_positive","Faux positif"
    class IncidentType(models.TextChoices):
        MALWARE = "malware","Malware"; RANSOMWARE = "ransomware","Ransomware"
        PHISHING = "phishing","Phishing"; INTRUSION = "intrusion","Intrusion"
        DDOS = "ddos","DDoS"; DATA_BREACH = "data_breach","Fuite de données"
        INSIDER = "insider_threat","Menace interne"
        SUPPLY_CHAIN = "supply_chain","Supply Chain"
        UNKNOWN = "unknown","Inconnu"

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="incidents")
    title = models.CharField(max_length=500)
    description = models.TextField()
    incident_type = models.CharField(max_length=30, choices=IncidentType.choices, default=IncidentType.UNKNOWN)
    severity = models.CharField(max_length=10, choices=Severity.choices, db_index=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN, db_index=True)
    alerts = models.ManyToManyField(Alert, blank=True, related_name="incidents")
    related_iocs = models.ManyToManyField("threat_intel.IOC", blank=True)
    affected_assets = models.ManyToManyField("organizations.Asset", blank=True)
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_incidents")
    responders = models.ManyToManyField(User, blank=True, related_name="incident_responses")
    detected_at = models.DateTimeField()
    contained_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    mitre_tactics = models.JSONField(default=list, blank=True)
    mitre_techniques = models.JSONField(default=list, blank=True)
    systems_affected = models.IntegerField(default=0)
    data_compromised = models.BooleanField(default=False)
    financial_impact_usd = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    executive_summary = models.TextField(blank=True)
    root_cause = models.TextField(blank=True)
    lessons_learned = models.TextField(blank=True)
    remediation_steps = models.JSONField(default=list, blank=True)
    tags = models.JSONField(default=list, blank=True)
    is_public = models.BooleanField(default=False)
    tlp_level = models.CharField(max_length=10, default="amber")
    class Meta:
        ordering = ["-detected_at"]
        verbose_name = "Incident"
    def __str__(self): return f"[{self.severity.upper()}] {self.title}"
    @property
    def duration_hours(self):
        if self.resolved_at and self.detected_at:
            return (self.resolved_at - self.detected_at).total_seconds() / 3600
        return None


class IncidentTimeline(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name="timeline")
    timestamp = models.DateTimeField(db_index=True)
    author = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=255)
    details = models.TextField(blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    is_automated = models.BooleanField(default=False)
    class Meta:
        ordering = ["timestamp"]
    def __str__(self): return f"{self.incident.title} — {self.action}"
