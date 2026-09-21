"""AfricaWatch — Organizations Models"""
import uuid, secrets
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone

class TimeStampedModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta: abstract = True

class Organization(TimeStampedModel):
    class OrgType(models.TextChoices):
        GOVERNMENT="government","Gouvernement"; CERT="cert","CERT/CSIRT"
        BANK="bank","Banque"; TELECOM="telecom","Télécom"
        NGO="ngo","ONG"; UNIVERSITY="university","Université"; PRIVATE="private","Entreprise"
    class Tier(models.TextChoices):
        FREE="free","Gratuit"; PRO="pro","Pro"; ENTERPRISE="enterprise","Enterprise"
    class TLPLevel(models.TextChoices):
        WHITE="white","TLP:WHITE"; GREEN="green","TLP:GREEN"; AMBER="amber","TLP:AMBER"; RED="red","TLP:RED"

    name = models.CharField(max_length=255)
    slug = models.SlugField(unique=True, max_length=100)
    org_type = models.CharField(max_length=20, choices=OrgType.choices, default=OrgType.PRIVATE)
    country = models.CharField(max_length=3)
    country_name = models.CharField(max_length=100, blank=True)
    tier = models.CharField(max_length=20, choices=Tier.choices, default=Tier.FREE)
    tlp_level = models.CharField(max_length=10, choices=TLPLevel.choices, default=TLPLevel.GREEN)
    api_key = models.CharField(max_length=64, unique=True, blank=True)
    contact_email = models.EmailField()
    website = models.URLField(blank=True)
    description = models.TextField(blank=True)
    logo = models.ImageField(upload_to="logos/", blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    max_assets = models.IntegerField(default=100)
    max_users = models.IntegerField(default=5)
    max_api_calls_per_day = models.IntegerField(default=1000)
    class Meta: ordering=["name"]; verbose_name="Organisation"
    def __str__(self): return f"{self.name} ({self.country})"
    def save(self, *args, **kwargs):
        if not self.api_key: self.api_key = secrets.token_hex(32)
        super().save(*args, **kwargs)

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email: raise ValueError("Email requis")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff",True)
        extra_fields.setdefault("is_superuser",True)
        extra_fields.setdefault("role","super_admin")
        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin, TimeStampedModel):
    class Role(models.TextChoices):
        SUPER_ADMIN="super_admin","Super Admin"; ORG_ADMIN="org_admin","Admin Org"
        ANALYST="analyst","Analyste SOC"; THREAT_HUNTER="threat_hunter","Threat Hunter"
        VIEWER="viewer","Lecteur"
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    organization = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True, related_name="users")
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.VIEWER)
    avatar = models.ImageField(upload_to="avatars/", blank=True, null=True)
    bio = models.TextField(blank=True)
    phone = models.CharField(max_length=20, blank=True)
    country = models.CharField(max_length=3, blank=True)
    timezone = models.CharField(max_length=50, default="UTC")
    language = models.CharField(max_length=5, default="fr")
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_mfa_enabled = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=32, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    last_activity = models.DateTimeField(null=True, blank=True)
    email_notifications = models.BooleanField(default=True)
    sms_notifications = models.BooleanField(default=False)
    notification_severity_threshold = models.CharField(max_length=10,
        choices=[("low","Low"),("medium","Medium"),("high","High"),("critical","Critical")], default="high")
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name","last_name"]
    objects = UserManager()
    class Meta: verbose_name="Utilisateur"
    def __str__(self): return f"{self.get_full_name()} <{self.email}>"
    def get_full_name(self): return f"{self.first_name} {self.last_name}".strip()

class Asset(TimeStampedModel):
    class AssetType(models.TextChoices):
        DOMAIN="domain","Domaine"; IP="ip","Adresse IP"; IP_RANGE="ip_range","Plage IP"
        URL="url","URL"; APPLICATION="application","Application web"
        ASN="asn","ASN"; EMAIL_DOMAIN="email_domain","Domaine email"
    class Criticality(models.TextChoices):
        LOW="low","Faible"; MEDIUM="medium","Moyen"; HIGH="high","Élevé"; CRITICAL="critical","Critique"
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="assets")
    name = models.CharField(max_length=255)
    asset_type = models.CharField(max_length=20, choices=AssetType.choices)
    value = models.CharField(max_length=500)
    criticality = models.CharField(max_length=10, choices=Criticality.choices, default=Criticality.MEDIUM)
    description = models.TextField(blank=True)
    tags = models.JSONField(default=list, blank=True)
    risk_score = models.FloatField(default=0.0)
    exposure_score = models.FloatField(default=0.0)
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    scan_enabled = models.BooleanField(default=True)
    scan_frequency_hours = models.IntegerField(default=24)
    ip_addresses = models.JSONField(default=list, blank=True)
    open_ports = models.JSONField(default=list, blank=True)
    technologies = models.JSONField(default=list, blank=True)
    geolocation = models.JSONField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    class Meta: ordering=["-criticality","name"]; verbose_name="Actif"; unique_together=[["organization","asset_type","value"]]
    def __str__(self): return f"{self.name} ({self.value})"

class AuditLog(models.Model):
    class Action(models.TextChoices):
        LOGIN="login","Connexion"; LOGOUT="logout","Déconnexion"
        LOGIN_FAILED="login_failed","Échec connexion"; IOC_CREATED="ioc_created","IOC créé"
        INCIDENT_CREATED="incident_created","Incident créé"; SCAN_LAUNCHED="scan_launched","Scan lancé"
        API_CALL="api_call","Appel API"; USER_CREATED="user_created","Utilisateur créé"
        SETTINGS_CHANGED="settings_changed","Paramètres modifiés"
    id = models.BigAutoField(primary_key=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="audit_logs")
    organization = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True, related_name="audit_logs")
    action = models.CharField(max_length=50, db_index=True)
    resource_type = models.CharField(max_length=50, blank=True)
    resource_id = models.CharField(max_length=100, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    details = models.JSONField(default=dict)
    success = models.BooleanField(default=True)
    class Meta: ordering=["-timestamp"]; verbose_name="Log d'audit"
    def __str__(self): return f"{self.action} — {self.user} @ {self.timestamp}"
