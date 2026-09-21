"""Organizations Initial Migration"""
import uuid, django.contrib.auth.models, django.db.models.deletion
from django.db import migrations, models
class Migration(migrations.Migration):
    initial = True
    dependencies = [("auth","0012_alter_user_first_name_max_length")]
    operations = [
        migrations.CreateModel(name="Organization",fields=[
            ("id",models.UUIDField(default=uuid.uuid4,editable=False,primary_key=True)),("created_at",models.DateTimeField(auto_now_add=True,db_index=True)),("updated_at",models.DateTimeField(auto_now=True)),
            ("name",models.CharField(max_length=255)),("slug",models.SlugField(unique=True,max_length=100)),("org_type",models.CharField(max_length=20,default="private")),("country",models.CharField(max_length=3)),("country_name",models.CharField(max_length=100,blank=True)),
            ("tier",models.CharField(max_length=20,default="free")),("tlp_level",models.CharField(max_length=10,default="green")),("api_key",models.CharField(max_length=64,unique=True,blank=True)),("contact_email",models.EmailField()),("website",models.URLField(blank=True)),
            ("description",models.TextField(blank=True)),("logo",models.ImageField(upload_to="logos/",blank=True,null=True)),("is_active",models.BooleanField(default=True)),("is_verified",models.BooleanField(default=False)),("max_assets",models.IntegerField(default=100)),("max_users",models.IntegerField(default=5)),("max_api_calls_per_day",models.IntegerField(default=1000)),
        ],options={"ordering":["name"]}),
        migrations.CreateModel(name="User",fields=[
            ("id",models.UUIDField(default=uuid.uuid4,editable=False,primary_key=True)),("created_at",models.DateTimeField(auto_now_add=True,db_index=True)),("updated_at",models.DateTimeField(auto_now=True)),("password",models.CharField(max_length=128,verbose_name="password")),("is_superuser",models.BooleanField(default=False)),("last_login",models.DateTimeField(blank=True,null=True)),
            ("email",models.EmailField(unique=True)),("first_name",models.CharField(max_length=100)),("last_name",models.CharField(max_length=100)),
            ("organization",models.ForeignKey(null=True,blank=True,on_delete=django.db.models.deletion.SET_NULL,related_name="users",to="organizations.organization")),
            ("role",models.CharField(max_length=20,default="viewer")),("bio",models.TextField(blank=True)),("phone",models.CharField(max_length=20,blank=True)),("country",models.CharField(max_length=3,blank=True)),("timezone",models.CharField(max_length=50,default="UTC")),("language",models.CharField(max_length=5,default="fr")),
            ("is_active",models.BooleanField(default=True)),("is_staff",models.BooleanField(default=False)),("is_mfa_enabled",models.BooleanField(default=False)),("mfa_secret",models.CharField(max_length=32,blank=True)),("last_login_ip",models.GenericIPAddressField(null=True,blank=True)),("last_activity",models.DateTimeField(null=True,blank=True)),
            ("email_notifications",models.BooleanField(default=True)),("sms_notifications",models.BooleanField(default=False)),("notification_severity_threshold",models.CharField(max_length=10,default="high")),
            ("groups",models.ManyToManyField(blank=True,related_name="user_set",to="auth.group",verbose_name="groups")),("user_permissions",models.ManyToManyField(blank=True,related_name="user_set",to="auth.permission",verbose_name="user permissions")),
        ],options={"verbose_name":"Utilisateur"},managers=[("objects",django.contrib.auth.models.BaseUserManager())]),
        migrations.CreateModel(name="Asset",fields=[
            ("id",models.UUIDField(default=uuid.uuid4,editable=False,primary_key=True)),("created_at",models.DateTimeField(auto_now_add=True,db_index=True)),("updated_at",models.DateTimeField(auto_now=True)),
            ("organization",models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,related_name="assets",to="organizations.organization")),("name",models.CharField(max_length=255)),("asset_type",models.CharField(max_length=20)),("value",models.CharField(max_length=500)),
            ("criticality",models.CharField(max_length=10,default="medium")),("description",models.TextField(blank=True)),("tags",models.JSONField(default=list,blank=True)),("risk_score",models.FloatField(default=0.0)),("exposure_score",models.FloatField(default=0.0)),
            ("last_scanned_at",models.DateTimeField(null=True,blank=True)),("scan_enabled",models.BooleanField(default=True)),("scan_frequency_hours",models.IntegerField(default=24)),("ip_addresses",models.JSONField(default=list,blank=True)),("open_ports",models.JSONField(default=list,blank=True)),("technologies",models.JSONField(default=list,blank=True)),("geolocation",models.JSONField(null=True,blank=True)),("is_active",models.BooleanField(default=True)),
        ],options={"ordering":["-criticality","name"]}),
        migrations.AlterUniqueTogether(name="asset",unique_together={("organization","asset_type","value")}),
        migrations.CreateModel(name="AuditLog",fields=[
            ("id",models.BigAutoField(primary_key=True)),("timestamp",models.DateTimeField(db_index=True)),
            ("user",models.ForeignKey(null=True,blank=True,on_delete=django.db.models.deletion.SET_NULL,related_name="audit_logs",to="organizations.user")),("organization",models.ForeignKey(null=True,blank=True,on_delete=django.db.models.deletion.SET_NULL,related_name="audit_logs",to="organizations.organization")),
            ("action",models.CharField(max_length=50,db_index=True)),("resource_type",models.CharField(max_length=50,blank=True)),("resource_id",models.CharField(max_length=100,blank=True)),("ip_address",models.GenericIPAddressField(null=True,blank=True)),("user_agent",models.TextField(blank=True)),("details",models.JSONField(default=dict)),("success",models.BooleanField(default=True)),
        ],options={"ordering":["-timestamp"]}),
    ]
