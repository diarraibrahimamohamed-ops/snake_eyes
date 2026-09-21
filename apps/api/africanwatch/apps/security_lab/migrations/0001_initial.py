from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    initial = True
    dependencies = [("organizations", "0001_initial")]
    operations = [
        migrations.CreateModel(
            name="SecurityReview",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("profile", models.CharField(choices=[
                    ("owasp_web", "OWASP Web 2025"), ("owasp_api", "OWASP API 2023"),
                    ("db_posture", "Database Posture"), ("db_code_surface", "SQL/DB Code Surface"),
                    ("local_code", "Local SAST / SCA"), ("local_container", "Local Container/Image Audit"),
                    ("local_secrets", "Local Secrets Audit"), ("local_credential", "Offline Credential Audit"),
                    ("zap_baseline_plan", "OWASP ZAP Baseline Plan"), ("hydra_readiness", "Remote Auth Test Readiness"),
                    ("sqlmap_readiness", "Injection Test Readiness"), ("toolchain", "Toolchain Health")], max_length=40)),
                ("status", models.CharField(choices=[("queued", "En attente"), ("running", "En cours"), ("completed", "Terminée"), ("failed", "Échec"), ("blocked", "Bloquée")], default="queued", max_length=20)),
                ("authorization_reference", models.CharField(blank=True, max_length=255)),
                ("input_ref", models.TextField(blank=True)),
                ("tool", models.CharField(blank=True, max_length=50)),
                ("result", models.JSONField(blank=True, default=dict)),
                ("stdout", models.TextField(blank=True)), ("stderr", models.TextField(blank=True)),
                ("error_message", models.TextField(blank=True)), ("findings_count", models.PositiveIntegerField(default=0)),
                ("started_at", models.DateTimeField(blank=True, null=True)), ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("duration_seconds", models.FloatField(blank=True, null=True)),
                ("asset", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="security_reviews", to="organizations.asset")),
                ("organization", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="security_reviews", to="organizations.organization")),
                ("requested_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to="organizations.user")),
            ],
            options={"ordering": ["-created_at"], "indexes": [models.Index(fields=["organization", "profile", "status"], name="security_la_organiz_77bb1b_idx")]},
        ),
        migrations.CreateModel(
            name="SecurityFinding",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)), ("updated_at", models.DateTimeField(auto_now=True)),
                ("framework", models.CharField(blank=True, max_length=40)), ("control_id", models.CharField(blank=True, max_length=80)),
                ("severity", models.CharField(choices=[("info", "Information"), ("low", "Faible"), ("medium", "Moyen"), ("high", "Élevé"), ("critical", "Critique")], default="info", max_length=10)),
                ("title", models.CharField(max_length=255)), ("description", models.TextField(blank=True)),
                ("evidence", models.JSONField(blank=True, default=dict)), ("remediation", models.TextField(blank=True)),
                ("confidence", models.FloatField(default=1.0)), ("fingerprint", models.CharField(max_length=64)),
                ("review", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="findings", to="security_lab.securityreview")),
            ],
            options={"ordering": ["-severity", "framework", "control_id", "title"]},
        ),
        migrations.AddConstraint(model_name="securityfinding", constraint=models.UniqueConstraint(fields=("review", "fingerprint"), name="uniq_securityfinding_review_fp")),
        migrations.CreateModel(
            name="ToolDefinition",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("slug", models.SlugField(max_length=80, unique=True)), ("name", models.CharField(max_length=120)),
                ("category", models.CharField(max_length=80)), ("mode", models.CharField(max_length=30)),
                ("description", models.TextField()), ("executable", models.CharField(blank=True, max_length=120)),
                ("safety_boundary", models.CharField(max_length=255)), ("default_enabled", models.BooleanField(default=False)),
            ], options={"ordering": ["category", "name"]},
        ),
    ]
