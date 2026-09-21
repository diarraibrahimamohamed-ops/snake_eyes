# Generated manually for AfricaWatch Offensive Security Lab.
import uuid
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True
    dependencies = [
        ("organizations", "0001_initial"),
    ]
    operations = [
        migrations.CreateModel(
            name="Engagement",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("name", models.CharField(max_length=255)),
                ("authorization_reference", models.CharField(max_length=255)),
                ("scope_hash", models.CharField(blank=True, max_length=64)),
                ("starts_at", models.DateTimeField()),
                ("ends_at", models.DateTimeField()),
                ("status", models.CharField(choices=[("draft", "Brouillon"), ("active", "Active"), ("expired", "Expirée"), ("closed", "Clôturée")], default="draft", max_length=20)),
                ("approved", models.BooleanField(default=False)),
                ("approved_at", models.DateTimeField(blank=True, null=True)),
                ("lab_mode", models.BooleanField(default=False)),
                ("notes", models.TextField(blank=True)),
                ("approved_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="approved_engagements", to="organizations.user")),
                ("organization", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="security_engagements", to="organizations.organization")),
            ],
            options={"ordering": ["-created_at"], "indexes": [models.Index(fields=["organization", "status"], name="offlab_eng_org_status")]},
        ),
        migrations.CreateModel(
            name="EngagementTarget",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("enabled", models.BooleanField(default=True)),
                ("notes", models.TextField(blank=True)),
                ("asset", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="engagement_targets", to="organizations.asset")),
                ("engagement", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="targets", to="offensive_lab.engagement")),
            ],
        ),
        migrations.AddConstraint(
            model_name="engagementtarget",
            constraint=models.UniqueConstraint(fields=("engagement", "asset"), name="uniq_engagement_asset"),
        ),
        migrations.CreateModel(
            name="AssessmentJob",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("profile", models.CharField(choices=[("dns_recon", "Reconnaissance DNS"), ("web_recon", "Reconnaissance HTTP/TLS"), ("port_recon", "Découverte de services"), ("combined_recon", "Reconnaissance combinée")], max_length=30)),
                ("status", models.CharField(choices=[("queued", "En file"), ("running", "En cours"), ("completed", "Terminée"), ("failed", "Échec"), ("blocked", "Bloquée")], default="queued", max_length=20)),
                ("command_summary", models.CharField(blank=True, max_length=500)),
                ("result", models.JSONField(default=dict, blank=True)),
                ("stdout", models.TextField(blank=True)),
                ("stderr", models.TextField(blank=True)),
                ("error_message", models.TextField(blank=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("engagement", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="jobs", to="offensive_lab.engagement")),
                ("requested_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to="organizations.user")),
                ("target", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="jobs", to="offensive_lab.engagementtarget")),
            ],
            options={"ordering": ["-created_at"], "indexes": [models.Index(fields=["engagement", "status"], name="offlab_job_eng_status")]},
        ),
    ]
