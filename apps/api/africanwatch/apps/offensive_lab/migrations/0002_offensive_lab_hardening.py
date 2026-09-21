import uuid
from django.utils import timezone
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("offensive_lab", "0001_initial")]

    operations = [
        migrations.AddField(model_name="engagement", name="max_targets", field=models.PositiveIntegerField(default=25)),
        migrations.AddField(model_name="engagement", name="max_jobs_per_hour", field=models.PositiveIntegerField(default=20)),
        migrations.AddField(model_name="engagement", name="max_concurrent_jobs", field=models.PositiveIntegerField(default=2)),
        migrations.AddField(model_name="engagement", name="allowed_profiles", field=models.JSONField(blank=True, default=list)),
        migrations.AddField(model_name="assessmentjob", name="task_id", field=models.CharField(blank=True, max_length=255)),
        migrations.AddField(model_name="assessmentjob", name="scope_hash_at_launch", field=models.CharField(blank=True, max_length=64)),
        migrations.AddField(model_name="assessmentjob", name="execution_nonce", field=models.CharField(blank=True, max_length=64)),
        migrations.AddField(model_name="assessmentjob", name="result_sha256", field=models.CharField(blank=True, max_length=64)),
        migrations.AddField(model_name="assessmentjob", name="duration_seconds", field=models.FloatField(blank=True, null=True)),
        migrations.AlterField(
            model_name="assessmentjob",
            name="profile",
            field=models.CharField(
                choices=[
                    ("dns_recon", "Reconnaissance DNS"),
                    ("web_recon", "Reconnaissance HTTP/TLS"),
                    ("port_recon", "Découverte de services"),
                    ("combined_recon", "Reconnaissance combinée"),
                    ("tls_audit", "Audit TLS"),
                    ("exposure_audit", "Audit d’exposition"),
                    ("nuclei_safe", "Nuclei — contrôles non intrusifs"),
                ],
                max_length=30,
            ),
        ),
        migrations.AlterField(
            model_name="assessmentjob",
            name="status",
            field=models.CharField(
                choices=[
                    ("queued", "En file"),
                    ("running", "En cours"),
                    ("completed", "Terminée"),
                    ("failed", "Échec"),
                    ("blocked", "Bloquée"),
                    ("cancelled", "Annulée"),
                ],
                default="queued",
                max_length=20,
            ),
        ),
        migrations.CreateModel(
            name="AssessmentFinding",
            fields=[
                ("id", models.UUIDField(primary_key=True, serialize=False, default=uuid.uuid4, editable=False)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("fingerprint", models.CharField(max_length=64)),
                ("severity", models.CharField(choices=[("info", "Information"), ("low", "Faible"), ("medium", "Moyen"), ("high", "Élevé"), ("critical", "Critique")], default="info", max_length=10)),
                ("category", models.CharField(max_length=80)),
                ("title", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True)),
                ("evidence", models.JSONField(blank=True, default=dict)),
                ("remediation", models.TextField(blank=True)),
                ("confidence", models.FloatField(default=1.0)),
                ("job", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="findings", to="offensive_lab.assessmentjob")),
            ],
            options={"ordering": ["-severity", "category", "title"], "indexes": [models.Index(fields=["job", "severity"], name="offlab_find_job_sev")]},
        ),
        migrations.AddConstraint(
            model_name="assessmentfinding",
            constraint=models.UniqueConstraint(fields=("job", "fingerprint"), name="uniq_finding_job_fp"),
        ),
        migrations.CreateModel(
            name="AssessmentEvent",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("event_type", models.CharField(max_length=50)),
                ("payload", models.JSONField(blank=True, default=dict)),
                ("previous_hash", models.CharField(blank=True, max_length=64)),
                ("event_hash", models.CharField(max_length=64)),
                ("timestamp", models.DateTimeField(default=timezone.now, db_index=True)),
                ("job", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="events", to="offensive_lab.assessmentjob")),
            ],
            options={"ordering": ["id"], "indexes": [models.Index(fields=["job", "timestamp"], name="offlab_evt_job_time")]},
        ),
    ]
