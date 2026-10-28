"""Add tenant-scoped scanner report ingestion and normalized findings."""
import django.db.models.deletion
import uuid
from africanwatch.apps.vulns.models import report_upload_path
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("organizations", "0001_initial"),
        ("vulns", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="ReportIngestion",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("source_type", models.CharField(choices=[
                    ("nmap_xml", "Nmap XML"), ("nuclei_json", "Nuclei JSON"),
                    ("nuclei_jsonl", "Nuclei JSONL"), ("nessus_xml", "Nessus XML"),
                    ("shodan_json", "Shodan JSON"), ("shodan_csv", "Shodan CSV"),
                ], max_length=20)),
                ("report_file", models.FileField(max_length=500, upload_to=report_upload_path)),
                ("original_filename", models.CharField(max_length=255)),
                ("sha256", models.CharField(max_length=64)),
                ("size_bytes", models.PositiveBigIntegerField()),
                ("status", models.CharField(choices=[
                    ("pending", "En attente"), ("processing", "Traitement"),
                    ("completed", "Terminé"), ("failed", "Échec"),
                ], db_index=True, default="pending", max_length=20)),
                ("total_findings", models.PositiveIntegerField(default=0)),
                ("linked_findings", models.PositiveIntegerField(default=0)),
                ("unmatched_findings", models.PositiveIntegerField(default=0)),
                ("summary", models.JSONField(blank=True, default=dict)),
                ("error_message", models.TextField(blank=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("organization", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="report_ingestions", to="organizations.organization")),
                ("uploaded_by", models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name="uploaded_security_reports", to="organizations.user")),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.AddConstraint(
            model_name="reportingestion",
            constraint=models.UniqueConstraint(fields=("organization", "sha256"), name="uniq_report_org_sha256"),
        ),
        migrations.AddIndex(
            model_name="reportingestion",
            index=models.Index(fields=["organization", "status"], name="report_org_status"),
        ),
        migrations.CreateModel(
            name="ReportFinding",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("fingerprint", models.CharField(max_length=64)),
                ("external_asset", models.CharField(blank=True, max_length=500)),
                ("scanner", models.CharField(blank=True, max_length=50)),
                ("cve_id", models.CharField(blank=True, db_index=True, max_length=30)),
                ("cvss_score", models.FloatField(blank=True, null=True)),
                ("severity", models.CharField(choices=[
                    ("info", "Info"), ("low", "Faible"), ("medium", "Moyen"),
                    ("high", "Élevé"), ("critical", "Critique"),
                ], db_index=True, default="info", max_length=10)),
                ("title", models.CharField(max_length=500)),
                ("description", models.TextField(blank=True)),
                ("affected_component", models.CharField(blank=True, max_length=255)),
                ("remediation", models.TextField(blank=True)),
                ("references", models.JSONField(blank=True, default=list)),
                ("evidence", models.JSONField(blank=True, default=dict)),
                ("asset", models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name="imported_report_findings", to="organizations.asset")),
                ("report", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE, related_name="findings",
                    to="vulns.reportingestion")),
                ("vulnerability", models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name="imported_evidence", to="vulns.vulnerability")),
            ],
            options={"ordering": ["-severity", "title"]},
        ),
        migrations.AddConstraint(
            model_name="reportfinding",
            constraint=models.UniqueConstraint(fields=("report", "fingerprint"), name="uniq_report_finding_fp"),
        ),
        migrations.AddIndex(
            model_name="reportfinding",
            index=models.Index(fields=["report", "severity"], name="report_finding_severity"),
        ),
        migrations.AddIndex(
            model_name="reportfinding",
            index=models.Index(fields=["asset", "severity"], name="report_asset_severity"),
        ),
    ]
