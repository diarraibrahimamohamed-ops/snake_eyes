import uuid

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("intelligence", "0003_source_url_template"),
    ]

    operations = [
        migrations.CreateModel(
            name="EvidenceRecord",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("source_label", models.CharField(blank=True, max_length=255)),
                ("source_url", models.URLField(blank=True)),
                ("acquisition_method", models.CharField(default="passive_collection", max_length=80)),
                ("captured_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("tlp", models.CharField(default="green", max_length=10)),
                ("payload", models.JSONField()),
                ("payload_sha256", models.CharField(db_index=True, max_length=64)),
                ("observation", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="evidence_records", to="intelligence.intelligenceobservation")),
                ("organization", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="evidence_records", to="organizations.organization")),
                ("run", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="evidence_records", to="intelligence.collectionrun")),
                ("source", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="evidence_records", to="intelligence.collectionsource")),
            ],
            options={
                "ordering": ["captured_at", "id"],
                "indexes": [
                    models.Index(fields=["organization", "captured_at"], name="intel_ev_org_cap_idx"),
                    models.Index(fields=["run", "captured_at"], name="intel_ev_run_cap_idx"),
                ],
            },
        ),
        migrations.CreateModel(
            name="EvidenceManifest",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("version", models.PositiveIntegerField(default=1)),
                ("hash_algorithm", models.CharField(default="SHA-256", max_length=16)),
                ("merkle_algorithm", models.CharField(default="sha256-0x00-leaf-0x01-node-duplicate-last-v1", max_length=64)),
                ("evidence_count", models.PositiveIntegerField(default=0)),
                ("root_hash", models.CharField(db_index=True, max_length=64)),
                ("entries", models.JSONField(default=list)),
                ("signature_algorithm", models.CharField(default="none", max_length=32)),
                ("signature", models.TextField(blank=True)),
                ("signing_key_id", models.CharField(blank=True, max_length=120)),
                ("generated_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("generated_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="generated_evidence_manifests", to="organizations.user")),
                ("organization", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="evidence_manifests", to="organizations.organization")),
                ("run", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="evidence_manifests", to="intelligence.collectionrun")),
            ],
            options={
                "ordering": ["-generated_at", "-version"],
                "indexes": [
                    models.Index(fields=["organization", "generated_at"], name="intel_evman_org_gen_idx"),
                ],
            },
        ),
        migrations.AddConstraint(
            model_name="evidencemanifest",
            constraint=models.UniqueConstraint(fields=("run", "version"), name="uniq_evidence_manifest_run_version"),
        ),
    ]
