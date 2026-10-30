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
            name="IntelligenceEvidence",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("sequence", models.PositiveIntegerField()),
                ("schema_version", models.PositiveSmallIntegerField(default=1)),
                ("captured_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("source_label", models.CharField(blank=True, max_length=255)),
                ("source_url", models.URLField(blank=True)),
                ("payload", models.JSONField()),
                ("payload_sha256", models.CharField(max_length=64)),
                ("previous_hash", models.CharField(blank=True, max_length=64)),
                ("record_hash", models.CharField(db_index=True, max_length=64)),
                (
                    "observation",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="evidence_records",
                        to="intelligence.intelligenceobservation",
                    ),
                ),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="intelligence_evidence",
                        to="organizations.organization",
                    ),
                ),
                (
                    "run",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="evidence_records",
                        to="intelligence.collectionrun",
                    ),
                ),
                (
                    "source",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="evidence_records",
                        to="intelligence.collectionsource",
                    ),
                ),
            ],
            options={
                "ordering": ["run_id", "sequence"],
            },
        ),
        migrations.AddConstraint(
            model_name="intelligenceevidence",
            constraint=models.UniqueConstraint(
                fields=("run", "sequence"),
                name="uniq_intel_evidence_run_sequence",
            ),
        ),
        migrations.AddIndex(
            model_name="intelligenceevidence",
            index=models.Index(
                fields=["organization", "captured_at"],
                name="intel_evidence_org_time_idx",
            ),
        ),
    ]
