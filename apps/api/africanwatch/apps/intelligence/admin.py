from django.contrib import admin

from .models import (
    CollectionTarget,
    CollectionSource,
    CollectionRun,
    IntelligenceObservation,
    IntelligenceEvidence,
    IntelligenceRelation,
    ThreatForecast,
)


for model in [
    CollectionTarget,
    CollectionSource,
    CollectionRun,
    IntelligenceObservation,
    IntelligenceRelation,
    ThreatForecast,
]:
    admin.site.register(model)


@admin.register(IntelligenceEvidence)
class IntelligenceEvidenceAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "run",
        "sequence",
        "source_label",
        "captured_at",
        "record_hash",
    )
    list_filter = ("schema_version", "captured_at")
    search_fields = ("record_hash", "payload_sha256", "source_label")
    readonly_fields = (
        "id",
        "organization",
        "run",
        "observation",
        "source",
        "sequence",
        "schema_version",
        "captured_at",
        "source_label",
        "source_url",
        "payload",
        "payload_sha256",
        "previous_hash",
        "record_hash",
        "created_at",
        "updated_at",
    )
    ordering = ("run_id", "sequence")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
