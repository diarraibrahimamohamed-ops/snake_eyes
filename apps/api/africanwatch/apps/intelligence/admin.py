from django.contrib import admin

from .models import (
    CollectionTarget,
    CollectionSource,
    CollectionRun,
    IntelligenceObservation,
    IntelligenceRelation,
    ThreatForecast,
    EvidenceRecord,
    EvidenceManifest,
)

for model in [CollectionTarget, CollectionSource, CollectionRun, IntelligenceObservation, IntelligenceRelation, ThreatForecast]:
    admin.site.register(model)


@admin.register(EvidenceRecord)
class EvidenceRecordAdmin(admin.ModelAdmin):
    list_display = ("id", "organization", "source_label", "acquisition_method", "captured_at", "payload_sha256")
    list_filter = ("acquisition_method", "tlp", "captured_at")
    search_fields = ("source_label", "source_url", "payload_sha256", "id")
    readonly_fields = tuple(field.name for field in EvidenceRecord._meta.fields)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return obj is not None and super().has_change_permission(request, obj)

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(EvidenceManifest)
class EvidenceManifestAdmin(admin.ModelAdmin):
    list_display = ("id", "organization", "run", "version", "evidence_count", "root_hash", "generated_at")
    list_filter = ("signature_algorithm", "generated_at")
    search_fields = ("root_hash", "signing_key_id", "id")
    readonly_fields = tuple(field.name for field in EvidenceManifest._meta.fields)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return obj is not None and super().has_change_permission(request, obj)

    def has_delete_permission(self, request, obj=None):
        return False
