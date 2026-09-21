from django.contrib import admin
from .models import Engagement, EngagementTarget, AssessmentJob, AssessmentFinding, AssessmentEvent


@admin.register(Engagement)
class EngagementAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "status", "approved", "starts_at", "ends_at", "lab_mode")
    list_filter = ("status", "approved", "lab_mode")
    search_fields = ("name", "authorization_reference", "organization__name")


@admin.register(EngagementTarget)
class EngagementTargetAdmin(admin.ModelAdmin):
    list_display = ("engagement", "asset", "enabled", "created_at")
    list_filter = ("enabled",)
    search_fields = ("engagement__name", "asset__value")


@admin.register(AssessmentJob)
class AssessmentJobAdmin(admin.ModelAdmin):
    list_display = ("id", "engagement", "profile", "status", "requested_by", "created_at", "duration_seconds")
    list_filter = ("profile", "status")
    search_fields = ("id", "engagement__name", "task_id", "result_sha256")
    readonly_fields = ("result", "stdout", "stderr", "scope_hash_at_launch", "execution_nonce", "result_sha256")


@admin.register(AssessmentFinding)
class AssessmentFindingAdmin(admin.ModelAdmin):
    list_display = ("job", "severity", "category", "title", "confidence", "created_at")
    list_filter = ("severity", "category")
    search_fields = ("title", "description", "fingerprint")


@admin.register(AssessmentEvent)
class AssessmentEventAdmin(admin.ModelAdmin):
    list_display = ("id", "job", "event_type", "timestamp", "event_hash")
    readonly_fields = ("timestamp", "previous_hash", "event_hash")
