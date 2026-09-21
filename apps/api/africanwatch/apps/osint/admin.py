from django.contrib import admin
from africanwatch.apps.osint.models import OSINTSource, OSINTEvent

@admin.register(OSINTSource)
class OSINTSourceAdmin(admin.ModelAdmin):
    list_display = ["name","source_type","is_active","is_african_source","last_crawled_at","last_event_count","error_count"]
    list_filter = ["source_type","is_active","is_african_source"]
    search_fields = ["name","url","handle"]
    actions = ["trigger_collect"]
    def trigger_collect(self, request, queryset):
        from africanwatch.apps.osint.tasks import collect_source
        for src in queryset:
            collect_source.delay(str(src.id))
        self.message_user(request, f"Collecte lancée pour {queryset.count()} sources.")
    trigger_collect.short_description = "Lancer la collecte"

@admin.register(OSINTEvent)
class OSINTEventAdmin(admin.ModelAdmin):
    list_display = ["source","language_detected","threat_relevance_score","is_threat_relevant","is_verified","published_at"]
    list_filter = ["is_threat_relevant","is_verified","sentiment","language_detected"]
    search_fields = ["content","author"]
    readonly_fields = ["content_translated","entities_iocs","entities_persons","entities_organizations","entities_locations"]
    date_hierarchy = "published_at"
