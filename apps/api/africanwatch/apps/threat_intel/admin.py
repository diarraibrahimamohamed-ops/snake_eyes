from django.contrib import admin
from africanwatch.apps.threat_intel.models import IOC, ThreatFeed, ThreatActor, Campaign, ThreatReport

@admin.register(ThreatFeed)
class ThreatFeedAdmin(admin.ModelAdmin):
    list_display = ["name","feed_type","status","total_iocs_imported","last_fetched_at","is_african_specific"]
    list_filter = ["feed_type","status","is_african_specific"]
    search_fields = ["name","url"]
    readonly_fields = ["total_iocs_imported","last_fetched_at","last_ioc_count","last_error"]
    actions = ["trigger_fetch"]
    def trigger_fetch(self, request, queryset):
        from africanwatch.apps.threat_intel.tasks import fetch_feed
        for feed in queryset:
            fetch_feed.delay(str(feed.id))
        self.message_user(request, f"Récupération lancée pour {queryset.count()} flux.")
    trigger_fetch.short_description = "Lancer la récupération"

@admin.register(IOC)
class IOCAdmin(admin.ModelAdmin):
    list_display = ["value","ioc_type","severity","confidence","is_african_threat","country_code","is_active","last_seen"]
    list_filter = ["ioc_type","severity","is_african_threat","is_active","tlp_level"]
    search_fields = ["value","description"]
    readonly_fields = ["value_normalized","hit_count","false_positive_count"]
    date_hierarchy = "last_seen"
    ordering = ["-last_seen"]

@admin.register(ThreatActor)
class ThreatActorAdmin(admin.ModelAdmin):
    list_display = ["name","motivation","sophistication","targets_africa","is_active"]
    list_filter = ["motivation","sophistication","targets_africa","is_active"]
    search_fields = ["name","description"]
    filter_horizontal = ["iocs"]

@admin.register(Campaign)
class CampaignAdmin(admin.ModelAdmin):
    list_display = ["name","threat_actor","severity","is_ongoing","start_date"]
    list_filter = ["severity","is_ongoing","tlp_level"]
    search_fields = ["name","description"]
    filter_horizontal = ["iocs"]

@admin.register(ThreatReport)
class ThreatReportAdmin(admin.ModelAdmin):
    list_display = ["title","report_type","is_public","tlp_level","published_at"]
    list_filter = ["report_type","is_public","tlp_level"]
    search_fields = ["title","summary"]
