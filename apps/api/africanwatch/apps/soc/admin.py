from django.contrib import admin
from africanwatch.apps.soc.models import Alert, Incident, DetectionRule, IncidentTimeline
@admin.register(DetectionRule)
class DetectionRuleAdmin(admin.ModelAdmin):
    list_display = ["name","rule_type","severity","status","hit_count","is_african_specific"]
    list_filter = ["rule_type","severity","status","is_african_specific"]
    search_fields = ["name","description"]
@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ["title","severity","status","source","organization","src_ip","created_at"]
    list_filter = ["severity","status","source"]
    search_fields = ["title","src_ip","hostname"]
    readonly_fields = ["raw_log","enriched_data"]
    date_hierarchy = "created_at"
    ordering = ["-created_at"]
@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ["title","incident_type","severity","status","organization","detected_at"]
    list_filter = ["incident_type","severity","status"]
    search_fields = ["title","description"]
    filter_horizontal = ["alerts","related_iocs","affected_assets","responders"]
@admin.register(IncidentTimeline)
class IncidentTimelineAdmin(admin.ModelAdmin):
    list_display = ["incident","timestamp","author","action","is_automated"]
    list_filter = ["is_automated"]
    ordering = ["-timestamp"]
