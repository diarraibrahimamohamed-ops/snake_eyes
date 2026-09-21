from django.contrib import admin
from africanwatch.apps.vulns.models import Vulnerability, ScanJob
@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ["title","cve_id","severity","cvss_score","status","asset","discovered_at"]
    list_filter = ["severity","status","scanner","is_exploitable"]
    search_fields = ["title","cve_id","description"]
    date_hierarchy = "discovered_at"
@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = ["asset","scan_type","status","findings_count","critical_count","started_at"]
    list_filter = ["scan_type","status"]
    readonly_fields = ["started_at","completed_at","findings_count","critical_count","high_count","medium_count","low_count"]
