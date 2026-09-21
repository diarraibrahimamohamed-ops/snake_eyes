from django.contrib import admin
from africanwatch.apps.organizations.models import Organization, User, Asset, AuditLog
@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display=["name","org_type","country","tier","is_active","is_verified"]
    list_filter=["org_type","tier","is_active","is_verified"]
    search_fields=["name","contact_email"]
    readonly_fields=["api_key"]
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display=["email","get_full_name","role","organization","is_active"]
    list_filter=["role","is_active"]
    search_fields=["email","first_name","last_name"]
@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display=["name","asset_type","value","criticality","risk_score","organization"]
    list_filter=["asset_type","criticality","scan_enabled"]
    search_fields=["name","value"]
@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display=["timestamp","user","action","ip_address","success"]
    list_filter=["action","success"]
    def has_add_permission(self,r): return False
    def has_change_permission(self,r,o=None): return False
