"""AfricaWatch — Vulns Serializers"""
from rest_framework import serializers
from africanwatch.apps.vulns.models import Vulnerability, ScanJob
class VulnerabilitySerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source="asset.name", read_only=True)
    asset_value = serializers.CharField(source="asset.value", read_only=True)
    class Meta:
        model = Vulnerability
        fields = ["id","asset","asset_name","asset_value","cve_id","cvss_score","severity","title",
                  "description","affected_component","affected_version","fixed_version","status",
                  "discovered_at","remediated_at","remediation_notes","scanner","references",
                  "is_exploitable","exploit_available","tags","created_at"]
        read_only_fields = ["discovered_at"]
class ScanJobSerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source="asset.name", read_only=True)
    triggered_by_name = serializers.CharField(source="triggered_by.get_full_name", read_only=True)
    class Meta:
        model = ScanJob
        fields = ["id","asset","asset_name","scan_type","status","started_at","completed_at",
                  "findings_count","critical_count","high_count","medium_count","low_count",
                  "error_message","triggered_by","triggered_by_name","created_at"]
        read_only_fields = ["started_at","completed_at","findings_count","critical_count",
                            "high_count","medium_count","low_count","error_message","status"]
