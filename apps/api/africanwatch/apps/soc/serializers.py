"""AfricaWatch — SOC Serializers"""
from rest_framework import serializers
from africanwatch.apps.soc.models import Alert, Incident, IncidentTimeline, DetectionRule

class DetectionRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = DetectionRule
        fields = "__all__"

class AlertSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    assigned_to_name = serializers.CharField(source="assigned_to.get_full_name", read_only=True)
    rule_name = serializers.CharField(source="rule.name", read_only=True)
    class Meta:
        model = Alert
        fields = ["id","organization","organization_name","rule","rule_name","title","description",
                  "severity","status","source","src_ip","dst_ip","src_port","dst_port","protocol",
                  "hostname","mitre_tactics","mitre_techniques","assigned_to","assigned_to_name",
                  "acknowledged_at","resolved_at","tags","notes","enriched_data","created_at","updated_at"]
        read_only_fields = ["acknowledged_at","resolved_at","enriched_data"]

class IncidentTimelineSerializer(serializers.ModelSerializer):
    author_name = serializers.CharField(source="author.get_full_name", read_only=True)
    class Meta:
        model = IncidentTimeline
        fields = ["id","timestamp","author","author_name","action","details","is_automated"]

class IncidentSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    assigned_to_name = serializers.CharField(source="assigned_to.get_full_name", read_only=True)
    alert_count = serializers.IntegerField(read_only=True)
    timeline = IncidentTimelineSerializer(many=True, read_only=True)
    duration_hours = serializers.FloatField(read_only=True)
    class Meta:
        model = Incident
        fields = ["id","organization","organization_name","title","description","incident_type",
                  "severity","status","assigned_to","assigned_to_name","detected_at","contained_at",
                  "resolved_at","duration_hours","mitre_tactics","mitre_techniques","systems_affected",
                  "data_compromised","financial_impact_usd","executive_summary","root_cause",
                  "lessons_learned","remediation_steps","tags","is_public","tlp_level",
                  "alert_count","timeline","created_at","updated_at"]
        read_only_fields = ["duration_hours"]
