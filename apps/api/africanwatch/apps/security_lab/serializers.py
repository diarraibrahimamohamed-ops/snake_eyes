from rest_framework import serializers
from .models import SecurityReview, SecurityFinding, ToolDefinition


class SecurityReviewSerializer(serializers.ModelSerializer):
    finding_count = serializers.SerializerMethodField()
    class Meta:
        model = SecurityReview
        fields = "__all__"
        read_only_fields = ["organization", "requested_by", "status", "result", "stdout", "stderr", "error_message", "findings_count", "started_at", "completed_at", "duration_seconds"]

    def get_finding_count(self, obj):
        return obj.findings.count()

    def validate(self, attrs):
        if not attrs.get("authorization_reference", "").strip():
            raise serializers.ValidationError({"authorization_reference": "Une référence d'autorisation est obligatoire pour toute revue du Security Lab."})
        return attrs


class SecurityFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityFinding
        fields = "__all__"


class ToolDefinitionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ToolDefinition
        fields = "__all__"
