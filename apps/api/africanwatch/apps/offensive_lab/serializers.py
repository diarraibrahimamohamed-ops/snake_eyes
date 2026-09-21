from django.conf import settings
from django.utils import timezone
from rest_framework import serializers

from africanwatch.apps.organizations.models import Asset
from .models import Engagement, EngagementTarget, AssessmentJob, AssessmentFinding, AssessmentEvent

SAFE_PROFILES = [choice[0] for choice in AssessmentJob.Profile.choices]
ACTIVE_ASSET_TYPES = {Asset.AssetType.DOMAIN, Asset.AssetType.IP, Asset.AssetType.URL, Asset.AssetType.APPLICATION}


class EngagementSerializer(serializers.ModelSerializer):
    target_count = serializers.SerializerMethodField()

    class Meta:
        model = Engagement
        fields = [
            "id", "organization", "name", "authorization_reference", "scope_hash", "starts_at", "ends_at",
            "status", "approved", "approved_by", "approved_at", "lab_mode", "max_targets", "max_jobs_per_hour",
            "max_concurrent_jobs", "allowed_profiles", "notes", "target_count", "created_at",
        ]
        read_only_fields = ["scope_hash", "approved", "approved_by", "approved_at", "created_at"]

    def get_target_count(self, obj):
        return obj.targets.count()

    def validate(self, attrs):
        starts = attrs.get("starts_at", getattr(self.instance, "starts_at", None))
        ends = attrs.get("ends_at", getattr(self.instance, "ends_at", None))
        if starts and ends and ends <= starts:
            raise serializers.ValidationError({"ends_at": "La fin doit être postérieure au début."})
        if starts and starts < timezone.now() - timezone.timedelta(minutes=1) and not self.instance:
            raise serializers.ValidationError({"starts_at": "Une nouvelle autorisation doit démarrer maintenant ou dans le futur."})
        lab_mode = attrs.get("lab_mode", getattr(self.instance, "lab_mode", False))
        if lab_mode and not getattr(settings, "LAB_MODE", False):
            raise serializers.ValidationError({"lab_mode": "Le mode LAB doit être explicitement activé côté serveur."})
        profiles = attrs.get("allowed_profiles", getattr(self.instance, "allowed_profiles", [])) or []
        invalid = sorted(set(profiles) - set(SAFE_PROFILES))
        if invalid:
            raise serializers.ValidationError({"allowed_profiles": f"Profils invalides: {', '.join(invalid)}"})
        for field in ("max_targets", "max_jobs_per_hour", "max_concurrent_jobs"):
            value = attrs.get(field, getattr(self.instance, field, None))
            if value is not None and not 1 <= value <= (500 if field == "max_targets" else 100):
                raise serializers.ValidationError({field: "Valeur hors limites de sécurité."})
        return attrs


class EngagementTargetSerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source="asset.name", read_only=True)
    asset_value = serializers.CharField(source="asset.value", read_only=True)

    class Meta:
        model = EngagementTarget
        fields = ["id", "engagement", "asset", "asset_name", "asset_value", "enabled", "notes", "created_at"]
        read_only_fields = ["created_at"]

    def validate(self, attrs):
        engagement = attrs["engagement"]
        asset = attrs["asset"]
        if engagement.organization_id != asset.organization_id:
            raise serializers.ValidationError("La cible doit appartenir à la même organisation que l'engagement.")
        if asset.asset_type not in ACTIVE_ASSET_TYPES:
            raise serializers.ValidationError("Ce type d'actif n'est pas admis dans l'Offensive Lab actif.")
        if engagement.targets.exclude(pk=getattr(self.instance, "pk", None)).filter(enabled=True).count() >= engagement.max_targets:
            raise serializers.ValidationError("Le plafond de cibles de l'engagement est atteint.")
        if not asset.is_active or not asset.scan_enabled:
            raise serializers.ValidationError("Cet actif est désactivé ou non autorisé au scanning.")
        return attrs


class AssessmentJobSerializer(serializers.ModelSerializer):
    finding_count = serializers.IntegerField(source="findings.count", read_only=True)

    class Meta:
        model = AssessmentJob
        fields = [
            "id", "engagement", "target", "requested_by", "profile", "status", "command_summary", "result",
            "stdout", "stderr", "error_message", "started_at", "completed_at", "task_id", "scope_hash_at_launch",
            "execution_nonce", "result_sha256", "duration_seconds", "finding_count", "created_at",
        ]
        read_only_fields = [
            "requested_by", "status", "command_summary", "result", "stdout", "stderr", "error_message",
            "started_at", "completed_at", "task_id", "scope_hash_at_launch", "execution_nonce", "result_sha256",
            "duration_seconds", "finding_count", "created_at",
        ]


class AssessmentFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssessmentFinding
        fields = ["id", "job", "fingerprint", "severity", "category", "title", "description", "evidence", "remediation", "confidence", "created_at"]
        read_only_fields = ["created_at"]


class AssessmentEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssessmentEvent
        fields = ["id", "job", "event_type", "payload", "previous_hash", "event_hash", "timestamp"]
        read_only_fields = ["timestamp", "previous_hash", "event_hash"]
