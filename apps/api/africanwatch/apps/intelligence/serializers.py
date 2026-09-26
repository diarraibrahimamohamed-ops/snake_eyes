from rest_framework import serializers
from .models import CollectionTarget, CollectionSource, CollectionRun, IntelligenceObservation, IntelligenceRelation, ThreatForecast

class CollectionTargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = CollectionTarget
        fields = "__all__"
        read_only_fields = ["organization"]
    def validate(self, attrs):
        if not attrs.get("authorization_reference", "").strip():
            raise serializers.ValidationError({"authorization_reference": "Référence d'autorisation obligatoire."})
        value = (attrs.get("value") or "").strip()
        if not value:
            raise serializers.ValidationError({"value": "La valeur de cible est obligatoire."})
        attrs["value"] = value
        if attrs.get("kind") in {CollectionTarget.Kind.EMAIL, CollectionTarget.Kind.PHONE_PUBLIC, CollectionTarget.Kind.SOCIAL_PUBLIC} and not attrs.get("asset"):
            raise serializers.ValidationError({"asset": "Pour un identifiant de contact/social, un actif organisationnel enregistré est requis."})
        return attrs

class CollectionSourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = CollectionSource
        fields = "__all__"
        read_only_fields = ["organization"]
    def validate_url(self, value):
        if not value.strip():
            raise serializers.ValidationError("URL ou modèle de requête obligatoire.")
        return value.strip()

class CollectionRunSerializer(serializers.ModelSerializer):
    def validate(self, attrs):
        sources = attrs.get("sources")
        if not sources:
            raise serializers.ValidationError({"sources": "Au moins une source est requise pour une collecte."})
        return attrs
    class Meta:
        model = CollectionRun
        fields = "__all__"
        read_only_fields = ["organization","requested_by","status","started_at","completed_at","result_summary","evidence_root_hash","error_message"]

class IntelligenceObservationSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntelligenceObservation
        fields = "__all__"
        read_only_fields = [f.name for f in IntelligenceObservation._meta.fields]

class IntelligenceRelationSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntelligenceRelation
        fields = "__all__"
        read_only_fields = [f.name for f in IntelligenceRelation._meta.fields]

class ThreatForecastSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatForecast
        fields = "__all__"
        read_only_fields = [f.name for f in ThreatForecast._meta.fields]
