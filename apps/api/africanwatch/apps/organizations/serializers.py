"""AfricaWatch — Organizations Serializers"""
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from africanwatch.apps.organizations.models import Organization, User, Asset, AuditLog

class OrganizationSerializer(serializers.ModelSerializer):
    user_count = serializers.IntegerField(read_only=True)
    asset_count = serializers.IntegerField(read_only=True)
    class Meta:
        model = Organization
        fields = ["id","name","slug","org_type","country","country_name","tier","tlp_level","contact_email","website","description","is_active","is_verified","max_assets","max_users","user_count","asset_count","created_at"]
        read_only_fields = ["slug","is_verified"]

class UserSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    full_name = serializers.CharField(source="get_full_name", read_only=True)
    class Meta:
        model = User
        fields = ["id","email","first_name","last_name","full_name","organization","organization_name","role","bio","phone","country","timezone","language","is_active","is_mfa_enabled","email_notifications","sms_notifications","notification_severity_threshold","last_activity","created_at"]
        read_only_fields = ["email", "organization", "role", "is_active", "is_mfa_enabled", "last_activity", "created_at"]

class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=12)
    password_confirm = serializers.CharField(write_only=True)
    class Meta:
        model = User
        fields = ["email","first_name","last_name","password","password_confirm","organization","role","phone","country"]
    def validate(self, data):
        if data["password"] != data.pop("password_confirm"):
            raise serializers.ValidationError({"password_confirm":"Les mots de passe ne correspondent pas."})
        request = self.context.get("request")
        target_org = data.get("organization")
        if request and request.user.is_authenticated and not request.user.is_superuser:
            if target_org != request.user.organization:
                raise serializers.ValidationError({"organization":"Vous ne pouvez créer un utilisateur que dans votre organisation."})
            if data.get("role") == User.Role.SUPER_ADMIN:
                raise serializers.ValidationError({"role":"Création de super-administrateur interdite via cette API."})
        return data
    def create(self, validated_data):
        p = validated_data.pop("password")
        u = User(**validated_data); u.set_password(p); u.save()
        return u

class AssetSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    vulnerability_count = serializers.IntegerField(read_only=True)
    class Meta:
        model = Asset
        fields = ["id","organization","organization_name","name","asset_type","value","criticality","description","tags","risk_score","exposure_score","last_scanned_at","scan_enabled","scan_frequency_hours","ip_addresses","open_ports","technologies","geolocation","is_active","vulnerability_count","created_at","updated_at"]
        read_only_fields = ["risk_score","exposure_score","last_scanned_at","ip_addresses","open_ports","technologies","geolocation"]

    def validate(self, attrs):
        request = self.context.get("request")
        target_org = attrs.get("organization", getattr(self.instance, "organization", None))
        if request and request.user.is_authenticated and not request.user.is_superuser and target_org != request.user.organization:
            raise serializers.ValidationError({"organization": "Actif limité à votre organisation."})
        return attrs

class AuditLogSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source="user.email", read_only=True)
    class Meta:
        model = AuditLog
        fields = ["id","timestamp","user","user_email","action","resource_type","resource_id","ip_address","details","success"]
        read_only_fields = fields

class AWTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = "email"
    def validate(self, attrs):
        data = super().validate(attrs)
        u = self.user
        data["user"] = {"id":str(u.id),"email":u.email,"full_name":u.get_full_name(),"role":u.role,"organization":str(u.organization.id) if u.organization else None,"organization_name":u.organization.name if u.organization else None}
        return data
