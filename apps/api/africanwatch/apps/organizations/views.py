"""AfricaWatch — Organizations Views"""
from django.db.models import Count
from django.utils import timezone
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from africanwatch.security.permissions import CanOperateSecurityAssessment, MinimumRole

class OrgAdminRole(MinimumRole):
    minimum_role = "org_admin"

from africanwatch.apps.organizations.models import Organization, User, Asset, AuditLog
from africanwatch.apps.organizations.serializers import OrganizationSerializer, UserSerializer, UserCreateSerializer, AssetSerializer, AuditLogSerializer, AWTokenObtainPairSerializer

class AWTokenObtainPairView(TokenObtainPairView):
    serializer_class = AWTokenObtainPairSerializer
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            try:
                user = User.objects.get(email=request.data.get("email","").lower())
                AuditLog.objects.create(user=user, organization=user.organization, action=AuditLog.Action.LOGIN,
                    ip_address=request.META.get("REMOTE_ADDR",""), user_agent=request.META.get("HTTP_USER_AGENT","")[:500], success=True)
                user.last_activity = timezone.now(); user.last_login_ip = request.META.get("REMOTE_ADDR","")
                user.save(update_fields=["last_activity","last_login_ip"])
            except Exception: pass
        return response

class OrganizationViewSet(viewsets.ModelViewSet):
    queryset = Organization.objects.annotate(user_count=Count("users"), asset_count=Count("assets"))
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ["org_type","country","tier","is_active"]
    search_fields = ["name","country_name","contact_email"]
    def get_queryset(self):
        qs = super().get_queryset(); u = self.request.user
        if not u.is_superuser and getattr(u,"role","") != "super_admin":
            qs = qs.filter(id=u.organization.id) if u.organization else qs.none()
        return qs

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.select_related("organization")
    permission_classes = [permissions.IsAuthenticated]
    def get_permissions(self):
        if self.action in {"create", "update", "partial_update", "destroy", "change_password"}:
            return [OrgAdminRole()]
        return [permissions.IsAuthenticated()]
    filterset_fields = ["role","is_active","organization"]
    search_fields = ["email","first_name","last_name"]
    def get_serializer_class(self): return UserCreateSerializer if self.action == "create" else UserSerializer
    def get_queryset(self):
        qs = super().get_queryset(); u = self.request.user
        if not u.is_superuser and getattr(u,"role","") != "super_admin":
            return qs.filter(organization=u.organization) if u.organization else qs.filter(id=u.id)
        return qs
    @action(detail=False, methods=["get","patch"], url_path="me")
    def me(self, request):
        if request.method == "GET": return Response(UserSerializer(request.user).data)
        s = UserSerializer(request.user, data=request.data, partial=True)
        s.is_valid(raise_exception=True); s.save(); return Response(s.data)
    @action(detail=True, methods=["post"], url_path="change-password")
    def change_password(self, request, pk=None):
        user = self.get_object()
        if not user.check_password(request.data.get("old_password","")): return Response({"error":"Ancien mot de passe incorrect."},status=400)
        new_pw = request.data.get("new_password","")
        if len(new_pw) < 12: return Response({"error":"Minimum 12 caractères."},status=400)
        user.set_password(new_pw); user.save()
        return Response({"message":"Mot de passe modifié."})

class AssetViewSet(viewsets.ModelViewSet):
    queryset = Asset.objects.annotate(vulnerability_count=Count("vulnerabilities")).select_related("organization")
    serializer_class = AssetSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ["asset_type","criticality","is_active","scan_enabled","organization"]
    search_fields = ["name","value","description"]
    def get_queryset(self):
        qs = super().get_queryset(); u = self.request.user
        if not u.is_superuser and getattr(u,"role","") != "super_admin":
            if u.organization: qs = qs.filter(organization=u.organization)
        return qs
    @action(detail=True, methods=["post"], permission_classes=[CanOperateSecurityAssessment])
    def scan(self, request, pk=None):
        asset = self.get_object()
        if not asset.scan_enabled:
            return Response({"error":"Les scans sont désactivés pour cet actif."}, status=400)
        from africanwatch.apps.vulns.tasks import scan_asset
        task = scan_asset.delay(str(asset.id), triggered_by=str(request.user.id))
        return Response({"message":f"Scan planifié pour {asset.name}","task_id":task.id},status=202)
    @action(detail=False, methods=["get"], url_path="risk-summary")
    def risk_summary(self, request):
        from django.db.models import Avg, Max
        qs = self.get_queryset()
        return Response({"total_assets":qs.count(),"avg_risk_score":round(qs.aggregate(a=Avg("risk_score"))["a"] or 0,2),"max_risk_score":qs.aggregate(m=Max("risk_score"))["m"] or 0,"by_criticality":list(qs.values("criticality").annotate(count=Count("id"))),"critical_assets":qs.filter(criticality="critical").count(),"never_scanned":qs.filter(last_scanned_at__isnull=True).count()})

class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AuditLog.objects.select_related("user","organization")
    serializer_class = AuditLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ["action","success","organization"]
    search_fields = ["user__email","ip_address","action"]
    ordering = ["-timestamp"]
    def get_queryset(self):
        qs = super().get_queryset(); u = self.request.user
        if not u.is_superuser and getattr(u,"role","") != "super_admin":
            if u.organization: qs = qs.filter(organization=u.organization)
        return qs
