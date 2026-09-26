from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied
from africanwatch.security.permissions import CanOperateSecurityAssessment, org_scope
from .models import CollectionTarget, CollectionSource, CollectionRun, IntelligenceObservation, IntelligenceRelation, ThreatForecast
from .serializers import *
from .collectors import dns_enrichment, rdap_ip, rdap_domain, certificate_transparency
from .tasks import run_collection_task, compute_forecast_task

class OrgScopedMixin:
    def get_queryset(self): return org_scope(super().get_queryset(), self.request.user, field="organization")
    def _org(self):
        org = getattr(self.request.user, "organization", None)
        if org is None:
            raise PermissionDenied("Utilisateur sans organisation")
        return org
class CollectionTargetViewSet(OrgScopedMixin, viewsets.ModelViewSet):
    queryset = CollectionTarget.objects.select_related("organization","asset")
    serializer_class = CollectionTargetSerializer
    permission_classes = [IsAuthenticated]
    def perform_create(self, serializer):
        serializer.save(organization=self._org(), allowed=False)
    @action(detail=True, methods=["post"], permission_classes=[CanOperateSecurityAssessment])
    def approve(self, request, pk=None):
        obj=self.get_object(); obj.allowed=True; obj.save(update_fields=["allowed","updated_at"]); return Response({"id":str(obj.id),"allowed":True})
class CollectionSourceViewSet(OrgScopedMixin, viewsets.ModelViewSet):
    queryset = CollectionSource.objects.select_related("organization")
    serializer_class = CollectionSourceSerializer
    permission_classes = [IsAuthenticated]
    def perform_create(self, serializer): serializer.save(organization=self._org())
class CollectionRunViewSet(OrgScopedMixin, viewsets.ModelViewSet):
    queryset = CollectionRun.objects.select_related("organization","target","requested_by").prefetch_related("sources")
    serializer_class = CollectionRunSerializer
    permission_classes = [IsAuthenticated]
    def perform_create(self, serializer):
        org=self._org(); target=serializer.validated_data.get("target")
        if target.organization_id != org.id and not self.request.user.is_superuser: raise PermissionDenied("Cible hors organisation")
        source_list=list(serializer.validated_data.get("sources", []))
        from django.conf import settings
        if len(source_list) > getattr(settings, "INTEL_MAX_SOURCES_PER_RUN", 12): raise PermissionDenied("Trop de sources pour une seule collecte")
        if any(src.organization_id != org.id for src in source_list) and not self.request.user.is_superuser: raise PermissionDenied("Source hors organisation")
        serializer.save(organization=org, requested_by=self.request.user, mode="passive")
    def get_permissions(self):
        return [CanOperateSecurityAssessment()] if self.action in {"create","run"} else [IsAuthenticated()]
    @action(detail=True, methods=["post"], permission_classes=[CanOperateSecurityAssessment])
    def run(self, request, pk=None):
        run=self.get_object()
        if run.status not in {CollectionRun.Status.QUEUED, CollectionRun.Status.FAILED}: return Response({"error":"Run déjà lancé"}, status=409)
        task=run_collection_task.delay(str(run.id)); return Response({"run_id":str(run.id),"task_id":task.id}, status=202)
class ObservationViewSet(OrgScopedMixin, viewsets.ReadOnlyModelViewSet):
    queryset = IntelligenceObservation.objects.select_related("organization","source","run")
    serializer_class = IntelligenceObservationSerializer
    permission_classes=[IsAuthenticated]
class RelationViewSet(OrgScopedMixin, viewsets.ReadOnlyModelViewSet):
    queryset = IntelligenceRelation.objects.select_related("organization","left","right")
    serializer_class=IntelligenceRelationSerializer
    permission_classes=[IsAuthenticated]
class ForecastViewSet(OrgScopedMixin, viewsets.ReadOnlyModelViewSet):
    queryset=ThreatForecast.objects.select_related("organization")
    serializer_class=ThreatForecastSerializer
    permission_classes=[IsAuthenticated]
    @action(detail=False, methods=["post"], permission_classes=[CanOperateSecurityAssessment])
    def refresh(self, request):
        org=self._org(); task=compute_forecast_task.delay(str(org.id)); return Response({"task_id":task.id}, status=202)
class PassiveLookupViewSet(viewsets.ViewSet):
    permission_classes=[IsAuthenticated, CanOperateSecurityAssessment]
    @action(detail=False, methods=["get"])
    def lookup(self, request):
        kind=request.query_params.get("kind","domain"); value=request.query_params.get("value","")
        if kind=="domain": data={"dns":dns_enrichment(value),"rdap":rdap_domain(value),"ct":certificate_transparency(value)}
        elif kind=="ip": data={"rdap":rdap_ip(value)}
        else: return Response({"error":"Seuls domain/ip sont disponibles pour le lookup passif."}, status=400)
        return Response(data)


@api_view(["GET"])
@permission_classes([IsAuthenticated, CanOperateSecurityAssessment])
def campaign_radar(request):
    from datetime import timedelta
    org = getattr(request.user, "organization", None)
    if org is None:
        raise PermissionDenied("Utilisateur sans organisation")
    since = timezone.now() - timedelta(days=7)
    rows = IntelligenceObservation.objects.filter(organization=org, retrieved_at__gte=since)[:1000]
    buckets = {}
    for row in rows:
        cats = [c.get("name") for c in (row.classification or {}).get("categories", []) if c.get("name")]
        for ioc in row.iocs or []:
            value = (ioc.get("value") or "").lower().strip()
            if not value: continue
            b = buckets.setdefault(value, {"observations": 0, "languages": set(), "categories": set(), "sources": set(), "first_seen": row.first_seen, "last_seen": row.last_seen})
            b["observations"] += 1
            if row.language: b["languages"].add(row.language)
            b["categories"].update(cats)
            if row.source_label: b["sources"].add(row.source_label)
            b["first_seen"] = min(b["first_seen"], row.first_seen)
            b["last_seen"] = max(b["last_seen"], row.last_seen)
    ranked = sorted(buckets.items(), key=lambda kv: (-kv[1]["observations"], -len(kv[1]["languages"])))[:50]
    return Response([{"key": key, "observations": data["observations"], "languages": sorted(data["languages"]), "categories": sorted(data["categories"]), "sources": sorted(data["sources"]), "cross_language": len(data["languages"]) > 1, "first_seen": data["first_seen"], "last_seen": data["last_seen"], "analytical_limit": "Corrélation défensive; aucune attribution politique ou individuelle."} for key, data in ranked])

@api_view(["GET"])
@permission_classes([IsAuthenticated, CanOperateSecurityAssessment])
def export_run_stix(request, pk):
    org = getattr(request.user, "organization", None)
    if org is None:
        raise PermissionDenied("Utilisateur sans organisation")
    run = CollectionRun.objects.filter(id=pk, organization=org).first()
    if not run:
        raise PermissionDenied("Collecte hors organisation")
    from .stix_export import export_run
    return Response(export_run(run))
