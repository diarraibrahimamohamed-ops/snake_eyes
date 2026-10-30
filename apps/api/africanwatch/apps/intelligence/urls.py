from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (CollectionTargetViewSet, CollectionSourceViewSet, CollectionRunViewSet, ObservationViewSet, RelationViewSet, ForecastViewSet, PassiveLookupViewSet, EvidenceRecordViewSet, EvidenceManifestViewSet, campaign_radar, export_run_stix)

router = DefaultRouter()
router.register("collection-targets", CollectionTargetViewSet, basename="collection-target")
router.register("collection-sources", CollectionSourceViewSet, basename="collection-source")
router.register("collection-runs", CollectionRunViewSet, basename="collection-run")
router.register("intelligence-observations", ObservationViewSet, basename="intelligence-observation")
router.register("intelligence-relations", RelationViewSet, basename="intelligence-relation")
router.register("threat-forecasts", ForecastViewSet, basename="threat-forecast")
router.register("evidence-records", EvidenceRecordViewSet, basename="evidence-record")
router.register("evidence-manifests", EvidenceManifestViewSet, basename="evidence-manifest")

urlpatterns = router.urls + [
    path("passive-lookup/", PassiveLookupViewSet.as_view({"get": "lookup"}), name="passive-lookup"),
    path("campaign-radar/", campaign_radar, name="campaign-radar"),
    path("collection-runs/<uuid:pk>/export-stix/", export_run_stix, name="collection-run-export-stix"),
]
