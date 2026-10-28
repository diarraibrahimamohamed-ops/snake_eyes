from django.urls import path, include
from rest_framework.routers import DefaultRouter
from africanwatch.apps.vulns.views import VulnerabilityViewSet, ScanJobViewSet, ReportIngestionViewSet, ReportFindingViewSet
router = DefaultRouter()
router.register("vulnerabilities", VulnerabilityViewSet, basename="vulnerability")
router.register("scan-jobs", ScanJobViewSet, basename="scan-job")
router.register("report-ingestions", ReportIngestionViewSet, basename="report-ingestion")
router.register("report-findings", ReportFindingViewSet, basename="report-finding")
urlpatterns = [path("", include(router.urls))]
