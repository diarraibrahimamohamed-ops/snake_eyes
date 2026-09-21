from django.urls import path, include
from rest_framework.routers import DefaultRouter
from africanwatch.apps.vulns.views import VulnerabilityViewSet, ScanJobViewSet
router = DefaultRouter()
router.register("vulnerabilities", VulnerabilityViewSet, basename="vulnerability")
router.register("scan-jobs", ScanJobViewSet, basename="scan-job")
urlpatterns = [path("", include(router.urls))]
