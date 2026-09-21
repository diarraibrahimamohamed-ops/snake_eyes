from django.urls import path, include
from rest_framework.routers import DefaultRouter
from africanwatch.apps.soc.views import AlertViewSet, IncidentViewSet, DetectionRuleViewSet
router = DefaultRouter()
router.register("alerts", AlertViewSet, basename="alert")
router.register("incidents", IncidentViewSet, basename="incident")
router.register("detection-rules", DetectionRuleViewSet, basename="detection-rule")
urlpatterns = [path("", include(router.urls))]
