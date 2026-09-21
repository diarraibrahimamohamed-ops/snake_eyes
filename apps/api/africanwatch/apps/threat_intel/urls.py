from django.urls import path, include
from rest_framework.routers import DefaultRouter
from africanwatch.apps.threat_intel.views import ThreatFeedViewSet, IOCViewSet, ThreatActorViewSet, CampaignViewSet
router = DefaultRouter()
router.register("feeds", ThreatFeedViewSet, basename="feed")
router.register("iocs", IOCViewSet, basename="ioc")
router.register("threat-actors", ThreatActorViewSet, basename="threat-actor")
router.register("campaigns", CampaignViewSet, basename="campaign")
urlpatterns = [path("", include(router.urls))]
