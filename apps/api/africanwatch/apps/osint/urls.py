from django.urls import path, include
from rest_framework.routers import DefaultRouter
from africanwatch.apps.osint.views import OSINTSourceViewSet, OSINTEventViewSet
router = DefaultRouter()
router.register("osint/sources", OSINTSourceViewSet, basename="osint-source")
router.register("osint/events", OSINTEventViewSet, basename="osint-event")
urlpatterns = [path("", include(router.urls))]
