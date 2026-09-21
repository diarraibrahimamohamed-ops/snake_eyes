from django.urls import path, include
from rest_framework.routers import DefaultRouter
from africanwatch.apps.organizations.views import OrganizationViewSet, UserViewSet, AssetViewSet, AuditLogViewSet
router = DefaultRouter()
router.register("organizations", OrganizationViewSet, basename="organization")
router.register("users", UserViewSet, basename="user")
router.register("assets", AssetViewSet, basename="asset")
router.register("audit-logs", AuditLogViewSet, basename="audit-log")
urlpatterns = [path("", include(router.urls))]
