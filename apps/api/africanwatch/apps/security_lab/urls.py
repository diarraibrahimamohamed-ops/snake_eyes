from rest_framework.routers import DefaultRouter
from .views import SecurityReviewViewSet, SecurityFindingViewSet, ToolDefinitionViewSet

router = DefaultRouter()
router.register("security-reviews", SecurityReviewViewSet, basename="security-review")
router.register("security-findings", SecurityFindingViewSet, basename="security-finding")
router.register("security-tools", ToolDefinitionViewSet, basename="security-tool")
urlpatterns = router.urls
