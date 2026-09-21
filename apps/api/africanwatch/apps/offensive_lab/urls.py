from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import EngagementViewSet, EngagementTargetViewSet, AssessmentJobViewSet

router = DefaultRouter()
router.register("engagements", EngagementViewSet, basename="offensive-engagement")
router.register("engagement-targets", EngagementTargetViewSet, basename="offensive-target")
router.register("assessment-jobs", AssessmentJobViewSet, basename="assessment-job")
urlpatterns = [path("", include(router.urls))]
