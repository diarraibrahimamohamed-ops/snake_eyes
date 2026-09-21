from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenBlacklistView
from africanwatch.apps.organizations.views import AWTokenObtainPairView
urlpatterns = [
    path("token/", AWTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("token/logout/", TokenBlacklistView.as_view(), name="token_blacklist"),
]
