"""AfricaWatch — URLs"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView

api_v1 = [
    path("auth/", include("africanwatch.apps.organizations.urls.auth")),
    path("", include("africanwatch.apps.organizations.urls.api")),
    path("", include("africanwatch.apps.threat_intel.urls")),
    path("", include("africanwatch.apps.osint.urls")),
    path("", include("africanwatch.apps.soc.urls")),
    path("", include("africanwatch.apps.vulns.urls")),
    path("", include("africanwatch.apps.ai_engine.urls")),
    path("", include("africanwatch.apps.offensive_lab.urls")),
    path("", include("africanwatch.apps.security_lab.urls")),
    path("", include("africanwatch.apps.intelligence.urls")),
    path("", include("africanwatch.apps.malware_lab.urls")),
    path("dashboard/", include("africanwatch.apps.dashboard.urls")),
]

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/", include(api_v1)),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger"),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
    path("health/", include("africanwatch.health.urls")),
    path("metrics/", include("django_prometheus.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    try:
        import debug_toolbar
        urlpatterns = [path("__debug__/", include(debug_toolbar.urls))] + urlpatterns
    except ImportError: pass
