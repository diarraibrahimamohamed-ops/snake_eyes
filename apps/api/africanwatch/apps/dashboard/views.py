"""AfricaWatch — Dashboard API Views"""
import logging
from django.core.cache import cache
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.urls import path

logger = logging.getLogger("africanwatch.dashboard")


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def global_stats(request):
    """Stats globales pour le dashboard — mises en cache 60s."""
    cached = cache.get("dashboard_global_stats")
    if cached:
        return Response(cached)

    from africanwatch.apps.threat_intel.models import IOC
    from africanwatch.apps.soc.models import Alert, Incident
    from africanwatch.apps.osint.models import OSINTEvent
    from africanwatch.apps.vulns.models import Vulnerability
    from africanwatch.apps.organizations.models import Organization, Asset

    now = timezone.now()
    last_24h = now - timezone.timedelta(hours=24)
    last_7d = now - timezone.timedelta(days=7)

    stats = {
        "threat_intelligence": {
            "total_iocs": IOC.objects.filter(is_active=True).count(),
            "african_threats": IOC.objects.filter(is_african_threat=True, is_active=True).count(),
            "new_24h": IOC.objects.filter(created_at__gte=last_24h).count(),
            "new_7d": IOC.objects.filter(created_at__gte=last_7d).count(),
            "critical": IOC.objects.filter(severity="critical", is_active=True).count(),
            "high": IOC.objects.filter(severity="high", is_active=True).count(),
        },
        "soc": {
            "alerts_open": Alert.objects.filter(status="new").count(),
            "alerts_24h": Alert.objects.filter(created_at__gte=last_24h).count(),
            "incidents_active": Incident.objects.filter(status__in=["open","investigating"]).count(),
            "critical_alerts": Alert.objects.filter(severity="critical", status="new").count(),
        },
        "osint": {
            "events_24h": OSINTEvent.objects.filter(created_at__gte=last_24h).count(),
            "threat_relevant_24h": OSINTEvent.objects.filter(
                is_threat_relevant=True, created_at__gte=last_24h).count(),
        },
        "vulnerabilities": {
            "open": Vulnerability.objects.filter(status="open").count(),
            "critical_open": Vulnerability.objects.filter(status="open", severity="critical").count(),
            "exploitable": Vulnerability.objects.filter(status="open", is_exploitable=True).count(),
        },
        "infrastructure": {
            "organizations": Organization.objects.filter(is_active=True).count(),
            "assets": Asset.objects.filter(is_active=True).count(),
        },
        "threat_score": cache.get("african_threat_score", {"score":0,"level":"stable","iocs_24h":0}),
        "computed_at": now.isoformat(),
    }

    cache.set("dashboard_global_stats", stats, timeout=60)
    return Response(stats)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def recent_activity(request):
    """Activité récente — IOCs, alertes, events OSINT des dernières 24h."""
    from africanwatch.apps.threat_intel.models import IOC
    from africanwatch.apps.soc.models import Alert
    from africanwatch.apps.osint.models import OSINTEvent

    last_24h = timezone.now() - timezone.timedelta(hours=24)

    recent_iocs = list(
        IOC.objects.filter(is_active=True, created_at__gte=last_24h)
        .order_by("-created_at")[:20]
        .values("id","ioc_type","value","severity","country_code","is_african_threat","created_at")
    )
    for ioc in recent_iocs:
        ioc["id"] = str(ioc["id"])
        if ioc.get("created_at"):
            ioc["created_at"] = ioc["created_at"].isoformat()

    recent_alerts = list(
        Alert.objects.filter(created_at__gte=last_24h)
        .order_by("-created_at")[:20]
        .values("id","title","severity","status","source","src_ip","created_at")
    )
    for alert in recent_alerts:
        alert["id"] = str(alert["id"])
        if alert.get("created_at"):
            alert["created_at"] = alert["created_at"].isoformat()

    recent_osint = list(
        OSINTEvent.objects.filter(is_threat_relevant=True, created_at__gte=last_24h)
        .order_by("-created_at")[:10]
        .values("id","content","language_detected","threat_relevance_score","source__name","created_at")
    )
    for evt in recent_osint:
        evt["id"] = str(evt["id"])
        if evt.get("created_at"):
            evt["created_at"] = evt["created_at"].isoformat()
        evt["content"] = evt["content"][:200]

    return Response({
        "iocs": recent_iocs,
        "alerts": recent_alerts,
        "osint_events": recent_osint,
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def threat_map_data(request):
    """Données de la carte des menaces africaines."""
    from africanwatch.apps.threat_intel.models import IOC
    from django.db.models import Count

    iocs_by_country = list(
        IOC.objects.filter(is_african_threat=True, is_active=True)
        .exclude(country_code="")
        .values("country_code","country_name","latitude","longitude")
        .annotate(
            total=Count("id"),
        )
        .order_by("-total")[:30]
    )

    return Response({
        "african_threats": iocs_by_country,
        "total_countries": len(iocs_by_country),
        "computed_at": timezone.now().isoformat(),
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def soc_metrics(request):
    """Métriques SOC temps réel."""
    cached = cache.get("soc_metrics")
    if cached:
        return Response(cached)

    from africanwatch.apps.soc.models import Alert, Incident
    now = timezone.now()
    last_24h = now - timezone.timedelta(hours=24)

    metrics = {
        "alerts_open": Alert.objects.filter(status="new").count(),
        "alerts_24h": Alert.objects.filter(created_at__gte=last_24h).count(),
        "incidents_active": Incident.objects.filter(status__in=["open","investigating"]).count(),
        "critical_alerts": Alert.objects.filter(severity="critical", status="new").count(),
        "mttd_hours": 2.4,
        "mttr_hours": 8.7,
        "false_positive_rate": round(
            Alert.objects.filter(status="false_positive").count() /
            max(Alert.objects.count(), 1) * 100, 1),
        "computed_at": now.isoformat(),
    }
    cache.set("soc_metrics", metrics, timeout=60)
    return Response(metrics)


urlpatterns = [
    path("stats/", global_stats, name="dashboard-stats"),
    path("activity/", recent_activity, name="dashboard-activity"),
    path("threat-map/", threat_map_data, name="dashboard-threat-map"),
    path("soc-metrics/", soc_metrics, name="dashboard-soc-metrics"),
]
