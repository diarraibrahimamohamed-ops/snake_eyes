"""AfricaWatch — Dashboard API Views"""
import logging
from django.core.cache import cache
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.urls import path

logger = logging.getLogger("africanwatch.dashboard")

TLP_ORDER = ["white", "green", "amber", "red"]


def _is_global_admin(user):
    return bool(getattr(user, "is_superuser", False) or getattr(user, "role", "") == "super_admin")


def _organization_id(user):
    organization_id = getattr(user, "organization_id", None)
    if organization_id:
        return organization_id
    organization = getattr(user, "organization", None)
    return getattr(organization, "id", None)


def _scope_org(queryset, user, field="organization_id"):
    if _is_global_admin(user):
        return queryset
    org_id = _organization_id(user)
    if not org_id:
        return queryset.none()
    return queryset.filter(**{field: org_id})


def _scope_tlp(queryset, user):
    if _is_global_admin(user):
        return queryset
    organization = getattr(user, "organization", None)
    if organization is None:
        return queryset.none()
    level = getattr(organization, "tlp_level", "white")
    index = TLP_ORDER.index(level) if level in TLP_ORDER else 0
    return queryset.filter(tlp_level__in=TLP_ORDER[: index + 1])



@api_view(["GET"])
@permission_classes([IsAuthenticated])
def global_stats(request):
    """Tenant-scoped dashboard statistics; only global admins see cross-tenant totals."""
    from africanwatch.apps.threat_intel.models import IOC
    from africanwatch.apps.soc.models import Alert, Incident
    from africanwatch.apps.osint.models import OSINTEvent
    from africanwatch.apps.vulns.models import Vulnerability
    from africanwatch.apps.organizations.models import Organization, Asset

    user = request.user
    org_id = _organization_id(user)
    tlp_level = getattr(getattr(user, "organization", None), "tlp_level", "global")
    cache_key = "dashboard_global_stats:global" if _is_global_admin(user) else f"dashboard_global_stats:org:{org_id or 'unassigned'}:tlp:{tlp_level}"
    cached = cache.get(cache_key)
    if cached:
        return Response(cached)

    now = timezone.now()
    last_24h = now - timezone.timedelta(hours=24)
    last_7d = now - timezone.timedelta(days=7)

    iocs = _scope_tlp(IOC.objects.all(), user)
    alerts = _scope_org(Alert.objects.all(), user, "organization_id")
    incidents = _scope_org(Incident.objects.all(), user, "organization_id")
    osint_events = _scope_org(OSINTEvent.objects.all(), user, "organization_id")
    vulnerabilities = _scope_org(Vulnerability.objects.all(), user, "asset__organization_id")
    organizations = _scope_org(Organization.objects.filter(is_active=True), user, "id")
    assets = _scope_org(Asset.objects.filter(is_active=True), user, "organization_id")

    stats = {
        "threat_intelligence": {
            "total_iocs": iocs.filter(is_active=True).count(),
            "african_threats": iocs.filter(is_african_threat=True, is_active=True).count(),
            "new_24h": iocs.filter(created_at__gte=last_24h).count(),
            "new_7d": iocs.filter(created_at__gte=last_7d).count(),
            "critical": iocs.filter(severity="critical", is_active=True).count(),
            "high": iocs.filter(severity="high", is_active=True).count(),
        },
        "soc": {
            "alerts_open": alerts.filter(status="new").count(),
            "alerts_24h": alerts.filter(created_at__gte=last_24h).count(),
            "incidents_active": incidents.filter(status__in=["open", "investigating"]).count(),
            "critical_alerts": alerts.filter(severity="critical", status="new").count(),
        },
        "osint": {
            "events_24h": osint_events.filter(created_at__gte=last_24h).count(),
            "threat_relevant_24h": osint_events.filter(is_threat_relevant=True, created_at__gte=last_24h).count(),
        },
        "vulnerabilities": {
            "open": vulnerabilities.filter(status="open").count(),
            "critical_open": vulnerabilities.filter(status="open", severity="critical").count(),
            "exploitable": vulnerabilities.filter(status="open", is_exploitable=True).count(),
        },
        "infrastructure": {
            "organizations": organizations.count(),
            "assets": assets.count(),
        },
        # This is an intentionally shared regional signal, not a tenant data series.
        "threat_score": cache.get("african_threat_score", {"score": 0, "level": "stable", "iocs_24h": 0}),
        "computed_at": now.isoformat(),
    }

    cache.set(cache_key, stats, timeout=60)
    return Response(stats)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def recent_activity(request):
    """Activité récente — IOCs, alertes, events OSINT des dernières 24h."""
    from africanwatch.apps.threat_intel.models import IOC
    from africanwatch.apps.soc.models import Alert
    from africanwatch.apps.osint.models import OSINTEvent

    last_24h = timezone.now() - timezone.timedelta(hours=24)

    user = request.user
    recent_iocs = list(
        _scope_tlp(IOC.objects.filter(is_active=True, created_at__gte=last_24h), user)
        .order_by("-created_at")[:20]
        .values("id","ioc_type","value","severity","country_code","is_african_threat","created_at")
    )
    for ioc in recent_iocs:
        ioc["id"] = str(ioc["id"])
        if ioc.get("created_at"):
            ioc["created_at"] = ioc["created_at"].isoformat()

    recent_alerts = list(
        _scope_org(Alert.objects.filter(created_at__gte=last_24h), user, "organization_id")
        .order_by("-created_at")[:20]
        .values("id","title","severity","status","source","src_ip","created_at")
    )
    for alert in recent_alerts:
        alert["id"] = str(alert["id"])
        if alert.get("created_at"):
            alert["created_at"] = alert["created_at"].isoformat()

    recent_osint = list(
        _scope_org(OSINTEvent.objects.filter(is_threat_relevant=True, created_at__gte=last_24h), user, "organization_id")
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
        _scope_tlp(IOC.objects.filter(is_african_threat=True, is_active=True), request.user)
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
    """Métriques SOC limitées au tenant; seules les admins globaux voient les totaux globaux."""
    from africanwatch.apps.soc.models import Alert, Incident
    user = request.user
    org_id = _organization_id(user)
    cache_key = "soc_metrics:global" if _is_global_admin(user) else f"soc_metrics:org:{org_id or 'unassigned'}"
    cached = cache.get(cache_key)
    if cached:
        return Response(cached)

    now = timezone.now()
    last_24h = now - timezone.timedelta(hours=24)
    alerts = _scope_org(Alert.objects.all(), user, "organization_id")
    incidents = _scope_org(Incident.objects.all(), user, "organization_id")
    total_alerts = alerts.count()

    metrics = {
        "alerts_open": alerts.filter(status="new").count(),
        "alerts_24h": alerts.filter(created_at__gte=last_24h).count(),
        "incidents_active": incidents.filter(status__in=["open", "investigating"]).count(),
        "critical_alerts": alerts.filter(severity="critical", status="new").count(),
        "mttd_hours": 2.4,
        "mttr_hours": 8.7,
        "false_positive_rate": round(alerts.filter(status="false_positive").count() / max(total_alerts, 1) * 100, 1),
        "computed_at": now.isoformat(),
    }
    cache.set(cache_key, metrics, timeout=60)
    return Response(metrics)


urlpatterns = [
    path("stats/", global_stats, name="dashboard-stats"),
    path("activity/", recent_activity, name="dashboard-activity"),
    path("threat-map/", threat_map_data, name="dashboard-threat-map"),
    path("soc-metrics/", soc_metrics, name="dashboard-soc-metrics"),
]
