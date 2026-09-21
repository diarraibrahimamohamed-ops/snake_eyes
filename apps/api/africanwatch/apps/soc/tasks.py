"""AfricaWatch — SOC Tasks"""
import logging
from celery import shared_task
from django.utils import timezone

logger = logging.getLogger("africanwatch.soc")


@shared_task(queue="default")
def update_soc_metrics():
    from africanwatch.apps.soc.models import Alert, Incident
    from django.core.cache import cache
    now = timezone.now()
    last_24h = now - timezone.timedelta(hours=24)
    metrics = {
        "alerts_open": Alert.objects.filter(status="new").count(),
        "alerts_24h": Alert.objects.filter(created_at__gte=last_24h).count(),
        "incidents_active": Incident.objects.filter(status__in=["open","investigating"]).count(),
        "critical_alerts": Alert.objects.filter(severity="critical", status="new").count(),
        "computed_at": now.isoformat(),
    }
    cache.set("soc_metrics", metrics, timeout=120)
    try:
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync
        async_to_sync(get_channel_layer().group_send)("aw.soc", {"type":"soc_metrics_update","data":metrics})
    except Exception:
        pass
    return metrics


@shared_task(queue="default")
def auto_correlate_iocs():
    from africanwatch.apps.soc.models import Alert
    from africanwatch.apps.threat_intel.models import IOC
    alerts = Alert.objects.filter(
        created_at__gte=timezone.now() - timezone.timedelta(hours=1),
        src_ip__isnull=False, status="new",
    )
    for alert in alerts:
        matching = IOC.objects.filter(ioc_type="ip", value_normalized=str(alert.src_ip).lower(), is_active=True)
        if matching.exists():
            alert.related_iocs.add(*matching)
            top = matching.order_by("-severity").first()
            if top and top.severity in ["high","critical"] and alert.severity not in ["high","critical"]:
                alert.severity = top.severity
                alert.save(update_fields=["severity"])


@shared_task(queue="default")
def process_wazuh_alert(alert_data: dict):
    from africanwatch.apps.soc.models import Alert
    from africanwatch.apps.organizations.models import Organization
    try:
        rule_level = int(alert_data.get("rule",{}).get("level", 0))
        if rule_level >= 15: severity = "critical"
        elif rule_level >= 12: severity = "high"
        elif rule_level >= 8: severity = "medium"
        else: severity = "low"
        org = Organization.objects.filter(is_active=True).first()
        if not org: return
        alert = Alert.objects.create(
            organization=org,
            title=alert_data.get("rule",{}).get("description","Wazuh Alert"),
            description=str(alert_data)[:2000],
            severity=severity, source=Alert.Source.WAZUH,
            src_ip=alert_data.get("data",{}).get("srcip"),
            hostname=alert_data.get("agent",{}).get("name",""),
            raw_log=alert_data,
        )
        logger.info(f"Wazuh alert created: {alert.title} [{severity}]")
        try:
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync
            from africanwatch.apps.soc.serializers import AlertSerializer
            async_to_sync(get_channel_layer().group_send)(
                f"aw.alerts.{org.id}", {"type":"alert_new","data":AlertSerializer(alert).data})
        except Exception:
            pass
    except Exception as e:
        logger.error(f"Wazuh alert processing error: {e}")
