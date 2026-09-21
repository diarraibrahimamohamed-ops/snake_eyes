"""AfricaWatch — Threat Intelligence Tasks"""
import logging
from datetime import timedelta
from celery import shared_task
from django.utils import timezone

logger = logging.getLogger("africanwatch.threat_intel")


@shared_task(bind=True, max_retries=3, default_retry_delay=300, queue="threat_intel")
def fetch_feed(self, feed_id: str):
    from africanwatch.apps.threat_intel.models import ThreatFeed
    from africanwatch.apps.threat_intel.fetchers import get_fetcher
    try:
        feed = ThreatFeed.objects.get(id=feed_id)
        feed.status = ThreatFeed.Status.ACTIVE
        feed.save(update_fields=["status"])
        count = get_fetcher(feed).fetch_and_import()
        feed.last_fetched_at = timezone.now()
        feed.last_ioc_count = count
        feed.total_iocs_imported += count
        feed.last_error = ""
        feed.save(update_fields=["last_fetched_at","last_ioc_count","total_iocs_imported","last_error"])
        logger.info(f"Feed '{feed.name}': {count} IOCs imported")
        return {"feed": feed.name, "imported": count}
    except ThreatFeed.DoesNotExist:
        return {"error": "Feed not found"}
    except Exception as exc:
        ThreatFeed.objects.filter(id=feed_id).update(status="error", last_error=str(exc)[:500])
        logger.error(f"Feed error {feed_id}: {exc}")
        raise self.retry(exc=exc)


@shared_task(queue="threat_intel")
def fetch_all_feeds():
    from africanwatch.apps.threat_intel.models import ThreatFeed
    feeds = ThreatFeed.objects.filter(status__in=["active","pending"])
    for feed in feeds:
        if feed.last_fetched_at:
            if timezone.now() < feed.last_fetched_at + timedelta(hours=feed.fetch_frequency_hours):
                continue
        fetch_feed.delay(str(feed.id))
    logger.info(f"Scheduled fetch for {feeds.count()} feeds")


@shared_task(queue="threat_intel")
def bootstrap_feeds():
    from africanwatch.apps.threat_intel.models import ThreatFeed
    feeds = [
        {"name":"AbuseCH URLhaus","description":"Malicious URLs","feed_type":"csv",
         "url":"https://urlhaus.abuse.ch/downloads/csv_recent/","is_public":True,
         "is_african_specific":False,"fetch_frequency_hours":1,"tlp_level":"white"},
        {"name":"AbuseCH Feodo Tracker","description":"C2 IPs","feed_type":"csv",
         "url":"https://feodotracker.abuse.ch/downloads/ipblocklist.csv","is_public":True,
         "is_african_specific":False,"fetch_frequency_hours":6,"tlp_level":"white"},
        {"name":"Emerging Threats IPs","description":"Compromised IPs","feed_type":"plaintext",
         "url":"https://rules.emergingthreats.net/blockrules/compromised-ips.txt","is_public":True,
         "is_african_specific":False,"fetch_frequency_hours":6,"tlp_level":"white"},
        {"name":"MalwareBazaar Recent","description":"Recent malware hashes","feed_type":"json",
         "url":"https://mb-api.abuse.ch/api/v1/","is_public":True,
         "is_african_specific":False,"fetch_frequency_hours":4,"tlp_level":"white"},
        {"name":"PhishTank","description":"Phishing URLs","feed_type":"json",
         "url":"https://data.phishtank.com/data/online-valid.json","is_public":True,
         "is_african_specific":False,"fetch_frequency_hours":3,"tlp_level":"white"},
    ]
    created = 0
    for fd in feeds:
        _, c = ThreatFeed.objects.get_or_create(name=fd["name"], defaults=fd)
        if c:
            created += 1
    logger.info(f"{created} public feeds initialized")
    if created > 0:
        fetch_all_feeds.delay()


@shared_task(bind=True, max_retries=2, default_retry_delay=60, queue="threat_intel")
def enrich_ioc(self, ioc_id: str):
    from africanwatch.apps.threat_intel.models import IOC
    from africanwatch.apps.threat_intel.enrichers import IPEnricher, DomainEnricher, HashEnricher
    try:
        ioc = IOC.objects.get(id=ioc_id)
        if ioc.ioc_type == IOC.IOCType.IP:
            IPEnricher(ioc).enrich()
        elif ioc.ioc_type == IOC.IOCType.DOMAIN:
            DomainEnricher(ioc).enrich()
        elif ioc.ioc_type in [IOC.IOCType.MD5, IOC.IOCType.SHA1, IOC.IOCType.SHA256]:
            HashEnricher(ioc).enrich()
        else:
            return {"skipped": True, "reason": "Type not enrichable"}
        ioc.save()
        _publish_kafka(ioc, "enriched")
        logger.info(f"IOC enriched: {ioc.value} ({ioc.ioc_type})")
        return {"ioc_id": ioc_id, "enriched": True}
    except IOC.DoesNotExist:
        return {"error": "IOC not found"}
    except Exception as exc:
        logger.error(f"Enrich error {ioc_id}: {exc}")
        raise self.retry(exc=exc)


@shared_task(queue="threat_intel")
def expire_old_iocs():
    from africanwatch.apps.threat_intel.models import IOC
    count = IOC.objects.filter(expiry_date__lt=timezone.now(), is_active=True).update(is_active=False)
    logger.info(f"{count} IOCs expired")
    return {"expired": count}


@shared_task(queue="threat_intel")
def compute_african_threat_score():
    from django.core.cache import cache
    from africanwatch.apps.threat_intel.models import IOC
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    qs = IOC.objects.filter(is_active=True, is_african_threat=True, last_seen__gte=last_24h)
    critical = qs.filter(severity="critical").count()
    high = qs.filter(severity="high").count()
    medium = qs.filter(severity="medium").count()
    score = min(100, critical * 10 + high * 3 + medium * 1)
    data = {"score": score, "level": "critical" if score >= 75 else "elevated" if score >= 40 else "stable",
            "iocs_24h": qs.count(), "critical_24h": critical, "computed_at": now.isoformat()}
    cache.set("african_threat_score", data, timeout=300)
    try:
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync
        async_to_sync(get_channel_layer().group_send)(
            "aw.dashboard", {"type": "threat_score_update", "data": data})
    except Exception:
        pass
    return data


def _publish_kafka(ioc, event_type: str):
    try:
        import json
        from confluent_kafka import Producer
        from django.conf import settings
        if not getattr(settings, "KAFKA_BOOTSTRAP_SERVERS", ""):
            return
        p = Producer({"bootstrap.servers": settings.KAFKA_BOOTSTRAP_SERVERS})
        p.produce(settings.KAFKA_TOPICS.get(f"IOC_{event_type.upper()}", "aw.ioc.event"),
                  json.dumps({"event_type": event_type, "ioc_id": str(ioc.id),
                              "ioc_type": ioc.ioc_type, "value": ioc.value,
                              "severity": ioc.severity, "is_african_threat": ioc.is_african_threat,
                              "ts": timezone.now().isoformat()}).encode())
        p.flush(timeout=3)
    except Exception as e:
        logger.debug(f"Kafka publish failed: {e}")
