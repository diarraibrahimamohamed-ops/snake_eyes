"""AfricaWatch — OSINT Tasks"""
import logging
from celery import shared_task
from django.utils import timezone
from django.db import models

logger = logging.getLogger("africanwatch.osint")

CYBER_KW_FR = ["cyberattaque","ransomware","piratage","malware","phishing","vulnérabilité",
               "fuite de données","intrusion","hack","botnet","spyware","ddos","exploitation"]
CYBER_KW_EN = ["cyberattack","ransomware","malware","phishing","breach","vulnerability",
               "exploit","backdoor","trojan","data leak","compromise","intrusion","apt"]
AFRICAN_KW = ["afrique","africa","mali","sénégal","ghana","nigeria","kenya","cameroun","burkina",
              "niger","côte d'ivoire","mobile money","orange money","mtn momo","wave","m-pesa"]


@shared_task(bind=True, max_retries=2, queue="osint")
def collect_source(self, source_id: str):
    from africanwatch.apps.osint.models import OSINTSource
    try:
        source = OSINTSource.objects.get(id=source_id)
        count = _collect(source)
        source.last_crawled_at = timezone.now()
        source.last_event_count = count
        source.error_count = 0
        source.save(update_fields=["last_crawled_at","last_event_count","error_count"])
        logger.info(f"OSINT '{source.name}': {count} events collected")
        return {"source": source.name, "collected": count}
    except Exception as exc:
        from africanwatch.apps.osint.models import OSINTSource as OS
        OS.objects.filter(id=source_id).update(error_count=models.F("error_count") + 1)
        logger.error(f"OSINT collect error {source_id}: {exc}")
        raise self.retry(exc=exc)


@shared_task(queue="osint")
def run_all_collections(organization_id=None):
    from africanwatch.apps.osint.models import OSINTSource
    from datetime import timedelta
    sources = OSINTSource.objects.filter(is_active=True, organization__isnull=False)
    if organization_id:
        sources = sources.filter(organization_id=organization_id)
    scheduled = 0
    for source in sources:
        if source.last_crawled_at:
            if timezone.now() < source.last_crawled_at + timedelta(minutes=source.crawl_frequency_minutes):
                continue
        collect_source.delay(str(source.id))
        scheduled += 1
    logger.info(f"OSINT scheduled: {scheduled} sources")
    return {"scheduled": scheduled}


@shared_task(queue="osint")
def process_osint_event(event_id: str):
    from africanwatch.apps.osint.models import OSINTEvent
    try:
        event = OSINTEvent.objects.get(id=event_id)
        text = event.content_translated or event.content
        event.entities_iocs = _extract_iocs(text)
        entities = _extract_entities(text)
        event.entities_locations = entities.get("LOC", [])
        event.entities_organizations = entities.get("ORG", [])
        event.entities_persons = entities.get("PER", [])
        event.is_processed = True
        event.save(update_fields=["entities_iocs","entities_locations","entities_organizations",
                                  "entities_persons","is_processed"])
        for ioc_data in event.entities_iocs[:10]:
            _create_ioc_from_text(ioc_data, event)
    except OSINTEvent.DoesNotExist:
        pass
    except Exception as e:
        logger.error(f"OSINT NLP error {event_id}: {e}")


# ── COLLECTORS ───────────────────────────────────────────────────────────────

def _collect(source) -> int:
    from africanwatch.apps.osint.models import OSINTSource as ST
    collectors = {
        ST.SourceType.NEWS_SITE: _collect_news,
        ST.SourceType.RSS: _collect_rss,
        ST.SourceType.TELEGRAM: _collect_telegram,
        ST.SourceType.GITHUB: _collect_github,
    }
    fn = collectors.get(source.source_type, lambda s: 0)
    try:
        return fn(source)
    except Exception as e:
        logger.error(f"Collector {source.source_type} error: {e}")
        return 0


def _score(text: str) -> float:
    t = text.lower()
    cyber = sum(1 for kw in CYBER_KW_FR + CYBER_KW_EN if kw in t)
    african = sum(1 for kw in AFRICAN_KW if kw in t)
    return min(cyber * 0.15 + african * 0.2, 1.0)


def _detect_lang(text: str) -> str:
    try:
        from langdetect import detect
        return detect(text)
    except Exception:
        return "fr"


def _translate(text: str, lang: str) -> str:
    if lang in ("fr","en") or not text:
        return text
    try:
        from deep_translator import GoogleTranslator
        return GoogleTranslator(source="auto", target="fr").translate(text[:500]) or text
    except Exception:
        return text


def _save_event(source, content, url="", author="", published_at=None, raw_data=None):
    from africanwatch.apps.osint.models import OSINTEvent
    lang = _detect_lang(content)
    score = _score(content)
    translated = _translate(content, lang)
    event = OSINTEvent.objects.create(
        source=source, organization=source.organization, content=content[:5000], content_translated=translated[:5000],
        language_detected=lang, url=url, author=author,
        published_at=published_at or timezone.now(),
        threat_relevance_score=score, is_threat_relevant=score >= 0.3,
        raw_data=raw_data or {},
    )
    if event.is_threat_relevant:
        process_osint_event.delay(str(event.id))
    return event


def _collect_news(source) -> int:
    import httpx
    from bs4 import BeautifulSoup
    from africanwatch.apps.osint.models import OSINTEvent
    created = 0
    try:
        from africanwatch.security.outbound import safe_get
        resp = safe_get(source.url, timeout=15, headers={"User-Agent": "AfricaWatch/2.0 SecurityBot"})
        if resp.status_code != 200:
            return 0
        soup = BeautifulSoup(resp.text, "lxml")
        articles = soup.find_all("article")[:20]
        if not articles:
            articles = soup.find_all(["h2","h3"])[:20]
        for article in articles:
            title = article.find("h2") or article.find("h3") or article
            if not title:
                continue
            link = article.find("a", href=True)
            url = link["href"] if link else source.url
            if not url.startswith("http"):
                continue
            if OSINTEvent.objects.filter(source=source, url=url).exists():
                continue
            _save_event(source, title.get_text().strip()[:2000], url=url)
            created += 1
    except Exception as e:
        logger.debug(f"NewsCollector {source.name}: {e}")
    return created


def _collect_rss(source) -> int:
    import feedparser
    from africanwatch.apps.osint.models import OSINTEvent
    created = 0
    try:
        from africanwatch.security.outbound import safe_get
        resp = safe_get(source.url, timeout=15)
        feed = feedparser.parse(resp.content)
        for entry in feed.entries[:50]:
            content = f"{entry.get('title','')} {entry.get('summary','')}"
            url = entry.get("link","")
            if url and OSINTEvent.objects.filter(source=source, url=url).exists():
                continue
            pub = None
            if entry.get("published"):
                try:
                    import dateutil.parser
                    pub = dateutil.parser.parse(entry.published)
                except Exception:
                    pass
            _save_event(source, content.strip()[:3000], url=url,
                       author=entry.get("author",""), published_at=pub)
            created += 1
    except Exception as e:
        logger.debug(f"RSSCollector {source.name}: {e}")
    return created


def _collect_telegram(source) -> int:
    import httpx
    from bs4 import BeautifulSoup
    channel = source.handle.lstrip("@")
    created = 0
    try:
        from africanwatch.security.outbound import safe_get
        resp = safe_get(f"https://t.me/s/{channel}", timeout=15)
        if resp.status_code != 200:
            return 0
        soup = BeautifulSoup(resp.text, "lxml")
        for msg in soup.find_all("div", class_="tgme_widget_message_text")[:30]:
            text = msg.get_text(separator=" ").strip()
            if not text or len(text) < 20:
                continue
            _save_event(source, text[:2000], url=f"https://t.me/{channel}", author=channel)
            created += 1
    except Exception as e:
        logger.debug(f"TelegramCollector {source.name}: {e}")
    return created


def _collect_github(source) -> int:
    import httpx
    from africanwatch.apps.osint.models import OSINTEvent
    keywords = ["africa password","mali credentials","senegal api key","ghana database","nigeria bank","kenya mpesa"]
    created = 0
    for kw in keywords[:3]:
        try:
            from africanwatch.security.outbound import safe_get
            query_url = "https://api.github.com/search/code?q=" + __import__("urllib.parse", fromlist=["quote"]).quote(kw) + "&sort=indexed&per_page=5"
            resp = safe_get(query_url, headers={"Accept": "application/vnd.github.v3+json"}, timeout=10, max_bytes=300_000)
            if resp.status_code != 200:
                continue
            for item in resp.json().get("items", []):
                url = item.get("html_url","")
                if url and OSINTEvent.objects.filter(source=source, url=url).exists():
                    continue
                content = f"Potential leak: {item.get('name')} in {item.get('repository',{}).get('full_name')} — keyword: {kw}"
                _save_event(source, content, url=url)
                created += 1
        except Exception as e:
            logger.debug(f"GitHubCollector: {e}")
    return created


# ── NLP HELPERS ──────────────────────────────────────────────────────────────

def _extract_iocs(text: str) -> list:
    import re
    iocs = []
    patterns = [
        (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'ip'),
        (r'\b[a-fA-F0-9]{64}\b', 'sha256'),
        (r'\b[a-fA-F0-9]{32}\b', 'md5'),
        (r'https?://[^\s<>"{}|\\^`\[\]]+', 'url'),
        (r'CVE-\d{4}-\d{4,}', 'cve'),
    ]
    for pattern, ioc_type in patterns:
        for match in re.findall(pattern, text)[:5]:
            iocs.append({"type": ioc_type, "value": match})
    return iocs


def _extract_entities(text: str) -> dict:
    from django.conf import settings
    if not getattr(settings, "OSINT_SPACY_ENABLED", False):
        return {"LOC": [], "ORG": [], "PER": []}
    try:
        import spacy
        nlp = spacy.load("fr_core_news_sm")
        doc = nlp(text[:2000])
        entities: dict = {"LOC": [], "ORG": [], "PER": []}
        for ent in doc.ents:
            if ent.label_ in entities and ent.text not in entities[ent.label_]:
                entities[ent.label_].append(ent.text)
        return entities
    except Exception:
        return {"LOC": [], "ORG": [], "PER": []}


def _create_ioc_from_text(ioc_data: dict, event):
    from africanwatch.apps.threat_intel.models import IOC
    from africanwatch.apps.threat_intel.tasks import enrich_ioc
    type_map = {"ip": IOC.IOCType.IP, "sha256": IOC.IOCType.SHA256,
                "md5": IOC.IOCType.MD5, "url": IOC.IOCType.URL, "cve": IOC.IOCType.CVE}
    ioc_type = type_map.get(ioc_data["type"])
    if not ioc_type:
        return
    try:
        ioc, created = IOC.objects.get_or_create(
            ioc_type=ioc_type, value_normalized=ioc_data["value"].lower(),
            defaults={"value": ioc_data["value"], "severity": "medium", "confidence": 50,
                     "first_seen": timezone.now(), "last_seen": timezone.now(),
                     "description": f"Extrait OSINT: {event.source.name}",
                     "tags": ["osint-extracted"]}
        )
        if created:
            enrich_ioc.delay(str(ioc.id))
        event.related_iocs.add(ioc)
    except Exception:
        pass
