from __future__ import annotations
import hashlib, json
from urllib.parse import quote, urlparse
from django.db import transaction
from django.utils import timezone
from .models import CollectionRun, CollectionTarget, CollectionSource, IntelligenceObservation
from .classifier import classify_text, extract_iocs, reliability_grade
from .collectors import dns_enrichment, rdap_ip, rdap_domain, certificate_transparency, public_page, gdelt_news, provider_enrichment, rss_entries, public_api_snapshot

def _obs_hash(title: str, content: str, url: str) -> str:
    return hashlib.sha256(f"{title}\n{content}\n{url}".encode("utf-8", "ignore")).hexdigest()

@transaction.atomic
def save_observation(run, source, title, content, url="", published_at=None, raw=None):
    classification = classify_text(content)
    iocs = extract_iocs(content)
    grade, conf = reliability_grade(source.reliability, 0, published_at)
    actionability = min(1.0, 0.55 * classification["relevance"] + 0.35 * conf + 0.10 * (1.0 if iocs else 0.0))
    fp = _obs_hash(title, content, url)
    obj, created = IntelligenceObservation.objects.get_or_create(
        organization=run.organization,
        content_sha256=fp,
        source_url=url,
        defaults={
            "run": run, "source": source, "source_label": source.name, "title": title[:500], "content": content[:10000],
            "language": classification["language"], "published_at": published_at, "source_reliability": source.reliability,
            "confidence": conf, "relevance": classification["relevance"], "actionability_score": actionability, "classification": classification, "entities": {},
            "iocs": iocs, "evidence_grade": grade, "provenance": {"collector": "AfricaWatch/6.0", "retrieved_at": timezone.now().isoformat(), "raw": raw or {}},
        },
    )
    if not created:
        obj.last_seen = timezone.now(); obj.corroboration_count += 1; obj.save(update_fields=["last_seen", "corroboration_count"])
    return obj, created

def run_collection(run_id: str) -> dict:
    run = CollectionRun.objects.select_related("target", "organization").prefetch_related("sources").get(id=run_id)
    if not run.target.allowed:
        run.status = CollectionRun.Status.BLOCKED; run.error_message = "Cible non autorisée"; run.save(update_fields=["status", "error_message"]); return {"status":"blocked"}
    run.status = CollectionRun.Status.RUNNING; run.started_at = timezone.now(); run.save(update_fields=["status", "started_at"])
    observations = []
    try:
        kind, value = run.target.kind, run.target.value
        payloads = []
        if kind == CollectionTarget.Kind.DOMAIN:
            payloads += [("RDAP", "https://rdap.org", json.dumps(rdap_domain(value), ensure_ascii=False, default=str))]
            payloads += [("DNS", "https://local.invalid/dns", json.dumps(dns_enrichment(value), ensure_ascii=False, default=str))]
            payloads += [("CT", "https://crt.sh/", json.dumps(certificate_transparency(value), ensure_ascii=False, default=str))]
        elif kind == CollectionTarget.Kind.IP:
            payloads += [("RDAP", "https://rdap.org", json.dumps(rdap_ip(value), ensure_ascii=False, default=str))]
        elif kind == CollectionTarget.Kind.URL:
            payloads += [("WEB", value, json.dumps(public_page(value), ensure_ascii=False, default=str))]
        elif kind == CollectionTarget.Kind.ONION:
            payloads += [("ONION", value, json.dumps(public_page(value, onion=True), ensure_ascii=False, default=str))]
        elif kind == CollectionTarget.Kind.ORGANIZATION:
            from django.conf import settings
            articles = gdelt_news(value) if getattr(settings, "INTEL_ENABLE_GDELT", True) else []
            for article in articles:
                payloads.append(("GDELT", article.get("url", ""), json.dumps(article, ensure_ascii=False, default=str)))
        elif kind in {CollectionTarget.Kind.EMAIL, CollectionTarget.Kind.PHONE_PUBLIC, CollectionTarget.Kind.SOCIAL_PUBLIC, CollectionTarget.Kind.USERNAME_PUBLIC, CollectionTarget.Kind.EMAIL_DOMAIN}:
            payloads.append(("PUBLIC_IDENTIFIER", "", f"Identifiant public institutionnel: {value}"))
        else:
            payloads.append(("PUBLIC_SEARCH", "configured-search-provider://not-configured", f"Collecte passive différée pour {kind}: source de recherche institutionnelle à configurer."))
        from django.conf import settings
        sources = list(run.sources.filter(is_active=True)[:getattr(settings, "INTEL_MAX_SOURCES_PER_RUN", 12)])
        fallback = sources[0] if sources else None
        if not sources:
            raise ValueError("Au moins une source institutionnelle doit être attachée à la collecte")
        for label, url, body in payloads[:getattr(settings, "INTEL_MAX_OBSERVATIONS_PER_RUN", 100)]:
            obj, _ = save_observation(run, fallback, f"{label} — {run.target.value}", body, url=url)
            observations.append(obj.id.hex)
        # Attached institutional sources can add passive RSS/API snapshots.
        for source in sources:
            try:
                if source.kind == CollectionSource.Kind.RSS and "{target}" not in source.url:
                    for entry in rss_entries(source.url, limit=25):
                        body = json.dumps(entry, ensure_ascii=False)
                        obj, _ = save_observation(run, source, entry.get("title") or source.name, body, url=entry.get("url", ""))
                        observations.append(obj.id.hex)
                elif source.kind == CollectionSource.Kind.PUBLIC_API and "{target}" not in source.url:
                    body = json.dumps(public_api_snapshot(source.url), ensure_ascii=False, default=str)
                    obj, _ = save_observation(run, source, source.name, body, url=source.url)
                    observations.append(obj.id.hex)
            except Exception:
                continue
        # Public-source templates can target a public search/profile URL without login.
        for source in sources:
            if "{target}" not in source.url or source.kind == CollectionSource.Kind.RDAP:
                continue
            target_q = quote(run.target.value, safe="")
            target_url = source.url.replace("{target}", target_q)
            is_onion = source.kind == CollectionSource.Kind.ONION or ".onion" in (urlparse(target_url).hostname or "")
            try:
                page = public_page(target_url, onion=is_onion)
                obj, _ = save_observation(run, source, page.get("title") or f"{source.name} — {run.target.value}", page.get("body_preview", ""), url=target_url, raw=page)
                observations.append(obj.id.hex)
            except Exception:
                continue
        # Optional reputation/passive provider enrichment; never performs a scan against the target.
        if kind in {CollectionTarget.Kind.IP, CollectionTarget.Kind.DOMAIN}:
            for label, purl, body in provider_enrichment(kind, value):
                obj, _ = save_observation(run, fallback, f"{label} — {value}", body, url=purl)
                observations.append(obj.id.hex)
        _correlate_observations(run, observations)
        run.status = CollectionRun.Status.COMPLETED
        run.completed_at = timezone.now()
        run.result_summary = {"observations": len(observations), "target": run.target.value, "mode": run.mode, "limitations": ["collecte passive; pas de connexion à des comptes privés", "les attributs personnels ne sont pas enrichis automatiquement"]}
        material = "|".join(sorted(observations))
        run.evidence_root_hash = hashlib.sha256(material.encode()).hexdigest() if material else ""
        run.save(update_fields=["status", "completed_at", "result_summary", "evidence_root_hash"])
        return run.result_summary
    except Exception as exc:
        run.status = CollectionRun.Status.FAILED; run.error_message = str(exc)[:4000]; run.completed_at = timezone.now(); run.save(update_fields=["status", "error_message", "completed_at"]); raise


def _correlate_observations(run, observation_ids):
    from .models import IntelligenceObservation, IntelligenceRelation
    rows=list(IntelligenceObservation.objects.filter(id__in=observation_ids, organization=run.organization))
    for i,left in enumerate(rows):
        li={x.get("value","").lower() for x in left.iocs if x.get("value")}
        for right in rows[i+1:]:
            ri={x.get("value","").lower() for x in right.iocs if x.get("value")}
            shared=li & ri
            if not shared and left.language != right.language:
                continue
            weight=min(1.0, 0.45 + 0.15*len(shared)) if shared else 0.35
            rel="shared_ioc" if shared else "cross_language_related"
            IntelligenceRelation.objects.get_or_create(organization=run.organization,left=left,right=right,relation_type=rel,defaults={"weight":weight,"evidence":{"shared_iocs":sorted(shared)[:20]}})
    for row in rows:
        row.corroboration_count=IntelligenceRelation.objects.filter(organization=run.organization,left=row).count()+IntelligenceRelation.objects.filter(organization=run.organization,right=row).count()
        row.save(update_fields=["corroboration_count"])
