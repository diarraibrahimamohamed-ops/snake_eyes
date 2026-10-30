from __future__ import annotations
import hashlib, json
from urllib.parse import quote, urlparse
from django.db import transaction
from django.utils import timezone
from .models import CollectionRun, CollectionTarget, CollectionSource, IntelligenceObservation
from .classifier import classify_text, extract_iocs, reliability_grade
from .collectors import dns_enrichment, rdap_ip, rdap_domain, certificate_transparency, public_page, gdelt_news, provider_enrichment, rss_entries, public_api_snapshot

def _obs_hash(title: str, content: str, url: str) -> str:
    # Keep the existing deduplication key stable for observations already stored in v6.
    return hashlib.sha256(f"{title}\n{content}\n{url}".encode("utf-8", "ignore")).hexdigest()


@transaction.atomic
def save_observation(
    run, source, title, content, url="", published_at=None, raw=None, source_label=None
):
    from .evidence import append_evidence_record
    from .models import IntelligenceEvidence

    retrieved_at = timezone.now()
    classification = classify_text(content)
    iocs = extract_iocs(content)
    source_reliability = float(source.reliability) if source else 0.5
    label = source_label or (source.name if source else "Source externe non référencée")
    grade, conf = reliability_grade(source_reliability, 0, published_at)
    actionability = min(1.0, 0.55 * classification["relevance"] + 0.35 * conf + 0.10 * (1.0 if iocs else 0.0))
    fp = _obs_hash(title, content, url)
    obj, created = IntelligenceObservation.objects.get_or_create(
        organization=run.organization,
        content_sha256=fp,
        source_url=url,
        defaults={
            "run": run, "source": source, "source_label": label, "title": title[:500], "content": content[:10000],
            "language": classification["language"], "published_at": published_at, "source_reliability": source_reliability,
            "confidence": conf, "relevance": classification["relevance"], "actionability_score": actionability,
            "classification": classification, "entities": {}, "iocs": iocs, "evidence_grade": grade,
            "provenance": {
                "collector": "AfricaWatch/6.0",
                "retrieved_at": retrieved_at.isoformat(),
                "source_id": str(source.id) if source else None,
                "source_kind": source.kind if source else None,
                "source_label": label,
                "source_url": url or "",
                "content_truncated": len(content or "") > 10000,
            },
        },
    )
    if not created:
        obj.last_seen = retrieved_at
        obj.save(update_fields=["last_seen", "updated_at"])

    append_evidence_record(
        run=run,
        observation=obj,
        source=source,
        source_label=label,
        source_url=url,
        title=title,
        content=content,
        published_at=published_at,
        raw=raw,
        captured_at=retrieved_at,
    )

    # Repeated retrievals from one source are not independent corroboration.
    source_keys = set()
    for source_id, evidence_source_label, evidence_source_url in (
        IntelligenceEvidence.objects.filter(observation=obj)
        .values_list("source_id", "source_label", "source_url")
    ):
        if source_id:
            source_keys.add(("registered", str(source_id)))
        elif evidence_source_url:
            source_keys.add(("url", evidence_source_url.casefold()))
    corroborations = max(0, len(source_keys) - 1)
    if obj.corroboration_count != corroborations:
        obj.corroboration_count = corroborations
        obj.save(update_fields=["corroboration_count", "updated_at"])

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
            payloads += [("DNS enrichment", "", json.dumps(dns_enrichment(value), ensure_ascii=False, default=str))]
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
            payloads.append(("PUBLIC_SEARCH non configurée", "", f"Collecte passive différée pour {kind}: source de recherche institutionnelle à configurer."))
        from django.conf import settings
        sources = list(run.sources.filter(is_active=True)[:getattr(settings, "INTEL_MAX_SOURCES_PER_RUN", 12)])
        if not sources:
            raise ValueError("Au moins une source institutionnelle doit être attachée à la collecte")
        for label, url, body in payloads[:getattr(settings, "INTEL_MAX_OBSERVATIONS_PER_RUN", 100)]:
            obj, _ = save_observation(
                run, None, f"{label} — {run.target.value}", body,
                url=url, source_label=label,
            )
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
                obj, _ = save_observation(
                    run, None, f"{label} — {value}", body, url=purl, source_label=label
                )
                observations.append(obj.id.hex)
        _correlate_observations(run, observations)
        run.status = CollectionRun.Status.COMPLETED
        run.completed_at = timezone.now()
        from .models import IntelligenceEvidence

        run.refresh_from_db(fields=["evidence_root_hash"])
        evidence_count = IntelligenceEvidence.objects.filter(run=run).count()
        run.result_summary = {
            "observations": len(set(observations)),
            "acquisition_events": len(observations),
            "evidence_records": evidence_count,
            "evidence_root_hash": run.evidence_root_hash,
            "target": run.target.value,
            "mode": run.mode,
            "limitations": [
                "collecte passive; pas de connexion à des comptes privés",
                "les attributs personnels ne sont pas enrichis automatiquement",
                "les aperçus de contenu dépassant 10 000 caractères sont tronqués; l'empreinte du contenu reçu est conservée",
            ],
        }
        run.save(update_fields=["status", "completed_at", "result_summary", "evidence_root_hash"])
        return run.result_summary
    except Exception as exc:
        run.status = CollectionRun.Status.FAILED; run.error_message = str(exc)[:4000]; run.completed_at = timezone.now(); run.save(update_fields=["status", "error_message", "completed_at"]); raise


def _correlate_observations(run, observation_ids):
    from .models import IntelligenceObservation, IntelligenceRelation

    rows = list(
        IntelligenceObservation.objects.filter(
            id__in=set(observation_ids), organization=run.organization
        ).order_by("retrieved_at", "id")
    )
    for index, left in enumerate(rows):
        left_iocs = {
            str(item.get("value", "")).casefold()
            for item in (left.iocs or [])
            if item.get("value")
        }
        if not left_iocs:
            continue
        for right in rows[index + 1:]:
            right_iocs = {
                str(item.get("value", "")).casefold()
                for item in (right.iocs or [])
                if item.get("value")
            }
            shared = left_iocs & right_iocs
            # Language similarity alone is not sufficient evidence of a relation.
            if not shared:
                continue
            weight = min(1.0, 0.5 + 0.1 * min(len(shared), 5))
            IntelligenceRelation.objects.get_or_create(
                organization=run.organization,
                left=left,
                right=right,
                relation_type="shared_ioc",
                defaults={
                    "weight": weight,
                    "evidence": {
                        "shared_iocs": sorted(shared)[:20],
                        "cross_language": bool(left.language and right.language and left.language != right.language),
                    },
                },
            )
