"""AfricaWatch — AI Engine Views"""
import logging
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

logger = logging.getLogger("africanwatch.ai")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def analyze_text(request):
    """Analyse un texte libre — extrait IOCs, entités, score de menace."""
    text = request.data.get("text","").strip()
    if not text:
        return Response({"error": "Paramètre 'text' requis"}, status=400)
    if len(text) > 50000:
        return Response({"error": "Texte trop long (max 50 000 caractères)"}, status=400)

    iocs = _extract_iocs(text)
    entities = _extract_entities(text)
    score = _score_threat(text)
    lang = _detect_language(text)

    return Response({
        "iocs_found": iocs,
        "entities": entities,
        "threat_relevance_score": score,
        "is_threat_relevant": score >= 0.3,
        "language": lang,
        "ioc_count": len(iocs),
        "analysis_truncated": len(text) > 10000,
    })


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def summarize_incident(request):
    """Génère un résumé exécutif d'un incident via LLM."""
    incident_id = request.data.get("incident_id")
    if not incident_id:
        return Response({"error": "incident_id requis"}, status=400)
    try:
        from africanwatch.apps.soc.models import Incident
        incident = Incident.objects.get(id=incident_id)
        if incident.organization and request.user.organization:
            if str(incident.organization.id) != str(request.user.organization.id):
                if not request.user.is_superuser:
                    return Response({"error": "Accès non autorisé"}, status=403)
    except Exception:
        return Response({"error": "Incident introuvable"}, status=404)

    summary = _generate_summary(incident)
    return Response({"summary": summary, "incident_id": str(incident_id)})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def threat_prediction(request):
    """Prédit les menaces probables pour les prochaines 24h."""
    from africanwatch.apps.threat_intel.models import IOC
    from django.db.models import Count
    from django.utils import timezone
    from datetime import timedelta

    last_7d = timezone.now() - timedelta(days=7)
    trending = list(
        IOC.objects.filter(created_at__gte=last_7d, is_active=True)
        .exclude(malware_families=[])
        .values("malware_families")
        .annotate(count=Count("id"))
        .order_by("-count")[:5]
    )
    african_iocs = IOC.objects.filter(is_african_threat=True, is_active=True,
                                       created_at__gte=last_7d).count()
    score = min(100, african_iocs * 2)
    level = "critical" if score >= 75 else "elevated" if score >= 40 else "stable"

    return Response({
        "trending_threats": trending,
        "african_iocs_7d": african_iocs,
        "predicted_risk_level": level,
        "predicted_score": score,
        "method": "heuristic_indicator",
        "note": "Indicateur heuristique basé sur les IOC récents; ce n'est pas un modèle prédictif validé.",
        "recommendations": _get_recommendations(level),
        "computed_at": timezone.now().isoformat(),
    })


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def extract_iocs_from_text(request):
    """Extrait des IOCs d'un rapport ou article."""
    text = request.data.get("text","").strip()
    if not text:
        return Response({"error": "Paramètre 'text' requis"}, status=400)

    iocs = _extract_iocs(text)
    saved = []
    if request.data.get("save_iocs", False) and iocs:
        from africanwatch.apps.threat_intel.models import IOC
        from africanwatch.apps.threat_intel.tasks import enrich_ioc
        from django.utils import timezone
        type_map = {"ip":IOC.IOCType.IP,"sha256":IOC.IOCType.SHA256,
                    "md5":IOC.IOCType.MD5,"url":IOC.IOCType.URL,"cve":IOC.IOCType.CVE}
        now = timezone.now()
        for ioc_data in iocs[:50]:
            t = type_map.get(ioc_data["type"])
            if t:
                ioc, created = IOC.objects.get_or_create(
                    ioc_type=t, value_normalized=ioc_data["value"].lower(),
                    defaults={"value":ioc_data["value"],"severity":"medium","confidence":50,
                              "first_seen":now,"last_seen":now,"tags":["ai-extracted"]}
                )
                if created:
                    enrich_ioc.delay(str(ioc.id))
                    saved.append(str(ioc.id))
    return Response({"iocs_found": iocs, "iocs_saved": len(saved), "saved_ids": saved})


# ── HELPERS ──────────────────────────────────────────────────────────────────

def _extract_iocs(text: str) -> list:
    import re
    iocs = []
    patterns = [
        (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'ip'),
        (r'\b[a-fA-F0-9]{64}\b', 'sha256'),
        (r'\b[a-fA-F0-9]{32}\b', 'md5'),
        (r'https?://[^\s<>"{}|\\^`\[\]]{5,}', 'url'),
        (r'\bCVE-\d{4}-\d{4,}\b', 'cve'),
    ]
    seen = set()
    for pattern, ioc_type in patterns:
        for match in re.findall(pattern, text)[:20]:
            key = f"{ioc_type}:{match.lower()}"
            if key not in seen:
                seen.add(key)
                iocs.append({"type": ioc_type, "value": match})
    return iocs


def _extract_entities(text: str) -> dict:
    try:
        import spacy
        nlp = spacy.load("fr_core_news_sm")
        doc = nlp(text[:3000])
        entities: dict = {"LOC": [], "ORG": [], "PER": [], "MISC": []}
        for ent in doc.ents:
            if ent.label_ in entities and ent.text not in entities[ent.label_]:
                entities[ent.label_].append(ent.text)
        return {k: v[:10] for k, v in entities.items()}
    except Exception:
        return {"LOC": [], "ORG": [], "PER": [], "MISC": []}


def _score_threat(text: str) -> float:
    cyber_kw = ["cyberattaque","ransomware","malware","phishing","intrusion","exploit",
                "vulnerability","backdoor","trojan","breach","data leak","apt","hack"]
    african_kw = ["afrique","africa","mali","sénégal","ghana","nigeria","kenya",
                  "mobile money","orange money","mtn","wave","m-pesa"]
    t = text.lower()
    cyber = sum(1 for kw in cyber_kw if kw in t)
    african = sum(1 for kw in african_kw if kw in t)
    return min(cyber * 0.12 + african * 0.18, 1.0)


def _detect_language(text: str) -> str:
    try:
        from langdetect import detect
        return detect(text[:500])
    except Exception:
        return "unknown"


def _generate_summary(incident) -> str:
    """Résumé local optionnel avec limites strictes et repli déterministe."""
    from django.conf import settings
    if getattr(settings, "AI_ENABLED", False):
        try:
            import httpx
            from africanwatch.security.ai_guard import build_summary_prompt
            prompt, guard_meta = build_summary_prompt(incident, settings.AI_MAX_INPUT_CHARS)
            payload = {
                "model": settings.AI_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_ctx": 2048,
                    "num_predict": settings.AI_MAX_OUTPUT_TOKENS,
                },
            }
            resp = httpx.post(
                f"{settings.OLLAMA_URL}/api/generate",
                json=payload,
                timeout=settings.AI_TIMEOUT_SECONDS,
                trust_env=False,
            )
            if resp.status_code == 200:
                result = resp.json().get("response", "").strip()
                if result and len(result) <= 6000:
                    return result
            logger.info("AI summary fallback; guard=%s", guard_meta)
        except Exception as e:
            logger.debug(f"LLM unavailable: {e}")

    return (
        f"Un incident de sécurité de niveau {incident.severity.upper()} a été détecté: "
        f"{incident.title}. "
        f"{incident.systems_affected} système(s) affecté(s). "
        f"Statut actuel: {incident.status}. "
        f"{'Des données ont été compromises.' if incident.data_compromised else 'Aucune donnée compromise à ce stade.'}"
    )

def _get_recommendations(level: str) -> list:
    base = ["Maintenir les mises à jour des systèmes", "Surveiller les logs d'accès"]
    if level == "elevated":
        return base + ["Renforcer surveillance emails et VPN",
                       "Vérifier les backups critiques",
                       "Alerter les équipes SOC"]
    if level == "critical":
        return base + ["Activer le plan de réponse aux incidents",
                       "Isoler les systèmes critiques si nécessaire",
                       "Notifier la direction et les parties prenantes",
                       "Contacter le CERT national"]
    return base
