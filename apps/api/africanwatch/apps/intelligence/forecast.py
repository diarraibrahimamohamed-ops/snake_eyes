from __future__ import annotations
from collections import Counter
from datetime import timedelta
from django.utils import timezone
from .models import IntelligenceObservation, ThreatForecast

def compute_forecasts(organization_id: str, horizon_hours: int = 168) -> list[ThreatForecast]:
    since = timezone.now() - timedelta(days=30)
    qs = IntelligenceObservation.objects.filter(organization_id=organization_id, retrieved_at__gte=since).only("classification", "relevance", "confidence", "retrieved_at", "evidence_grade")
    counts = Counter(); weighted = Counter(); corroboration = Counter(); unique_iocs = set()
    recent_72h = timezone.now() - timedelta(hours=72)
    recent_count = 0
    for row in qs:
        if row.retrieved_at >= recent_72h:
            recent_count += 1
        for item in row.classification.get("categories", []):
            name = item.get("name")
            if name:
                counts[name] += int(item.get("hits", 0) or 0)
                weighted[name] += float(row.relevance or 0) * float(row.confidence or 0)
        for ioc in (row.iocs or [])[:20]:
            corroboration[ioc.get("type", "ioc")] += 1
            if ioc.get("value"):
                unique_iocs.add(str(ioc["value"]).lower())
    total_observations = qs.count()
    prior_count = max(1, total_observations - recent_count)
    velocity_ratio = min(3.0, recent_count / prior_count)
    try:
        from africanwatch.apps.vulns.models import Vulnerability
        vulns=Vulnerability.objects.filter(asset__organization_id=organization_id,status="open")
        exposure=(4*vulns.filter(severity="critical").count()+2*vulns.filter(severity="high").count()+vulns.filter(exploit_available=True).count())
        if exposure:
            weighted["exposure_risk"] += min(12.0, float(exposure))
            counts["exposure_risk"] += min(12, int(exposure))
    except Exception:
        pass
    created = []
    for signal, value in weighted.most_common(8):
        raw = counts[signal]
        score = min(1.0, 0.55 * min(value / 10.0, 1.0) + 0.30 * min(raw / 10.0, 1.0) + 0.10 * min(velocity_ratio / 2.0, 1.0) + 0.05 * min(len(unique_iocs) / 20.0, 1.0))
        level = "critical" if score >= .85 else "high" if score >= .65 else "medium" if score >= .40 else "low"
        confidence = min(0.95, 0.35 + min(raw / 20.0, .35) + min(value / 20.0, .25))
        statement = f"Signal de tendance: {signal}. La plateforme observe une augmentation/corrélation suffisante pour renforcer la surveillance sur un horizon de {horizon_hours} h. Ce résultat n'est pas une prédiction certaine d'attaque."
        created.append(ThreatForecast.objects.create(organization_id=organization_id, horizon_hours=horizon_hours, signal_type=signal, level=level, score=round(score, 4), confidence=round(confidence, 4), basis={"window_days":30,"observations":total_observations,"raw_hits":raw,"weighted_signal":round(value,4),"corroboration_ioc_types":corroboration.most_common(10),"recent_72h":recent_count,"velocity_ratio":round(velocity_ratio,3),"unique_iocs":len(unique_iocs)}, statement=statement))
    return created
