from __future__ import annotations
import re
import unicodedata
from collections import Counter
from datetime import timedelta
from django.utils import timezone

LANG_TERMS = {
    "fr": {"cyberattaque", "ransomware", "piratage", "fuite", "désinformation", "appel à la violence", "mobilisation", "faux"},
    "en": {"cyberattack", "ransomware", "breach", "leak", "disinformation", "incitement", "mobilization", "fake"},
    "ar": {"اختراق", "تسريب", "هجوم", "تضليل", "تحريض", "دعوة للعنف"},
    "ha": {"hare-haren", "barazana", "satar bayanai", "rikici", "tashin hankali", "tatsuniya", "labarin karya", "barazanar yanar gizo"},
    "ff": {"nguurndam", "bonnugol", "haala", "fittinaare", "fitina", "yantugol"},
    "bm": {"sisan", "kelen", "jɛngɛ", "wulikili", "fili", "kumaw", "kiri", "jaatigi"},
}
CATEGORIES = {
    "cyber_threat": {"fr": {"cyberattaque", "ransomware", "piratage", "malware", "phishing", "exploitation", "intrusion", "ddos"}, "en": {"cyberattack", "ransomware", "malware", "phishing", "exploit", "intrusion", "ddos"}},
    "harmful_influence_signal": {"fr": {"désinformation", "fausse information", "rumeur", "appel à la violence", "incitation", "mobilisation", "provocation", "déchaîner", "coup d'état"}, "en": {"disinformation", "misinformation", "rumor", "incitement", "violent mobilization", "provocation", "coup"}},
    "data_leak": {"fr": {"fuite de données", "base de données exposée", "identifiants divulgués"}, "en": {"data leak", "database exposed", "credentials leaked"}},
    "fraud": {"fr": {"arnaque", "escroquerie", "faux site", "phishing"}, "en": {"scam", "fraud", "fake site", "phishing"}},
}
IOC_RE = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    "url": re.compile(r"https?://[^\s<>\"']+", re.I),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.I),
    "phone_public": re.compile(r"(?<!\w)(?:\+?223[ -]?(?:[0-9][ -]?){7,8}|\+?33[ -]?(?:[0-9][ -]?){9,10}|\+?234[ -]?(?:[0-9][ -]?){10})(?!\w)"),
}

def detect_language(text: str) -> str:
    try:
        from langdetect import detect
        return detect(text or "") or "unknown"
    except Exception:
        return "unknown"

def normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text or "").lower()

def extract_iocs(text: str) -> list[dict]:
    result = []
    seen = set()
    for kind, rx in IOC_RE.items():
        for value in rx.findall(text or ""):
            key = (kind, value.lower())
            if key not in seen:
                seen.add(key)
                result.append({"type": kind, "value": value[:500]})
    return result[:100]

def classify_text(text: str, language: str | None = None) -> dict:
    normalized = normalize(text)
    lang = language or detect_language(text)
    scores = Counter()
    matches = []
    for category, langs in CATEGORIES.items():
        terms = set().union(*langs.values())
        for term in terms:
            if normalize(term) in normalized:
                scores[category] += 1
                matches.append(term)
    max_score = min(1.0, sum(scores.values()) / 8.0)
    return {
        "language": lang,
        "categories": [{"name": k, "hits": v} for k, v in scores.most_common()],
        "matched_terms": sorted(set(matches))[:50],
        "harmful_influence_signal": float(min(1.0, scores.get("harmful_influence_signal", 0) / 4.0)),
        "cyber_signal": float(min(1.0, scores.get("cyber_threat", 0) / 4.0)),
        "relevance": max_score,
        "classifier": "multilingual-lexicon-v1",
        "limitations": "Signal de triage; ne constitue pas une attribution ni une conclusion sur une intention politique.",
    }

def reliability_grade(source_reliability: float, corroboration_count: int, published_at=None) -> tuple[str, float]:
    freshness = 0.5
    if published_at:
        age_h = max(0.0, (timezone.now() - published_at).total_seconds() / 3600)
        freshness = max(0.0, 1.0 - min(age_h / (24 * 14), 1.0))
    score = min(1.0, 0.45 * source_reliability + 0.35 * min(corroboration_count / 3.0, 1.0) + 0.20 * freshness)
    grade = "A" if score >= 0.85 else "B" if score >= 0.70 else "C" if score >= 0.50 else "D" if score >= 0.30 else "F"
    return grade, score
