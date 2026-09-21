"""Threat-informed analysis helpers for the Offensive Lab.

This module models how an adversary would reason about an exposed surface without
performing exploitation. It produces attack-path hypotheses, telemetry expectations,
and safe next steps from observations already collected by the lab.
"""
from __future__ import annotations

from typing import Any


SEVERITY_WEIGHT = {"info": 0.2, "low": 1.0, "medium": 2.5, "high": 4.0, "critical": 6.0}


def _severity_score(findings: list[dict]) -> float:
    raw = sum(SEVERITY_WEIGHT.get(str(f.get("severity", "info")).lower(), 0.2) for f in findings)
    return round(min(100.0, raw * 7.5), 2)


def build_attack_surface(result: dict[str, Any], *, asset_criticality: str = "medium") -> dict[str, Any]:
    """Turn recon observations into a non-exploitative attack-path hypothesis."""
    findings = list(result.get("findings") or [])
    services = list((result.get("ports") or {}).get("services") or [])
    web = result.get("web") or {}
    dns = result.get("dns") or {}
    nodes: list[AttackNode] = []

    if services:
        nodes.append({
            "stage": "discovery", "title": "Services exposés", "rationale": "Une surface réseau identifiable donne à un adversaire des points d'entrée à examiner.",
            "evidence": {"services": [{"port": s.get("port"), "service": s.get("service"), "product": s.get("product")} for s in services[:50]]}, "confidence": 0.96,
        })

    sensitive = [s for s in services if s.get("port") in {21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 5432, 5900, 6379, 9200}]
    if sensitive:
        nodes.append({
            "stage": "exposure", "title": "Services à examiner prioritairement", "rationale": "Certains services ont une surface d'administration, de données ou de protocole suffisamment importante pour justifier une validation ciblée.",
            "evidence": {"ports": [s.get("port") for s in sensitive]}, "confidence": 0.93,
        })

    web_findings = [f for f in findings if str(f.get("category", "")).startswith(("web-", "http-", "information-disclosure", "cors", "cookie"))]
    if web_findings or web:
        nodes.append({
            "stage": "web", "title": "Surface applicative", "rationale": "La pile HTTP expose des métadonnées et des contrôles de sécurité pouvant être analysés sans exploitation.",
            "evidence": {"status": web.get("status_code"), "title": web.get("title"), "finding_count": len(web_findings)}, "confidence": 0.95,
        })

    dns_findings = [f for f in findings if str(f.get("category", "")).startswith("dns-")]
    if dns_findings or dns:
        nodes.append({
            "stage": "recon", "title": "Posture DNS", "rationale": "Les DNS, certificats et politiques de messagerie peuvent fournir des informations de surface et de confiance.",
            "evidence": {"record_types": sorted(k for k in dns if k.startswith("dns_"))}, "confidence": 0.92,
        })

    barriers = [
        "TLS moderne et certificats valides réduisent certaines possibilités de downgrade ou d'interception.",
        "CSP, HSTS, cookies correctement protégés et CORS strict réduisent plusieurs classes d'abus web.",
        "Réduction de l'exposition réseau et filtrage des services sensibles diminuent la surface observable.",
    ]

    criticality_bonus = {"low": 0, "medium": 5, "high": 10, "critical": 15}.get(asset_criticality, 5)
    score = round(min(100.0, _severity_score(findings) + criticality_bonus), 2)

    return {
        "model": "threat-informed-non-exploitative-v1",
        "risk_signal": score,
        "asset_criticality": asset_criticality,
        "nodes": nodes,
        "barriers": barriers,
        "likely_next_actions_for_an_attacker": [
            "Énumérer et comparer les services déjà observés.",
            "Rechercher des erreurs de configuration sur la surface HTTP/TLS.",
            "Corréler les résultats avec l'inventaire d'actifs, les CVE et les journaux SOC.",
        ],
        "safe_validation_next_steps": [
            "Confirmer les findings avec un second échantillon autorisé.",
            "Comparer l'exposition avec le job précédent du même actif.",
            "Associer chaque finding à une preuve, un propriétaire et une remédiation.",
        ],
    }


def detection_expectations(result: dict[str, Any]) -> dict[str, Any]:
    """Describe likely defender telemetry; never attempts to evade it."""
    request_count = 0
    if result.get("web"):
        request_count += 1
    if result.get("web_posture"):
        request_count += 5
    if result.get("dns"):
        request_count += 5
    if result.get("dns_posture"):
        request_count += 6
    if result.get("ports"):
        request_count += max(1, len((result.get("ports") or {}).get("services") or []))
    noise = "low" if request_count <= 8 else "moderate" if request_count <= 30 else "high"
    return {
        "estimated_network_actions": request_count,
        "noise_level": noise,
        "telemetry_to_expect": [
            "journaux DNS et résolveur",
            "access/error logs HTTP et reverse-proxy",
            "logs TLS et éventuels WAF/IDS",
            "logs de pare-feu et connexions aux ports observés",
            "événements EDR/SIEM si l'actif est instrumenté",
        ],
        "defender_validation": [
            "Vérifier la présence des événements dans le SIEM.",
            "Mesurer le délai entre activité et alerte.",
            "Vérifier que l'organisation, l'actif et la règle de détection sont corrélés.",
        ],
    }


def build_adversary_plan(*, profiles: list[str], scope_size: int, lab_mode: bool) -> dict[str, Any]:
    """Create a red-team-style assessment sequence without exploit instructions."""
    ordered = [
        ("phase_1", "Reconnaissance faible bruit", ["dns_recon", "dns_posture", "web_recon", "web_posture", "tls_audit"]),
        ("phase_2", "Cartographie de surface", ["port_recon", "adversary_recon"]),
        ("phase_3", "Validation contrôlée", ["nuclei_safe", "exposure_audit"]),
        ("phase_4", "Corrélation", ["exposure_chain"]),
    ]
    phases = []
    for phase_id, name, candidates in ordered:
        enabled = [p for p in candidates if p in profiles]
        phases.append({"id": phase_id, "name": name, "profiles": enabled, "enabled": bool(enabled)})
    return {
        "model": "adversary-planner-non-exploitative-v1",
        "scope_size": scope_size,
        "lab_mode": lab_mode,
        "phases": phases,
        "rules": {
            "no_exploitation": True,
            "no_credentials": True,
            "no_persistence": True,
            "no_evasion": True,
            "registered_assets_only": True,
        },
        "analyst_questions": [
            "Quel point d'entrée observable est le plus exposé ?",
            "Quelle faiblesse peut être confirmée sans exploitation ?",
            "Quelles preuves manquent avant de conclure ?",
            "Quelle détection devrait se déclencher et laquelle ne se déclenche pas ?",
        ],
    }
