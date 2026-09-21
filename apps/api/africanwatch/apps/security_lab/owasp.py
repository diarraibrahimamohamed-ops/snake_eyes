from __future__ import annotations
import json
from urllib.parse import urlparse
from africanwatch.security.outbound import safe_get, validate_scan_target

OWASP_2025 = {
    "A01": "Broken Access Control", "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures", "A04": "Cryptographic Failures",
    "A05": "Injection", "A06": "Insecure Design", "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures", "A09": "Security Logging & Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}
API_TOP10_2023 = {
    "API1": "Broken Object Level Authorization", "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization", "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization", "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery", "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management", "API10": "Unsafe Consumption of APIs",
}


def _finding(severity, framework, control_id, title, description, evidence, remediation, confidence=0.95):
    return {
        "severity": severity, "framework": framework, "control_id": control_id, "title": title,
        "description": description, "evidence": evidence, "remediation": remediation, "confidence": confidence,
    }


def web_review(target: str, allow_private: bool = False) -> dict:
    target = validate_scan_target(target, allow_private=allow_private)
    response = safe_get(target, timeout=10.0, max_bytes=250_000)
    headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
    findings = []
    required = {
        "strict-transport-security": ("medium", "HSTS"),
        "content-security-policy": ("medium", "Content-Security-Policy"),
        "x-content-type-options": ("low", "X-Content-Type-Options"),
        "referrer-policy": ("low", "Referrer-Policy"),
        "permissions-policy": ("low", "Permissions-Policy"),
    }
    missing = [name for name in required if name not in headers]
    for name in missing:
        sev, label = required[name]
        findings.append(_finding(sev, "OWASP-2025", "A02", f"{label} absent", "Le contrôle HTTP n'est pas observé sur la réponse.", {"header": name}, f"Définir {label} au niveau du reverse proxy/application après validation de l'architecture."))
    if urlparse(target).scheme == "http":
        findings.append(_finding("medium", "OWASP-2025", "A04", "Service observé en HTTP", "La cible a été fournie en HTTP non chiffré.", {"target": target}, "Utiliser HTTPS et rediriger HTTP vers HTTPS."))
    if headers.get("access-control-allow-origin") == "*" and headers.get("access-control-allow-credentials", "").lower() == "true":
        findings.append(_finding("high", "OWASP-2025", "A01", "CORS wildcard avec credentials", "La réponse combine une origine wildcard et l'autorisation des credentials.", {}, "Restreindre Access-Control-Allow-Origin à une liste d'origines explicites."))
    server = headers.get("server")
    if server:
        findings.append(_finding("info", "OWASP-2025", "A02", "Bannière Server exposée", "Le serveur divulgue une bannière HTTP.", {"server": server}, "Réduire les informations de bannière exposées."))
    powered = headers.get("x-powered-by")
    if powered:
        findings.append(_finding("low", "OWASP-2025", "A02", "X-Powered-By exposé", "La réponse divulgue une technologie applicative.", {"x-powered-by": powered}, "Supprimer X-Powered-By si possible."))
    set_cookie = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []
    for raw in set_cookie[:20]:
        low = raw.lower()
        name = raw.split("=", 1)[0][:80]
        if any(x in name.lower() for x in ("session", "auth", "token", "jwt")) and ("secure" not in low or "httponly" not in low):
            findings.append(_finding("medium", "OWASP-2025", "A07", "Cookie d'authentification sans attributs de protection complets", "Un cookie possiblement sensible manque Secure ou HttpOnly.", {"cookie_name": name, "secure": "secure" in low, "httponly": "httponly" in low}, "Activer Secure et HttpOnly et définir une politique SameSite adaptée."))
    body = getattr(response, "text", "")[:200_000]
    if "<!doctype" in body.lower() and "<!--" in body:
        findings.append(_finding("info", "OWASP-WSTG", "WSTG-INFO-05", "Commentaires HTML observés", "Des commentaires HTML publics peuvent contenir des informations internes ; une revue manuelle est nécessaire.", {}, "Revoir les commentaires et métadonnées exposés en production.", 0.8))
    return {"target": target, "status_code": response.status_code, "headers": headers, "findings": findings, "framework": OWASP_2025}


def api_review(spec_text: str) -> dict:
    try:
        spec = json.loads(spec_text)
    except json.JSONDecodeError as exc:
        return {"valid": False, "error": f"OpenAPI JSON invalide: {exc}", "findings": []}
    findings = []
    servers = spec.get("servers") or []
    insecure_servers = [s.get("url") for s in servers if isinstance(s, dict) and str(s.get("url", "")).startswith("http://")]
    if insecure_servers:
        findings.append(_finding("medium", "OWASP-API-2023", "API8", "Serveur API déclaré en HTTP", "Le document OpenAPI contient au moins une URL de serveur non chiffrée.", {"servers": insecure_servers[:10]}, "Utiliser HTTPS pour les serveurs d'API."))
    components = spec.get("components") or {}
    security_schemes = (components.get("securitySchemes") or {})
    operations = []
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if str(method).lower() in {"get", "post", "put", "patch", "delete", "head", "options", "trace"} and isinstance(op, dict):
                operations.append((path, method.lower(), op))
    unsecured = [(p, m) for p, m, op in operations if not op.get("security") and not spec.get("security")]
    if unsecured:
        findings.append(_finding("medium", "OWASP-API-2023", "API2", "Opérations sans exigence de sécurité déclarée", "Des opérations OpenAPI ne déclarent aucune exigence de sécurité.", {"count": len(unsecured), "sample": unsecured[:20]}, "Vérifier les endpoints publics attendus et déclarer explicitement les mécanismes d'authentification."))
    if not security_schemes:
        findings.append(_finding("high", "OWASP-API-2023", "API2", "Aucun securityScheme OpenAPI", "Le document ne décrit aucun mécanisme d'authentification.", {}, "Décrire le schéma d'authentification de l'API et vérifier son application réelle."))
    inventory = len(operations)
    if inventory == 0:
        findings.append(_finding("low", "OWASP-API-2023", "API9", "Inventaire d'API vide ou incomplet", "Aucune opération n'a été trouvée dans le document.", {}, "Maintenir un inventaire versionné et exhaustif des API."))
    return {"valid": True, "title": spec.get("info", {}).get("title", "OpenAPI"), "version": spec.get("info", {}).get("version", ""), "operations": inventory, "security_schemes": list(security_schemes), "findings": findings, "framework": API_TOP10_2023}
