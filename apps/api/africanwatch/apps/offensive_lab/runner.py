"""Threat-informed, safe-by-default active assessment runners.

The lab is intentionally limited to reconnaissance and configuration validation on
registered, authorized assets. It does not implement exploitation, credential
attacks, payload delivery, persistence, evasion, or arbitrary command execution.
"""
from __future__ import annotations

import json
import re
import socket
import ssl
import subprocess
from datetime import datetime, timezone as dt_timezone
from urllib.parse import urljoin, urlparse

from africanwatch.security.outbound import safe_get, validate_scan_target
from .adversary import build_attack_surface, detection_expectations

MAX_OUTPUT = 80_000
MAX_BODY_INSPECTION = 250_000
MAX_FINDINGS = 100
MAX_FIXED_PATHS = 3
SAFE_NUCLEI_EXCLUDE = "dos,fuzz,intrusive,bruteforce,exploit,rce,sqli,ssrf,lfi,rfi,xxe,deserialization,headless,network"
SAFE_NUCLEI_TAGS = "misconfig,exposure,ssl,tech"
SECRET_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt-like", re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")),
    ("cloud-access-key-shape", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("token-assignment", re.compile(r"\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*[\"'][^\"']{12,}[\"']", re.I)),
]


def _clip(value: str, size: int = MAX_OUTPUT) -> str:
    return (value or "")[:size]


def _host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    return parsed.hostname or target


def _origin(target: str, scheme: str | None = None) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    chosen = scheme or parsed.scheme or "https"
    netloc = parsed.netloc or parsed.path.split("/", 1)[0]
    return f"{chosen}://{netloc}"


def _fixed_url(target: str, path: str) -> str:
    return urljoin(_origin(target).rstrip("/") + "/", path.lstrip("/"))


def _port(target: str, default: int = 443) -> int:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    return parsed.port or default


def _findings_for_web(data: dict) -> list[dict]:
    findings: list[dict] = []
    missing = data.get("missing_security_headers", [])
    if missing:
        findings.append({
            "severity": "low" if len(missing) <= 2 else "medium",
            "category": "web-hardening",
            "title": "En-têtes de sécurité HTTP manquants",
            "description": "Plusieurs en-têtes de sécurité usuels ne sont pas présents sur la réponse observée.",
            "evidence": {"missing": missing},
            "remediation": "Définir HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy et Permissions-Policy selon l'architecture.",
            "confidence": 0.98,
        })
    if data.get("server"):
        findings.append({
            "severity": "info",
            "category": "information-disclosure",
            "title": "En-tête Server exposé",
            "description": "Le serveur HTTP divulgue une bannière via l'en-tête Server.",
            "evidence": {"server": data["server"]},
            "remediation": "Réduire les bannières et versions exposées lorsque cela est compatible avec le support.",
            "confidence": 0.99,
        })
    if data.get("x_powered_by"):
        findings.append({
            "severity": "low",
            "category": "information-disclosure",
            "title": "Technologie applicative exposée par X-Powered-By",
            "description": "Une technologie ou version applicative est divulguée par un en-tête dédié.",
            "evidence": {"x_powered_by": data["x_powered_by"]},
            "remediation": "Supprimer ou minimiser X-Powered-By sur les réponses publiques.",
            "confidence": 0.99,
        })
    return findings[:MAX_FINDINGS]


def _findings_for_tls(data: dict) -> list[dict]:
    findings: list[dict] = []
    tls = data.get("tls") or {}
    not_after = tls.get("not_after")
    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt_timezone.utc)
            days = (expires - datetime.now(dt_timezone.utc)).days
            if days < 0:
                findings.append({"severity": "high", "category": "tls", "title": "Certificat TLS expiré", "description": "Le certificat présenté est expiré.", "evidence": {"not_after": not_after}, "remediation": "Renouveler et déployer un certificat valide.", "confidence": 1.0})
            elif days <= 30:
                findings.append({"severity": "medium", "category": "tls", "title": "Certificat TLS bientôt expiré", "description": f"Le certificat observé expire dans environ {days} jours.", "evidence": {"not_after": not_after, "days_remaining": days}, "remediation": "Préparer le renouvellement avant la fenêtre d'expiration.", "confidence": 0.98})
        except ValueError:
            pass
    if tls.get("protocol") in {"TLSv1", "TLSv1.1"}:
        findings.append({"severity": "high", "category": "tls", "title": "Protocole TLS ancien observé", "description": "Le service a négocié un protocole TLS ancien.", "evidence": {"protocol": tls.get("protocol")}, "remediation": "Désactiver TLS 1.0/1.1 et conserver TLS 1.2/1.3 selon les besoins.", "confidence": 0.99})
    return findings[:MAX_FINDINGS]


def _parse_cookie_flags(set_cookie_headers: list[str]) -> list[dict]:
    cookies = []
    for raw in set_cookie_headers[:20]:
        first = raw.split(";", 1)[0].strip()
        name = first.split("=", 1)[0].strip() if "=" in first else first[:80]
        lower = raw.lower()
        cookies.append({
            "name": name[:100],
            "secure": "secure" in {part.strip().lower() for part in raw.split(";")[1:]},
            "httponly": "httponly" in {part.strip().lower() for part in raw.split(";")[1:]},
            "samesite": next((part.split("=", 1)[1].strip() for part in raw.split(";")[1:] if part.strip().lower().startswith("samesite=")), ""),
            "path": next((part.split("=", 1)[1].strip() for part in raw.split(";")[1:] if part.strip().lower().startswith("path=")), ""),
            "looks_auth": any(token in name.lower() for token in ("session", "auth", "token", "jwt")),
        })
        cookies[-1]["suspicious_flags"] = bool(cookies[-1]["looks_auth"] and (not cookies[-1]["httponly"] or not cookies[-1]["secure"]))
        del lower
    return cookies


def _scan_for_secret_shapes(body: str) -> list[dict]:
    findings = []
    sample = body[:MAX_BODY_INSPECTION]
    for label, pattern in SECRET_PATTERNS:
        match = pattern.search(sample)
        if not match:
            continue
        # Never persist the matched secret. Store only a class, location and a length bucket.
        findings.append({
            "severity": "medium",
            "category": "possible-secret-disclosure",
            "title": f"Motif de secret potentiellement exposé ({label})",
            "description": "Un motif ressemblant à un secret a été observé dans la réponse ; la valeur n'est jamais stockée par le scanner.",
            "evidence": {"pattern": label, "offset": match.start(), "length_bucket": min(999, len(match.group(0))) // 10 * 10},
            "remediation": "Supprimer le secret du contenu public, effectuer une rotation et vérifier les journaux/cache si la valeur était réelle.",
            "confidence": 0.78,
        })
    return findings


def dns_recon(target: str, allow_private: bool = False) -> dict:
    target = validate_scan_target(target, allow_private=allow_private)
    host = _host(target)
    records: dict[str, list[str]] = {}
    for family, name in [(socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")]:
        try:
            records[name] = sorted({x[4][0] for x in socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)})
        except socket.gaierror:
            records[name] = []
    result = {"target": target, "host": host, "records": records}
    try:
        import dns.resolver
        for rtype in ("MX", "NS", "TXT", "CNAME"):
            try:
                result["dns_" + rtype.lower()] = [r.to_text().strip('"') for r in dns.resolver.resolve(host, rtype, lifetime=4)]
            except Exception:
                result["dns_" + rtype.lower()] = []
    except Exception:
        pass
    return result


def dns_posture(target: str, allow_private: bool = False) -> dict:
    base = dns_recon(target, allow_private=allow_private)
    host = base["host"]
    findings = []
    try:
        import dns.resolver
        txt = base.get("dns_txt", [])
        spf = any(str(item).lower().startswith("v=spf1") for item in txt)
        if not spf:
            findings.append({"severity": "low", "category": "dns-spf", "title": "SPF non observé", "description": "Aucun enregistrement TXT SPF n'a été observé sur le domaine testé.", "evidence": {"host": host}, "remediation": "Évaluer si la politique SPF est nécessaire au domaine et définir une politique cohérente.", "confidence": 0.88})
        dmarc_name = f"_dmarc.{host}"
        try:
            dmarc_records = [r.to_text().strip('"') for r in dns.resolver.resolve(dmarc_name, "TXT", lifetime=4)]
        except Exception:
            dmarc_records = []
        base["dmarc_records"] = dmarc_records
        if not any("v=dmarc1" in str(item).lower() for item in dmarc_records):
            findings.append({"severity": "medium", "category": "dns-dmarc", "title": "DMARC non observé", "description": "Aucun enregistrement DMARC n'a été observé sur le domaine testé.", "evidence": {"record": dmarc_name}, "remediation": "Évaluer une politique DMARC adaptée aux flux de messagerie du domaine.", "confidence": 0.9})
        try:
            caa = [r.to_text() for r in dns.resolver.resolve(host, "CAA", lifetime=4)]
        except Exception:
            caa = []
        base["dns_caa"] = caa
    except Exception:
        pass
    base["findings"] = findings[:MAX_FINDINGS]
    return base


def web_recon(target: str, allow_private: bool = False) -> dict:
    target = validate_scan_target(target, allow_private=allow_private)
    url = target if "://" in target else f"https://{target}"
    response = safe_get(url, timeout=10)
    security_headers = {
        k.lower(): response.headers.get(k) for k in (
            "strict-transport-security", "content-security-policy", "x-frame-options",
            "x-content-type-options", "referrer-policy", "permissions-policy",
        )
    }
    tls = tls_audit(target, allow_private=allow_private).get("tls", {}) if urlparse(str(response.url)).scheme == "https" else {}
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.text[:200_000], "html.parser")
        title = (soup.title.string or "").strip() if soup.title else ""
        generators = [m.get("content", "") for m in soup.find_all("meta", attrs={"name": re.compile("generator", re.I)})]
    except Exception:
        title, generators = "", []
    result = {
        "url": str(response.url),
        "status_code": response.status_code,
        "server": response.headers.get("server", ""),
        "x_powered_by": response.headers.get("x-powered-by", ""),
        "content_type": response.headers.get("content-type", ""),
        "content_length": len(response.content),
        "security_headers": {k: v for k, v in security_headers.items() if v},
        "missing_security_headers": [k for k, v in security_headers.items() if not v],
        "http_methods_advertised": response.headers.get("allow", ""),
        "title": title,
        "technology_hints": generators[:10],
        "tls": tls,
    }
    result["findings"] = _findings_for_web(result) + _findings_for_tls(result) + _scan_for_secret_shapes(response.text)
    return result


def web_posture(target: str, allow_private: bool = False) -> dict:
    """Perform bounded, fixed-path web security validation; no wordlist enumeration."""
    target = validate_scan_target(target, allow_private=allow_private)
    base_url = _origin(target)
    root = target if "://" in target else f"https://{target}"
    root_response = safe_get(root, timeout=10, headers={"Origin": "https://africanwatch-audit.invalid"})
    allow = root_response.headers.get("allow", "")
    cookies = _parse_cookie_flags(root_response.headers.get_list("set-cookie")) if hasattr(root_response.headers, "get_list") else _parse_cookie_flags([root_response.headers.get("set-cookie", "")] if root_response.headers.get("set-cookie") else [])
    cors_origin = root_response.headers.get("access-control-allow-origin", "")
    cors_credentials = root_response.headers.get("access-control-allow-credentials", "")
    exposed = root_response.headers.get("access-control-expose-headers", "")

    fixed_checks = {}
    for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
        try:
            response = safe_get(urljoin(base_url.rstrip("/") + "/", path.lstrip("/")), timeout=6)
            fixed_checks[path] = {"status_code": response.status_code, "content_type": response.headers.get("content-type", ""), "length": len(response.content)}
        except Exception as exc:
            fixed_checks[path] = {"error": str(exc)[:200]}

    findings = []
    if cors_origin == "*" and cors_credentials.lower() == "true":
        findings.append({"severity": "medium", "category": "cors", "title": "Politique CORS incohérente avec credentials", "description": "La réponse combine ACAO=* et Access-Control-Allow-Credentials=true.", "evidence": {"allow_origin": cors_origin, "allow_credentials": cors_credentials}, "remediation": "Restreindre les origines autorisées et valider la politique CORS côté serveur.", "confidence": 0.92})
    if cors_origin == "https://africanwatch-audit.invalid":
        findings.append({"severity": "medium", "category": "cors", "title": "Origine CORS de test reflétée", "description": "Le serveur reflète une origine de test fournie par le scanner.", "evidence": {"reflected_origin": cors_origin}, "remediation": "Utiliser une allowlist d'origines plutôt qu'une réflexion d'origine arbitraire.", "confidence": 0.96})
    methods = {x.strip().upper() for x in allow.split(",") if x.strip()}
    risky_advertised = sorted(methods & {"TRACE", "CONNECT"})
    if risky_advertised:
        findings.append({"severity": "medium", "category": "http-methods", "title": "Méthodes HTTP sensibles annoncées", "description": "Des méthodes rarement nécessaires sont annoncées par la surface HTTP.", "evidence": {"methods": risky_advertised}, "remediation": "Désactiver les méthodes non nécessaires et appliquer une allowlist côté reverse-proxy/application.", "confidence": 0.9})
    for cookie in cookies:
        if cookie["suspicious_flags"]:
            findings.append({"severity": "medium", "category": "cookie", "title": f"Cookie d'authentification insuffisamment protégé: {cookie['name']}", "description": "Un cookie qui ressemble à un cookie de session présente des attributs de sécurité manquants.", "evidence": {k: cookie[k] for k in ("name", "secure", "httponly", "samesite", "looks_auth")}, "remediation": "Activer Secure, HttpOnly et une politique SameSite adaptée au rôle du cookie.", "confidence": 0.94})
    if not root_response.headers.get("strict-transport-security") and urlparse(str(root_response.url)).scheme == "https":
        findings.append({"severity": "low", "category": "web-transport", "title": "HSTS non observé", "description": "La réponse HTTPS ne présente pas d'en-tête Strict-Transport-Security.", "evidence": {"url": str(root_response.url)}, "remediation": "Évaluer puis déployer HSTS sur les domaines HTTPS adaptés.", "confidence": 0.97})
    if exposed:
        findings.append({"severity": "info", "category": "cors", "title": "En-têtes CORS exposés", "description": "La réponse publie une liste explicite d'en-têtes CORS exposés.", "evidence": {"expose_headers": exposed}, "remediation": "Vérifier que seuls les en-têtes nécessaires sont exposés aux scripts cross-origin.", "confidence": 0.95})

    return {
        "target": target,
        "root": {"url": str(root_response.url), "status_code": root_response.status_code},
        "cors": {"allow_origin": cors_origin, "allow_credentials": cors_credentials, "expose_headers": exposed},
        "allow_methods": sorted(methods),
        "cookies": cookies,
        "fixed_paths": fixed_checks,
        "safe_probe_policy": {"fixed_paths_only": True, "max_paths": MAX_FIXED_PATHS, "wordlist_enumeration": False},
        "findings": findings[:MAX_FINDINGS],
        "requests": 2 + len(fixed_checks),
    }


def tls_audit(target: str, allow_private: bool = False) -> dict:
    target = validate_scan_target(target, allow_private=allow_private)
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.hostname or target
    port = parsed.port or 443
    context = ssl.create_default_context()
    data = {"host": host, "port": port, "tls": {}}
    try:
        with socket.create_connection((host, port), timeout=6) as raw:
            with context.wrap_socket(raw, server_hostname=host) as conn:
                cert = conn.getpeercert()
                data["tls"] = {
                    "protocol": conn.version(),
                    "cipher": conn.cipher()[0] if conn.cipher() else None,
                    "subject": cert.get("subject", []),
                    "issuer": cert.get("issuer", []),
                    "not_after": cert.get("notAfter"),
                    "san_count": len(cert.get("subjectAltName", [])),
                }
    except Exception as exc:
        data["tls"] = {"error": "certificat TLS non récupérable", "detail": str(exc)[:300]}
    data["findings"] = _findings_for_tls(data)
    return data


def port_recon(target: str, allow_private: bool = False) -> dict:
    target = validate_scan_target(target, allow_private=allow_private)
    host = _host(target)
    cmd = [
        "nmap", "-sT", "-sV", "--version-light", "--open", "-T3", "--max-retries", "1",
        "--host-timeout", "90s", "--top-ports", "100", "-oX", "-", host,
    ]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False, shell=False)
    except FileNotFoundError:
        return {"target": target, "scanner": "nmap", "available": False, "reason": "nmap non installé", "findings": []}
    except subprocess.TimeoutExpired as exc:
        return {"target": target, "scanner": "nmap", "available": True, "timeout": True, "stderr": _clip(str(exc)), "findings": []}
    services = []
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(completed.stdout or "<nmaprun/>")
        for node in root.findall(".//port"):
            state = node.find("state")
            service = node.find("service")
            services.append({
                "port": int(node.attrib.get("portid", "0")),
                "protocol": node.attrib.get("protocol", "tcp"),
                "state": state.attrib.get("state") if state is not None else "unknown",
                "service": service.attrib.get("name", "") if service is not None else "",
                "product": service.attrib.get("product", "") if service is not None else "",
                "version": service.attrib.get("version", "") if service is not None else "",
            })
    except Exception:
        services = []
    findings = []
    high_exposure_ports = {21: "FTP", 23: "Telnet", 139: "NetBIOS", 445: "SMB", 2375: "Docker API", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch"}
    for service in services:
        port = service.get("port")
        if port in high_exposure_ports:
            severity = "high" if port in {2375, 6379, 9200, 5432} else "medium"
            findings.append({
                "severity": severity,
                "category": "network-exposure",
                "title": f"Service sensible exposé sur le port {port}",
                "description": f"Le service {high_exposure_ports[port]} est accessible depuis la surface testée.",
                "evidence": service,
                "remediation": "Restreindre l'exposition aux segments/bastions nécessaires et appliquer un filtrage explicite.",
                "confidence": 0.97,
            })
    return {"target": target, "scanner": "nmap", "available": True, "exit_code": completed.returncode, "services": services, "stdout": _clip(completed.stdout), "stderr": _clip(completed.stderr, 20_000), "findings": findings[:MAX_FINDINGS], "scan_policy": {"tcp_connect": True, "udp": False, "nse": False, "evasion": False, "top_ports": 100}}


def exposure_audit(target: str, allow_private: bool = False) -> dict:
    web = web_recon(target, allow_private=allow_private)
    ports = port_recon(target, allow_private=allow_private)
    dns = dns_posture(target, allow_private=allow_private)
    posture = web_posture(target, allow_private=allow_private)
    findings = (web.get("findings") or []) + (ports.get("findings") or []) + (dns.get("findings") or []) + (posture.get("findings") or [])
    attack_surface = build_attack_surface({"web": web, "ports": ports, "dns": dns, "findings": findings})
    return {"target": target, "web": web, "web_posture": posture, "dns": dns, "ports": ports, "attack_surface": attack_surface, "detection_expectations": detection_expectations({"web": web, "web_posture": posture, "dns": dns, "ports": ports}), "findings": findings[:MAX_FINDINGS]}


def adversary_recon(target: str, allow_private: bool = False) -> dict:
    """Maximum safe reconnaissance profile: broad enough for red-team thinking, non-exploitative."""
    dns = dns_posture(target, allow_private=allow_private)
    web = web_recon(target, allow_private=allow_private)
    posture = web_posture(target, allow_private=allow_private)
    tls = tls_audit(target, allow_private=allow_private)
    ports = port_recon(target, allow_private=allow_private)
    findings = (dns.get("findings") or []) + (web.get("findings") or []) + (posture.get("findings") or []) + (tls.get("findings") or []) + (ports.get("findings") or [])
    composite = {"dns": dns, "web": web, "web_posture": posture, "tls": tls, "ports": ports, "findings": findings}
    return {
        "target": target,
        "dns": dns,
        "web": web,
        "web_posture": posture,
        "tls": tls,
        "ports": ports,
        "attack_surface": build_attack_surface(composite),
        "detection_expectations": detection_expectations(composite),
        "findings": findings[:MAX_FINDINGS],
        "assessment_boundary": {
            "recon": True,
            "configuration_validation": True,
            "exploitation": False,
            "credential_attacks": False,
            "persistence": False,
            "lateral_movement": False,
            "evasion": False,
        },
    }


def exposure_chain(target: str, allow_private: bool = False) -> dict:
    base = adversary_recon(target, allow_private=allow_private)
    surface = base["attack_surface"]
    paths = []
    for node in surface.get("nodes", []):
        stage = node.get("stage")
        if stage == "exposure":
            paths.append({"from": "internet_observation", "to": "service_review", "reason": node.get("rationale"), "evidence": node.get("evidence")})
        elif stage == "web":
            paths.append({"from": "web_surface", "to": "configuration_review", "reason": node.get("rationale"), "evidence": node.get("evidence")})
        elif stage == "recon":
            paths.append({"from": "dns_metadata", "to": "trust_surface_review", "reason": node.get("rationale"), "evidence": node.get("evidence")})
    return {"target": target, "attack_surface": surface, "paths": paths[:50], "findings": base.get("findings", [])[:MAX_FINDINGS], "detection_expectations": base.get("detection_expectations", {})}


def nuclei_safe(target: str, allow_private: bool = False) -> dict:
    target = validate_scan_target(target, allow_private=allow_private)
    cmd = [
        "nuclei", "-u", target, "-jsonl", "-silent", "-no-color", "-rate-limit", "5", "-concurrency", "1",
        "-retries", "0", "-timeout", "5", "-severity", "info,low,medium", "-tags", SAFE_NUCLEI_TAGS,
        "-exclude-tags", SAFE_NUCLEI_EXCLUDE,
    ]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=150, check=False, shell=False)
    except FileNotFoundError:
        return {"target": target, "scanner": "nuclei", "available": False, "reason": "nuclei non installé", "findings": []}
    except subprocess.TimeoutExpired as exc:
        return {"target": target, "scanner": "nuclei", "available": True, "timeout": True, "stderr": _clip(str(exc)), "findings": []}
    findings = []
    for line in (completed.stdout or "").splitlines()[:MAX_FINDINGS]:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info") or {}
        severity = str(info.get("severity", "info")).lower()
        if severity not in {"info", "low", "medium"}:
            continue
        findings.append({
            "severity": severity,
            "category": "nuclei-exposure",
            "title": str(info.get("name") or item.get("template-id") or "Nuclei finding")[:255],
            "description": str(info.get("description") or "Détection non intrusive issue du jeu de contrôles autorisé.")[:3000],
            "evidence": {"matched_at": item.get("matched-at"), "template": item.get("template-id"), "type": item.get("type")},
            "remediation": str(info.get("remediation") or "Consulter la recommandation du contrôle et corriger le service concerné.")[:3000],
            "confidence": 0.85,
        })
    return {"target": target, "scanner": "nuclei", "available": True, "exit_code": completed.returncode, "findings": findings, "stdout": _clip(completed.stdout), "stderr": _clip(completed.stderr, 20_000), "policy": {"tags": SAFE_NUCLEI_TAGS, "excluded_tags": SAFE_NUCLEI_EXCLUDE, "max_severity": "medium", "templates_must_be_non_intrusive": True}}


def run_profile(profile: str, target: str, allow_private: bool = False) -> dict:
    profiles = {
        "dns_recon": lambda: dns_recon(target, allow_private),
        "dns_posture": lambda: dns_posture(target, allow_private),
        "web_recon": lambda: web_recon(target, allow_private),
        "web_posture": lambda: web_posture(target, allow_private),
        "port_recon": lambda: port_recon(target, allow_private),
        "tls_audit": lambda: tls_audit(target, allow_private),
        "exposure_audit": lambda: exposure_audit(target, allow_private),
        "adversary_recon": lambda: adversary_recon(target, allow_private),
        "exposure_chain": lambda: exposure_chain(target, allow_private),
        "nuclei_safe": lambda: nuclei_safe(target, allow_private),
        "combined_recon": lambda: adversary_recon(target, allow_private),
    }
    if profile not in profiles:
        raise ValueError("Profil d'évaluation inconnu")
    result = profiles[profile]()
    result["profile"] = profile
    result["safety_policy"] = {
        "arbitrary_commands": False,
        "exploitation": False,
        "credential_attacks": False,
        "persistence": False,
        "lateral_movement": False,
        "evasion": False,
        "fixed_wordlists": False,
    }
    result["operator_perspective"] = "threat-informed: identify entry points, weaknesses, evidence gaps and defender visibility without exploiting the target"
    return result
