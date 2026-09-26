from __future__ import annotations
import hashlib
import ipaddress
import json
from urllib.parse import quote, urlparse
from datetime import datetime, timezone as dt_timezone
import httpx


def _safe_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if len(value) > 253 or any(ch in value for ch in "\r\n\x00"):
        raise ValueError("Cible invalide")
    if value.startswith("http://") or value.startswith("https://"):
        value = urlparse(value).hostname or ""
    if not value or "." not in value:
        raise ValueError("Domaine invalide")
    return value


def _safe_public_http(url: str):
    from africanwatch.security.outbound import safe_get
    return safe_get(url, timeout=12, max_bytes=600_000, headers={"User-Agent": "AfricaWatch-Intel/6.0"})


def _onion_get(url: str):
    from django.conf import settings
    if not getattr(settings, "TOR_ENABLED", False):
        raise ValueError("Le mode Tor n'est pas activé côté serveur")
    parsed = urlparse(url)
    if parsed.hostname is None or not parsed.hostname.endswith(".onion"):
        raise ValueError("La collecte Onion exige une adresse .onion")
    allowed = {x.strip().lower() for x in getattr(settings, "ONION_ALLOWED_HOSTS", []) if x.strip()}
    if parsed.hostname.lower() not in allowed:
        raise ValueError("Source Onion hors allowlist institutionnelle")
    proxy = getattr(settings, "TOR_SOCKS_PROXY", "socks5://tor:9050")
    try:
        client = httpx.Client(proxy=proxy, follow_redirects=False, trust_env=False, timeout=20.0)
    except TypeError:
        client = httpx.Client(proxies=proxy, follow_redirects=False, trust_env=False, timeout=20.0)
    with client:
        response = client.get(url, headers={"User-Agent": "AfricaWatch-OnionCollector/6.0"})
        if len(response.content) > 600_000:
            raise ValueError("Réponse Onion trop volumineuse")
        return response


def dns_enrichment(domain: str) -> dict:
    import dns.resolver
    domain = _safe_domain(domain)
    output = {"domain": domain, "records": {}}
    for rr in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            answers = dns.resolver.resolve(domain, rr, lifetime=5)
            output["records"][rr] = [str(r).strip('"') for r in answers][:30]
        except Exception:
            output["records"][rr] = []
    return output


def rdap_ip(ip: str) -> dict:
    parsed = ipaddress.ip_address(ip.strip())
    url = f"https://rdap.org/ip/{parsed}"
    response = _safe_public_http(url)
    try:
        return response.json()
    except Exception:
        return {"status_code": response.status_code, "body": response.text[:10000]}


def rdap_domain(domain: str) -> dict:
    domain = _safe_domain(domain)
    response = _safe_public_http(f"https://rdap.org/domain/{quote(domain)}")
    try:
        return response.json()
    except Exception:
        return {"status_code": response.status_code, "body": response.text[:10000]}


def certificate_transparency(domain: str) -> list[dict]:
    domain = _safe_domain(domain)
    url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
    response = _safe_public_http(url)
    try:
        rows = response.json()
    except Exception:
        return []
    seen = set(); out = []
    for row in rows[:300]:
        names = str(row.get("name_value", "")).splitlines()
        for name in names:
            name = name.strip().lower().lstrip("*.")
            if name == domain or name.endswith("." + domain):
                if name not in seen:
                    seen.add(name)
                    out.append({"domain": name, "issuer": row.get("issuer_name"), "not_before": row.get("not_before"), "not_after": row.get("not_after")})
    return out[:200]


def public_page(url: str, *, onion=False) -> dict:
    response = _onion_get(url) if onion else _safe_public_http(url)
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(response.text[:600000], "lxml")
    title = (soup.title.get_text(" ", strip=True) if soup.title else "")[:500]
    description = ""
    meta = soup.find("meta", attrs={"name": "description"})
    if meta:
        description = (meta.get("content") or "")[:1200]
    links = []
    for a in soup.find_all("a", href=True)[:200]:
        href = a.get("href")
        if href:
            links.append(href[:500])
    return {
        "status_code": response.status_code,
        "final_url": str(response.url),
        "title": title,
        "description": description,
        "headers": {k.lower(): v[:400] for k, v in response.headers.items() if k.lower() in {"server", "content-type", "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"}},
        "links": links,
        "body_sha256": hashlib.sha256(response.content).hexdigest(),
        "body_preview": soup.get_text(" ", strip=True)[:5000],
    }


def gdelt_news(query: str) -> list[dict]:
    q = quote(query[:300])
    url = f"https://api.gdeltproject.org/api/v2/doc/doc?query={q}&mode=ArtList&format=json&maxrecords=50&sort=HybridRel"
    response = _safe_public_http(url)
    try:
        data = response.json()
    except Exception:
        return []
    return data.get("articles", [])[:50]


def provider_enrichment(kind: str, value: str) -> list[tuple[str, str, str]]:
    """Optional passive enrichment via existing provider credentials; no target probing."""
    from django.conf import settings
    out = []
    try:
        import httpx
        if kind == "ip" and getattr(settings, "SHODAN_API_KEY", ""):
            r = httpx.get(f"https://api.shodan.io/shodan/host/{value}", params={"key": settings.SHODAN_API_KEY}, timeout=10, follow_redirects=False, trust_env=False)
            if r.status_code == 200:
                out.append(("SHODAN", r.url.__str__(), r.text[:120000]))
        if getattr(settings, "VIRUSTOTAL_API_KEY", ""):
            path = "ip_addresses" if kind == "ip" else "domains" if kind == "domain" else None
            if path:
                r = httpx.get(f"https://www.virustotal.com/api/v3/{path}/{value}", headers={"x-apikey": settings.VIRUSTOTAL_API_KEY}, timeout=10, follow_redirects=False, trust_env=False)
                if r.status_code == 200:
                    out.append(("VIRUSTOTAL", str(r.url), r.text[:120000]))
    except Exception:
        pass
    return out


def rss_entries(url: str, limit: int = 50) -> list[dict]:
    import feedparser
    response = _safe_public_http(url)
    feed = feedparser.parse(response.content)
    return [{
        "title": str(entry.get("title", ""))[:500],
        "summary": str(entry.get("summary", ""))[:4000],
        "url": str(entry.get("link", ""))[:1000],
        "published": str(entry.get("published", ""))[:120],
        "author": str(entry.get("author", ""))[:255],
    } for entry in feed.entries[:limit]]

def public_api_snapshot(url: str) -> dict:
    response = _safe_public_http(url)
    content_type = response.headers.get("content-type", "")
    try:
        data = response.json()
    except Exception:
        data = {"body": response.text[:10000]}
    return {"status_code": response.status_code, "content_type": content_type[:160], "sha256": hashlib.sha256(response.content).hexdigest(), "data": data}
