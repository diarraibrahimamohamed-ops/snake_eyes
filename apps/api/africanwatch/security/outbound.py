"""Outbound HTTP controls: SSRF-resistant fetching for untrusted URLs."""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import httpx
from django.conf import settings

MAX_REDIRECTS = 3
MAX_RESPONSE_BYTES = 2_000_000


def _resolve(hostname: str) -> list[ipaddress._BaseAddress]:
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Impossible de résoudre le domaine") from exc
    addresses = []
    for info in infos:
        addr = info[4][0]
        try:
            addresses.append(ipaddress.ip_address(addr))
        except ValueError:
            continue
    if not addresses:
        raise ValueError("Aucune adresse IP résolue")
    return list(dict.fromkeys(addresses))


def validate_public_url(url: str) -> str:
    """Validate a user-controlled URL before making an outbound request."""
    parsed = urlparse((url or "").strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Seules les URLs HTTP(S) sont autorisées")
    if not parsed.hostname:
        raise ValueError("Hôte manquant")
    if parsed.username or parsed.password:
        raise ValueError("Les identifiants dans les URLs sont interdits")
    lab_mode = bool(getattr(settings, "LAB_MODE", False))
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise ValueError("Port invalide")
    allowed_ports = set(getattr(settings, "ALLOWED_PUBLIC_TARGET_PORTS", [80, 443]))
    if not lab_mode and parsed.port not in (None, *allowed_ports):
        raise ValueError("Port non autorisé hors LAB")
    addresses = _resolve(parsed.hostname)
    if not lab_mode:
        for address in addresses:
            if (
                address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_multicast
                or address.is_reserved
                or address.is_unspecified
            ):
                raise ValueError("Cible interne/non publique bloquée")
    return url


def safe_get(url: str, *, headers: dict[str, str] | None = None, timeout: float = 15.0, max_bytes: int = MAX_RESPONSE_BYTES) -> httpx.Response:
    """Fetch HTTP content with bounded redirects, streamed body size and host validation."""
    current = validate_public_url(url)
    client_headers = {"User-Agent": "AfricaWatch/2.0", **(headers or {})}
    with httpx.Client(follow_redirects=False, trust_env=False, timeout=timeout) as client:
        for _ in range(MAX_REDIRECTS + 1):
            with client.stream("GET", current, headers=client_headers) as response:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        break
                    current = validate_public_url(urljoin(current, location))
                    continue
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        if int(content_length) > max_bytes:
                            raise ValueError("Réponse trop volumineuse")
                    except ValueError as exc:
                        if str(exc) == "Réponse trop volumineuse":
                            raise
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError("Réponse trop volumineuse")
                    chunks.append(chunk)
                content = b"".join(chunks)
                return httpx.Response(response.status_code, headers=response.headers, content=content, request=response.request, extensions=response.extensions)
    raise ValueError("Trop de redirections")


def validate_scan_target(value: str, *, allow_private: bool = False) -> str:
    """Validate a registered assessment target. Private targets require global LAB_MODE."""
    value = (value or "").strip()
    if not value or any(ch in value for ch in "\r\n\x00"):
        raise ValueError("Cible invalide")
    if allow_private and not getattr(settings, "LAB_MODE", False):
        raise ValueError("Le mode LAB doit être activé côté serveur")
    parsed = urlparse(value if "://" in value else f"https://{value}")
    host = parsed.hostname
    if not host:
        raise ValueError("Hôte de cible manquant")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        addresses = _resolve(host)
        if not allow_private:
            for address in addresses:
                if address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved or address.is_unspecified:
                    raise ValueError("Le nom cible résout vers une adresse interne/réservée")
        return value

    blocked = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    if blocked and not allow_private:
        raise ValueError("Cible privée/réservée bloquée hors mode LAB")
    return value
