from __future__ import annotations
import os
import shutil
import subprocess
from pathlib import Path

ROOTS = {
    "code": Path(os.getenv("SECURITY_CODE_ROOT", "/security-lab/code")).resolve(),
    "container": Path(os.getenv("SECURITY_CONTAINER_ROOT", "/security-lab/containers")).resolve(),
    "secrets": Path(os.getenv("SECURITY_CODE_ROOT", "/security-lab/code")).resolve(),
    "credentials": Path(os.getenv("CREDENTIAL_LAB_ROOT", "/security-lab/credentials")).resolve(),
}


def resolve_under(root_key: str, organization_id, relative: str) -> Path:
    root = ROOTS[root_key] / str(organization_id) if root_key in {"code", "container", "secrets", "credentials"} else ROOTS[root_key]
    root = root.resolve()
    candidate = (root / relative).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError("Chemin hors du répertoire autorisé")
    if not candidate.exists():
        raise ValueError("Ressource introuvable dans le répertoire autorisé")
    return candidate


def availability() -> list[dict]:
    tools = ["semgrep", "trivy", "gitleaks", "docker"]
    return [{"tool": t, "available": bool(shutil.which(t))} for t in tools]


def _run_fixed(args: list[str], cwd: Path | None = None, timeout: int = 120) -> dict:
    try:
        completed = subprocess.run(args, cwd=str(cwd) if cwd else None, capture_output=True, text=True, timeout=timeout, shell=False, check=False, env={k:v for k,v in os.environ.items() if k not in {"HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","NO_PROXY"}})
    except FileNotFoundError:
        return {"available": False, "reason": f"outil absent: {args[0]}"}
    except subprocess.TimeoutExpired:
        return {"available": True, "timeout": True, "returncode": 124, "stdout": "", "stderr": "timeout"}
    return {"available": True, "command": " ".join(args[:4]) + (" …" if len(args) > 4 else ""), "returncode": completed.returncode, "stdout": completed.stdout[-60_000:], "stderr": completed.stderr[-20_000:]}


def local_sast(organization_id, relative: str) -> dict:
    path = resolve_under("code", organization_id, relative)
    results = {}
    if shutil.which("semgrep"):
        results["semgrep"] = _run_fixed(["semgrep", "--config", "auto", "--json", "--metrics=off", str(path)], cwd=path if path.is_dir() else path.parent, timeout=180)
    else:
        results["semgrep"] = {"available": False}
    return {"path": relative, "results": results}


def local_secrets(organization_id, relative: str) -> dict:
    path = resolve_under("secrets", organization_id, relative)
    if shutil.which("gitleaks"):
        return {"tool": "gitleaks", "result": _run_fixed(["gitleaks", "dir", "--redact", "--no-banner", str(path)], cwd=path if path.is_dir() else path.parent, timeout=180)}
    return {"tool": "gitleaks", "available": False}


def local_container(organization_id, relative: str) -> dict:
    path = resolve_under("container", organization_id, relative)
    if shutil.which("trivy"):
        return {"tool": "trivy", "result": _run_fixed(["trivy", "fs", "--scanners", "vuln,misconfig,secret", "--format", "json", str(path)], cwd=path.parent, timeout=240)}
    return {"tool": "trivy", "available": False}


def credential_audit(organization_id, relative_hash_file: str, wordlist_relative: str = "") -> dict:
    """Audit stored hash *formats* only; never crack, verify or reveal credentials."""
    hashfile = resolve_under("credentials", organization_id, relative_hash_file)
    if not hashfile.is_file():
        raise ValueError("Le fichier de hashes doit être un fichier régulier")
    if hashfile.stat().st_size > 5 * 1024 * 1024:
        raise ValueError("Fichier de hashes trop volumineux (maximum 5 Mio)")

    import re

    format_patterns = [
        ("argon2", re.compile(r"^\$argon2(?:id|i|d)\$")),
        ("bcrypt", re.compile(r"^\$2[aby]\$")),
        ("scrypt", re.compile(r"^\$scrypt\$")),
        ("pbkdf2", re.compile(r"^\$pbkdf2-")),
        ("sha512crypt", re.compile(r"^\$6\$")),
        ("sha256crypt", re.compile(r"^\$5\$")),
        ("md5crypt", re.compile(r"^\$1\$")),
        ("md5_or_unsalted_legacy", re.compile(r"^[0-9a-fA-F]{32}$")),
        ("sha1_or_unsalted_legacy", re.compile(r"^[0-9a-fA-F]{40}$")),
        ("sha256_or_unsalted_legacy", re.compile(r"^[0-9a-fA-F]{64}$")),
    ]
    counts = {}
    total = 0
    invalid_or_unknown = 0
    with hashfile.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            value = line.strip()
            if not value:
                continue
            total += 1
            if total > 100_000:
                raise ValueError("Trop d'entrées (maximum 100 000)")
            label = next((name for name, pattern in format_patterns if pattern.search(value)), None)
            if label is None:
                invalid_or_unknown += 1
                continue
            counts[label] = counts.get(label, 0) + 1

    legacy_count = sum(count for name, count in counts.items() if "legacy" in name or name == "md5crypt")
    modern_count = counts.get("argon2", 0) + counts.get("bcrypt", 0) + counts.get("scrypt", 0) + counts.get("pbkdf2", 0)
    return {
        "enabled": True,
        "mode": "format-policy-audit-only",
        "file": relative_hash_file,
        "total_entries": total,
        "format_counts": counts,
        "unknown_or_unclassified": invalid_or_unknown,
        "policy_findings": [
            {"severity": "high", "code": "LEGACY_HASH_FORMATS", "count": legacy_count,
             "message": "Des formats de hash historiques ou non recommandés sont présents; planifier une migration après authentification réussie."}
            for _ in [0] if legacy_count
        ] + [
            {"severity": "medium", "code": "NO_MODERN_PASSWORD_HASHES", "count": total,
             "message": "Aucun format Argon2, bcrypt, scrypt ou PBKDF2 reconnu dans le fichier."}
            for _ in [0] if total and not modern_count
        ],
        "credential_values_persisted": False,
        "password_cracking_performed": False,
    }


def remote_auth_plan(target: str, service: str) -> dict:
    return {"tool": "hydra", "mode": "plan-only", "target": target, "service": service, "execution": False, "reason": "Les tests de mots de passe réseau ne sont pas exécutés par l'API.", "preconditions": ["preuve d'autorisation", "cible dans le scope", "fenêtre de test active", "compte de test dédié", "limite de tentatives et arrêt automatique", "validation côté propriétaire"]}


def injection_test_plan(target: str) -> dict:
    return {"tool": "sqlmap", "mode": "plan-only", "target": target, "execution": False, "reason": "Le moteur fournit le cadrage et les contrôles non destructifs ; l'exploitation automatisée est laissée à une station de pentest isolée.", "preconditions": ["scope explicite", "endpoint de test", "jeu de données non sensible", "backup/rollback", "fenêtre de test"]}
