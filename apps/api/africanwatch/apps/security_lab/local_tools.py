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
    "wordlists": Path(os.getenv("CREDENTIAL_WORDLIST_ROOT", "/security-lab/wordlists")).resolve(),
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
    tools = ["nmap", "nuclei", "john", "hashcat", "semgrep", "trivy", "gitleaks", "docker"]
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
    if os.getenv("ALLOW_LOCAL_CREDENTIAL_AUDIT", "false").lower() != "true":
        return {"enabled": False, "reason": "ALLOW_LOCAL_CREDENTIAL_AUDIT=false", "mode": "offline-only"}
    hashfile = resolve_under("credentials", organization_id, relative_hash_file)
    result = {"enabled": True, "hash_file": relative_hash_file, "tool": "john", "mode": "offline-only"}
    if not shutil.which("john"):
        result["available"] = False
        return result
    args = ["john"]
    if wordlist_relative:
        wordlist = resolve_under("wordlists", organization_id, wordlist_relative)
        args.append("--wordlist=" + str(wordlist))
    args.extend(["--pot=/tmp/afw-john.pot", str(hashfile)])
    result["run"] = _run_fixed(args, cwd=hashfile.parent, timeout=300)
    return result


def remote_auth_plan(target: str, service: str) -> dict:
    return {"tool": "hydra", "mode": "plan-only", "target": target, "service": service, "execution": False, "reason": "Les tests de mots de passe réseau ne sont pas exécutés par l'API.", "preconditions": ["preuve d'autorisation", "cible dans le scope", "fenêtre de test active", "compte de test dédié", "limite de tentatives et arrêt automatique", "validation côté propriétaire"]}


def injection_test_plan(target: str) -> dict:
    return {"tool": "sqlmap", "mode": "plan-only", "target": target, "execution": False, "reason": "Le moteur fournit le cadrage et les contrôles non destructifs ; l'exploitation automatisée est laissée à une station de pentest isolée.", "preconditions": ["scope explicite", "endpoint de test", "jeu de données non sensible", "backup/rollback", "fenêtre de test"]}
