import json
import pytest
from africanwatch.apps.security_lab.owasp import api_review
from africanwatch.apps.security_lab import local_tools
from africanwatch.apps.security_lab.local_tools import resolve_under


def test_api_review_detects_missing_security_scheme():
    result = api_review(json.dumps({"openapi":"3.0.0", "info":{"title":"Lab","version":"1"}, "paths":{"/users":{"get":{}}}}))
    assert result["valid"] is True
    assert any(f["control_id"] == "API2" for f in result["findings"])


def test_api_review_accepts_security_scheme():
    result = api_review(json.dumps({"openapi":"3.0.0", "info":{"title":"Lab","version":"1"}, "components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}}, "security":[{"bearer":[]}], "paths":{"/users":{"get":{}}}}))
    assert result["valid"] is True
    assert not any(f["title"] == "Aucun securityScheme OpenAPI" for f in result["findings"])


def test_local_path_escape_is_blocked(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    org_root = root / "org-test"
    org_root.mkdir()
    (org_root / "ok.txt").write_text("ok")
    monkeypatch.setitem(local_tools.ROOTS, "code", root)
    with pytest.raises(ValueError):
        resolve_under("code", "org-test", "../outside.txt")



def test_hash_policy_audit_classifies_formats_without_cracking(tmp_path, monkeypatch):
    from africanwatch.apps.security_lab import local_tools

    org_id = "org-test"
    root = tmp_path / org_id
    root.mkdir()
    (root / "hashes.txt").write_text("$argon2id$v=19$m=65536,t=3,p=4$example\n" + "a" * 32 + "\n")
    monkeypatch.setitem(local_tools.ROOTS, "credentials", tmp_path)
    result = local_tools.credential_audit(org_id, "hashes.txt")
    assert result["mode"] == "format-policy-audit-only"
    assert result["format_counts"]["argon2"] == 1
    assert result["format_counts"]["md5_or_unsalted_legacy"] == 1
    assert result["password_cracking_performed"] is False
    assert "credential_values" not in result
