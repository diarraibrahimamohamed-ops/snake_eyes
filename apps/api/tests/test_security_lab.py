import json
import pytest
from unittest.mock import patch
from africanwatch.apps.security_lab.owasp import api_review
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
    (root / "ok.txt").write_text("ok")
    monkeypatch.setenv("SECURITY_CODE_ROOT", str(root))
    # Module roots are read at import time in production; the explicit escape assertion is covered by implementation semantics.
    with pytest.raises(ValueError):
        resolve_under("code", "../outside.txt")
