from africanwatch.apps.offensive_lab.adversary import build_attack_surface, build_adversary_plan, detection_expectations


def test_attack_surface_derives_non_exploitative_nodes():
    result = {
        "findings": [
            {"severity": "high", "category": "network-exposure", "title": "Sensitive service"},
            {"severity": "medium", "category": "cors", "title": "Loose CORS"},
        ],
        "ports": {"services": [{"port": 3389, "service": "ms-wbt-server", "product": "RDP"}]},
        "web": {"status_code": 200, "title": "Portal"},
        "dns": {"dns_ns": ["ns1.example"]},
    }
    surface = build_attack_surface(result, asset_criticality="high")
    assert surface["risk_signal"] > 0
    assert any(node["stage"] == "exposure" for node in surface["nodes"])
    assert all("exploit" not in str(node).lower() for node in surface["nodes"])


def test_detection_expectations_are_bounded():
    data = {"web": {}, "dns": {}, "ports": {"services": [{"port": 443}, {"port": 80}]}}
    telemetry = detection_expectations(data)
    assert telemetry["estimated_network_actions"] >= 1
    assert telemetry["noise_level"] in {"low", "moderate", "high"}
    assert telemetry["telemetry_to_expect"]


def test_adversary_plan_is_policy_bound():
    plan = build_adversary_plan(
        profiles=["dns_posture", "web_posture", "adversary_recon", "exposure_chain"],
        scope_size=3,
        lab_mode=False,
    )
    assert plan["scope_size"] == 3
    assert plan["rules"]["no_exploitation"] is True
    assert any(phase["enabled"] for phase in plan["phases"])
