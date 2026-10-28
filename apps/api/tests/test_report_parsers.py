"""Unit tests for bounded offline scanner report parsers."""
import json

import pytest

from africanwatch.apps.vulns.report_parsers import ReportParseError, parse_report


def test_nuclei_json_normalizes_cve_severity_and_asset():
    raw = json.dumps({
        "template-id": "CVE-2024-1234",
        "host": "app.example.test",
        "matched-at": "https://app.example.test/",
        "info": {
            "name": "Example vulnerability",
            "severity": "high",
            "description": "Example description",
            "classification": {"cve-id": ["CVE-2024-1234"], "cvss-score": 8.2},
            "reference": ["https://example.test/advisory"],
        },
    }).encode()
    findings = parse_report("nuclei_json", raw)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["cve_id"] == "CVE-2024-1234"
    assert findings[0]["cvss_score"] == 8.2
    assert findings[0]["external_asset"] == "app.example.test"


def test_nmap_xml_imports_only_open_ports_as_observations():
    raw = b"""<?xml version="1.0"?>
    <nmaprun>
      <host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="23"><state state="open"/>
            <service name="telnet" product="BusyBox"/>
          </port>
          <port protocol="tcp" portid="443"><state state="closed"/>
            <service name="https"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""
    findings = parse_report("nmap_xml", raw)
    assert len(findings) == 1
    assert findings[0]["external_asset"] == "192.0.2.10"
    assert findings[0]["severity"] == "high"
    assert findings[0]["evidence"]["port"] == "23"


def test_nessus_xml_imports_plugin_evidence():
    raw = b"""<NessusClientData_v2><Report>
      <ReportHost name="192.0.2.20"><ReportItem port="443" svc_name="www"
      protocol="tcp" severity="3" pluginID="123" pluginName="TLS issue"
      pluginFamily="General">
        <risk_factor>High</risk_factor><description>Weak TLS config</description>
        <solution>Update TLS configuration</solution><cve>CVE-2023-1234</cve>
        <cvss3_base_score>7.5</cvss3_base_score>
      </ReportItem></ReportHost>
    </Report></NessusClientData_v2>"""
    findings = parse_report("nessus_xml", raw)
    assert findings[0]["scanner"] == "nessus"
    assert findings[0]["severity"] == "high"
    assert findings[0]["cve_id"] == "CVE-2023-1234"
    assert findings[0]["remediation"] == "Update TLS configuration"


def test_shodan_csv_requires_host_column():
    findings = parse_report("shodan_csv", b"ip_str,port,product\n192.0.2.1,443,nginx\n")
    assert len(findings) == 1
    assert findings[0]["external_asset"] == "192.0.2.1"
    assert findings[0]["evidence"]["port"] == "443"


def test_xml_dtd_and_entities_are_rejected():
    raw = b'<!DOCTYPE nmaprun [<!ENTITY x "bad">]><nmaprun>&x;</nmaprun>'
    with pytest.raises(ReportParseError, match="DTD"):
        parse_report("nmap_xml", raw)


def test_invalid_jsonl_fails_closed():
    with pytest.raises(ReportParseError, match="Ligne JSONL"):
        parse_report("nuclei_jsonl", b'{"info":{}}\nnot-json\n')


def test_report_size_limit_is_enforced():
    with pytest.raises(ReportParseError, match="10 Mio"):
        parse_report("nuclei_json", b"x" * (10 * 1024 * 1024 + 1))
