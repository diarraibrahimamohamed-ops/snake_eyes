"""Safe parsers for third-party vulnerability reports.

Parsing is offline: uploaded reports are data, never commands. Inputs are bounded
and XML entity expansion is not enabled (stdlib ElementTree).
"""
import csv
import hashlib
import io
import json
import re
import xml.etree.ElementTree as ET

MAX_REPORT_BYTES = 10 * 1024 * 1024
MAX_FINDINGS = 20_000
SEVERITIES = {"info", "low", "medium", "high", "critical"}


class ReportParseError(ValueError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _text(value, limit=5000):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    return str(value).strip()[:limit]


def _severity(value):
    value = str(value or "info").strip().lower()
    if value in SEVERITIES:
        return value
    if value in {"moderate", "warning"}:
        return "medium"
    if value in {"informational", "none"}:
        return "info"
    if value in {"urgent", "emergency"}:
        return "critical"
    return "info"


def _cvss(value):
    try:
        number = float(value)
        if 0 <= number <= 10:
            return number
    except (TypeError, ValueError):
        pass
    return None


def _refs(value):
    if isinstance(value, list):
        items = value
    elif isinstance(value, str):
        items = re.split(r"[\s,;]+", value)
    else:
        items = []
    return [str(item)[:500] for item in items if item and len(str(item)) <= 500][:20]


def _base(*, title, severity="info", scanner="", external_asset="", description="",
          cve_id="", cvss_score=None, component="", remediation="", references=None, evidence=None):
    return {
        "title": _text(title, 500) or "Finding without title",
        "severity": _severity(severity),
        "scanner": _text(scanner, 50),
        "external_asset": _text(external_asset, 500),
        "description": _text(description, 5000),
        "cve_id": _text(cve_id, 30).upper(),
        "cvss_score": _cvss(cvss_score),
        "affected_component": _text(component, 255),
        "remediation": _text(remediation, 5000),
        "references": _refs(references),
        "evidence": evidence if isinstance(evidence, dict) else {},
    }


def _json_payload(data):
    try:
        return json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReportParseError("Le rapport JSON est invalide ou non UTF-8.") from exc


def _parse_nuclei_json(obj):
    if not isinstance(obj, dict):
        return None
    info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    cves = classification.get("cve-id") or obj.get("matched-at", "")
    if isinstance(cves, list):
        cve = cves[0] if cves else ""
    else:
        cve = cves
    refs = info.get("reference", [])
    if isinstance(refs, str):
        refs = [refs]
    return _base(
        title=info.get("name") or obj.get("template-id") or "Nuclei finding",
        severity=info.get("severity"),
        scanner="nuclei",
        external_asset=obj.get("host") or obj.get("matched-at") or obj.get("ip"),
        description=info.get("description"),
        cve_id=cve,
        cvss_score=classification.get("cvss-score"),
        component=obj.get("type") or obj.get("template-id"),
        remediation=info.get("remediation"),
        references=refs,
        evidence={"template_id": _text(obj.get("template-id"), 200),
                  "matched_at": _text(obj.get("matched-at"), 500),
                  "type": _text(obj.get("type"), 50)},
    )


def _parse_nmap(data):
    # Reject DTD/entity declarations explicitly; reports are untrusted input.
    upper_prefix = data.upper()
    if b"<!DOCTYPE" in upper_prefix or b"<!ENTITY" in upper_prefix:
        raise ReportParseError("DTD et entités XML ne sont pas autorisés.")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ReportParseError("Le rapport XML Nmap est invalide.") from exc
    if root.tag != "nmaprun":
        raise ReportParseError("Le contenu XML ne ressemble pas à un rapport Nmap.")
    findings = []
    for host in root.findall("host"):
        addresses = [x.get("addr", "") for x in host.findall("address") if x.get("addr")]
        hostnames = [x.get("name", "") for x in host.findall("./hostnames/hostname") if x.get("name")]
        target = (addresses + hostnames)
        external_asset = target[0] if target else ""
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            service_name = service.get("name", "unknown") if service is not None else "unknown"
            product = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            port_id = port.get("portid", "")
            protocol = port.get("protocol", "tcp")
            risk = {"telnet": "high", "ftp": "medium", "rdp": "high",
                    "http": "info", "https": "info", "ssh": "info"}.get(service_name, "low")
            title = f"Port {port_id}/{protocol} ouvert — {service_name}"
            findings.append(_base(
                title=title, severity=risk, scanner="nmap", external_asset=external_asset,
                description=f"Service déclaré par le rapport: {service_name} {product} {version}".strip(),
                component=f"{service_name} {product} {version}".strip(),
                evidence={"port": port_id, "protocol": protocol, "service": service_name,
                          "product": product, "version": version},
            ))
            if len(findings) > MAX_FINDINGS:
                raise ReportParseError("Le rapport dépasse la limite de constats.")
    return findings


def _parse_nessus(data):
    # The full report is capped at 10 MiB by parse_report; inspect all of it.
    upper_prefix = data.upper()
    if b"<!DOCTYPE" in upper_prefix or b"<!ENTITY" in upper_prefix:
        raise ReportParseError("DTD et entités XML ne sont pas autorisés.")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ReportParseError("Le rapport XML Nessus est invalide.") from exc
    if root.tag != "NessusClientData_v2":
        raise ReportParseError("Le contenu XML ne ressemble pas à un rapport Nessus.")
    findings = []
    for item in root.findall(".//ReportItem"):
        host = item.get("host-ip") or item.get("hostname") or ""
        risk = item.findtext("risk_factor") or item.get("risk_factor", "None")
        cvss = item.findtext("cvss3_base_score") or item.findtext("cvss_base_score")
        cve = item.findtext("cve") or ""
        refs = [x.text for x in item.findall("see_also") if x.text]
        findings.append(_base(
            title=item.get("plugin_name") or "Nessus finding",
            severity=_severity(risk), scanner="nessus", external_asset=host,
            description=item.findtext("description") or "",
            cve_id=cve, cvss_score=cvss,
            component=item.get("svc_name") or item.get("protocol") or "",
            remediation=item.findtext("solution") or "",
            references=refs,
            evidence={"plugin_id": _text(item.get("pluginID"), 50),
                      "port": _text(item.get("port"), 20),
                      "plugin_family": _text(item.get("pluginFamily"), 100)},
        ))
        if len(findings) > MAX_FINDINGS:
            raise ReportParseError("Le rapport dépasse la limite de constats.")
    return findings


def _parse_shodan_json(obj):
    if not isinstance(obj, dict):
        raise ReportParseError("L'export Shodan JSON doit être un objet ou une liste d'objets.")
    matches = obj.get("matches")
    if isinstance(matches, list):
        records = matches
    elif isinstance(obj.get("data"), list):
        records = obj["data"]
    else:
        records = [obj]
    findings = []
    for row in records:
        if not isinstance(row, dict):
            continue
        ip = row.get("ip_str") or row.get("ip") or row.get("hostnames") or ""
        port = row.get("port")
        transport = row.get("transport", "tcp")
        product = row.get("product") or row.get("http", {}).get("server", "") if isinstance(row.get("http", {}), dict) else row.get("product", "")
        findings.append(_base(
            title=f"Service observé dans Shodan{f' — port {port}' if port is not None else ''}",
            severity="info", scanner="shodan", external_asset=ip,
            description=_text(row.get("data") or row.get("banner") or product, 2000),
            component=product,
            evidence={"port": _text(port, 20), "transport": _text(transport, 20),
                      "org": _text(row.get("org"), 200), "product": _text(product, 200)},
        ))
        if len(findings) > MAX_FINDINGS:
            raise ReportParseError("Le rapport dépasse la limite de constats.")
    return findings


def _parse_shodan_csv(data):
    try:
        text = data.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
    except UnicodeDecodeError as exc:
        raise ReportParseError("Le CSV Shodan doit être encodé en UTF-8.") from exc
    if not reader.fieldnames:
        raise ReportParseError("Le CSV ne contient pas d'en-têtes.")
    fields = {name.strip().lower() for name in reader.fieldnames if name}
    if not fields.intersection({"ip", "ip_str", "ip address", "host", "ip_address"}):
        raise ReportParseError("Colonne IP/host absente du CSV Shodan.")
    findings = []
    for row in reader:
        lowered = {(key or "").strip().lower(): value for key, value in row.items()}
        ip = lowered.get("ip_str") or lowered.get("ip") or lowered.get("ip address") or lowered.get("ip_address") or lowered.get("host") or ""
        port = lowered.get("port", "")
        product = lowered.get("product", "")
        findings.append(_base(
            title=f"Service observé dans Shodan{f' — port {port}' if port else ''}",
            severity="info", scanner="shodan", external_asset=ip,
            description=lowered.get("data", "") or lowered.get("banner", ""),
            component=product,
            evidence={"port": _text(port, 20), "product": _text(product, 200)},
        ))
        if len(findings) > MAX_FINDINGS:
            raise ReportParseError("Le rapport dépasse la limite de constats.")
    return findings


def parse_report(source_type: str, data: bytes):
    if not isinstance(data, bytes) or not data:
        raise ReportParseError("Le fichier est vide.")
    if len(data) > MAX_REPORT_BYTES:
        raise ReportParseError("Le rapport dépasse la limite de 10 Mio.")
    if source_type == "nmap_xml":
        result = _parse_nmap(data)
    elif source_type == "nessus_xml":
        result = _parse_nessus(data)
    elif source_type == "nuclei_json":
        obj = _json_payload(data)
        if isinstance(obj, list):
            result = [_parse_nuclei_json(x) for x in obj]
        elif isinstance(obj, dict) and isinstance(obj.get("info"), dict):
            result = [_parse_nuclei_json(obj)]
        elif isinstance(obj, dict) and isinstance(obj.get("results"), list):
            result = [_parse_nuclei_json(x) for x in obj["results"]]
        else:
            result = [_parse_nuclei_json(obj)]
        result = [x for x in result if x]
    elif source_type == "nuclei_jsonl":
        result = []
        try:
            lines = data.decode("utf-8-sig").splitlines()
        except UnicodeDecodeError as exc:
            raise ReportParseError("Le JSONL doit être encodé en UTF-8.") from exc
        for line_number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                result.append(_parse_nuclei_json(json.loads(line)))
            except json.JSONDecodeError as exc:
                raise ReportParseError(f"Ligne JSONL invalide: {line_number}.") from exc
            if len(result) > MAX_FINDINGS:
                raise ReportParseError("Le rapport dépasse la limite de constats.")
        result = [x for x in result if x]
    elif source_type == "shodan_json":
        result = _parse_shodan_json(_json_payload(data))
    elif source_type == "shodan_csv":
        result = _parse_shodan_csv(data)
    else:
        raise ReportParseError("Format de rapport non pris en charge.")
    if len(result) > MAX_FINDINGS:
        raise ReportParseError("Le rapport dépasse la limite de constats.")
    return result
