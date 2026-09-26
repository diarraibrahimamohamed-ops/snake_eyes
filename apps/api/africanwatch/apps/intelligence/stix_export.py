from __future__ import annotations
import json
from stix2 import Bundle, Identity, Indicator, Note

IOC_PATTERNS = {
    "ipv4": "[ipv4-addr:value = '{value}']",
    "ip": "[ipv4-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "email": "[email-addr:value = '{value}']",
    "sha256": "[file:hashes.'SHA-256' = '{value}']",
    "sha1": "[file:hashes.'SHA-1' = '{value}']",
    "md5": "[file:hashes.MD5 = '{value}']",
}

def _safe(value: str) -> str:
    return (value or "").replace("\\", "\\\\").replace("'", "\\'")

def export_run(run) -> dict:
    identity = Identity(name="AfricaWatch Intelligence Center", identity_class="organization")
    objects = [identity]
    indicators = {}
    for row in run.observations.all()[:500]:
        content = f"{row.title}\n{row.content[:1200]}".strip()[:1400]
        objects.append(Note(content=content or "AfricaWatch observation", object_refs=[identity.id]))
        for ioc in row.iocs or []:
            kind = str(ioc.get("type") or "").lower()
            value = _safe(str(ioc.get("value") or ""))
            if not value or (kind, value) in indicators:
                continue
            pattern = IOC_PATTERNS.get(kind)
            if not pattern:
                continue
            ind = Indicator(name=f"AfricaWatch {kind}", pattern=pattern.format(value=value), pattern_type="stix", valid_from=row.retrieved_at)
            objects.append(ind)
            indicators[(kind, value)] = ind
    return json.loads(Bundle(*objects).serialize(pretty=True))
