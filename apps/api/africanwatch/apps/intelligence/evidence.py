"""Application-layer evidence ledger with hash-chain and Merkle verification.

The ledger detects accidental or unauthorized changes to recorded evidence.
A Merkle root stored in the same database is not an external trust anchor;
deployments still need independent signing/anchoring for stronger guarantees.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

from django.db import transaction
from django.utils import timezone

from .models import CollectionRun, IntelligenceEvidence


SCHEMA_VERSION = 1
CONTENT_PREVIEW_LIMIT = 10_000


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON deterministically for reproducible content hashes."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=str,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _record_hash(
    *,
    run_id: str,
    sequence: int,
    schema_version: int,
    captured_at: str,
    payload_sha256: str,
    previous_hash: str,
) -> str:
    material = {
        "schema_version": schema_version,
        "run_id": str(run_id),
        "sequence": sequence,
        "captured_at": captured_at,
        "payload_sha256": payload_sha256,
        "previous_hash": previous_hash,
    }
    return sha256_bytes(b"africawatch:evidence-record:v1:" + canonical_json_bytes(material))


def merkle_root(record_hashes: Iterable[str]) -> str:
    """Return a domain-separated Merkle root; duplicate the last odd leaf."""
    nodes = [
        hashlib.sha256(b"\x00" + bytes.fromhex(value)).digest()
        for value in record_hashes
    ]
    if not nodes:
        return ""

    while len(nodes) > 1:
        if len(nodes) % 2:
            nodes.append(nodes[-1])
        nodes = [
            hashlib.sha256(b"\x01" + nodes[index] + nodes[index + 1]).digest()
            for index in range(0, len(nodes), 2)
        ]
    return nodes[0].hex()


@transaction.atomic
def append_evidence_record(
    *,
    run: CollectionRun,
    observation,
    source=None,
    source_label: str = "",
    source_url: str = "",
    title: str = "",
    content: str = "",
    published_at=None,
    raw=None,
    captured_at=None,
) -> IntelligenceEvidence:
    """Append a snapshot for one acquisition event, including deduplicated hits."""
    locked_run = CollectionRun.objects.select_for_update().select_related(
        "organization", "target"
    ).get(pk=run.pk)

    previous = (
        IntelligenceEvidence.objects.filter(run=locked_run)
        .order_by("-sequence")
        .first()
    )
    sequence = (previous.sequence + 1) if previous else 1
    previous_hash = previous.record_hash if previous else ""
    captured_at = captured_at or timezone.now()
    captured_at_text = captured_at.isoformat()

    source_name = source_label or (source.name if source else "Source externe non référencée")
    raw_sha256 = sha256_json(raw) if raw is not None else None
    content_text = content or ""
    retained_content = content_text[:CONTENT_PREVIEW_LIMIT]

    payload = {
        "schema_version": SCHEMA_VERSION,
        "event_type": "observation_acquired",
        "run_id": str(locked_run.id),
        "organization_id": str(locked_run.organization_id),
        "observation_id": str(observation.id),
        "captured_at": captured_at_text,
        "target": {
            "kind": locked_run.target.kind,
            "value": locked_run.target.value,
        },
        "source": {
            "id": str(source.id) if source else None,
            "label": source_name,
            "kind": source.kind if source else None,
            "url": source_url or "",
            "registered_source_url": source.url if source else None,
            "reliability": float(source.reliability) if source else None,
        },
        "observation": {
            "title": (title or observation.title)[:500],
            "published_at": published_at.isoformat() if published_at else None,
            "content_sha256": sha256_bytes(content_text.encode("utf-8")),
            "content_length": len(content_text),
            "content_preview": retained_content,
            "content_truncated": len(content_text) > CONTENT_PREVIEW_LIMIT,
            "raw_sha256": raw_sha256,
            "classification": observation.classification or {},
            "iocs": observation.iocs or [],
            "evidence_grade": observation.evidence_grade,
            "confidence": observation.confidence,
            "relevance": observation.relevance,
        },
    }
    payload_sha256 = sha256_json(payload)
    record_hash = _record_hash(
        run_id=str(locked_run.id),
        sequence=sequence,
        schema_version=SCHEMA_VERSION,
        captured_at=captured_at_text,
        payload_sha256=payload_sha256,
        previous_hash=previous_hash,
    )

    record = IntelligenceEvidence.objects.create(
        organization=locked_run.organization,
        run=locked_run,
        observation=observation,
        source=source,
        sequence=sequence,
        schema_version=SCHEMA_VERSION,
        captured_at=captured_at,
        source_label=source_name,
        source_url=source_url or "",
        payload=payload,
        payload_sha256=payload_sha256,
        previous_hash=previous_hash,
        record_hash=record_hash,
    )

    hashes = list(
        IntelligenceEvidence.objects.filter(run=locked_run)
        .order_by("sequence")
        .values_list("record_hash", flat=True)
    )
    locked_run.evidence_root_hash = merkle_root(hashes)
    locked_run.save(update_fields=["evidence_root_hash", "updated_at"])
    run.evidence_root_hash = locked_run.evidence_root_hash
    return record


def verify_run_evidence(run: CollectionRun) -> dict[str, Any]:
    """Recompute payload hashes, the per-run hash chain and the Merkle root."""
    records = list(
        IntelligenceEvidence.objects.filter(run=run).order_by("sequence")
    )
    if not records:
        return {
            "status": "empty",
            "valid": False,
            "record_count": 0,
            "stored_merkle_root": None,
            "legacy_root_present": bool(run.evidence_root_hash),
            "calculated_merkle_root": "",
            "errors": ["no_evidence_records"],
        }

    errors: list[str] = []
    expected_previous = ""
    calculated_record_hashes: list[str] = []

    for expected_sequence, record in enumerate(records, start=1):
        if record.sequence != expected_sequence:
            errors.append(f"sequence_gap:{record.sequence}")

        payload = record.payload if isinstance(record.payload, dict) else {}
        calculated_payload_hash = sha256_json(record.payload)
        if calculated_payload_hash != record.payload_sha256:
            errors.append(f"payload_hash_mismatch:{record.sequence}")

        if record.previous_hash != expected_previous:
            errors.append(f"previous_hash_mismatch:{record.sequence}")

        if record.schema_version != SCHEMA_VERSION:
            errors.append(f"schema_version_mismatch:{record.sequence}")
        if payload.get("run_id") != str(record.run_id):
            errors.append(f"run_reference_mismatch:{record.sequence}")
        if payload.get("organization_id") != str(record.organization_id):
            errors.append(f"organization_reference_mismatch:{record.sequence}")
        if payload.get("observation_id") != str(record.observation_id):
            errors.append(f"observation_reference_mismatch:{record.sequence}")

        payload_source = payload.get("source") if isinstance(payload.get("source"), dict) else {}
        expected_source_id = str(record.source_id) if record.source_id else None
        if payload_source.get("id") != expected_source_id:
            errors.append(f"source_reference_mismatch:{record.sequence}")
        if record.source_label != payload_source.get("label", ""):
            errors.append(f"source_label_mismatch:{record.sequence}")
        if record.source_url != payload_source.get("url", ""):
            errors.append(f"source_url_mismatch:{record.sequence}")

        captured_at_text = record.captured_at.isoformat()
        calculated_hash = _record_hash(
            run_id=str(run.id),
            sequence=record.sequence,
            schema_version=record.schema_version,
            captured_at=captured_at_text,
            payload_sha256=calculated_payload_hash,
            previous_hash=expected_previous,
        )
        if calculated_hash != record.record_hash:
            errors.append(f"record_hash_mismatch:{record.sequence}")

        calculated_record_hashes.append(calculated_hash)
        expected_previous = calculated_hash

    calculated_root = merkle_root(calculated_record_hashes)
    if calculated_root != run.evidence_root_hash:
        errors.append("merkle_root_mismatch")

    return {
        "status": "valid" if not errors else "invalid",
        "valid": not errors,
        "record_count": len(records),
        "stored_merkle_root": run.evidence_root_hash,
        "calculated_merkle_root": calculated_root,
        "errors": errors,
    }
