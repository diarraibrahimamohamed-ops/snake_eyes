"""Evidence capture, canonical hashing and verifiable Merkle manifests.

The application layer prevents ordinary updates/deletes. A database owner can
still bypass Django model guards; use independent signed anchors for stronger
tamper evidence and operational separation.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import date, datetime
from typing import Any

from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from .models import EvidenceManifest, EvidenceRecord


HASH_ALGORITHM = "SHA-256"
MERKLE_ALGORITHM = "sha256-0x00-leaf-0x01-node-duplicate-last-v1"


def _json_default(value: Any) -> str:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    raise TypeError(f"Unsupported value in canonical evidence payload: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON deterministically; reject NaN/Infinity and unsupported values."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=_json_default,
    ).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def payload_digest(payload: dict[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(payload))


def merkle_root(payload_hashes: list[str]) -> str:
    """Compute a domain-separated Merkle root from SHA-256 payload digests.

    Leaves are SHA256(0x00 || digest_bytes); internal nodes are
    SHA256(0x01 || left || right). The final node is duplicated at each odd
    level. Empty manifests use SHA256(empty).
    """
    if not payload_hashes:
        return sha256_hex(b"")

    level = []
    for digest in payload_hashes:
        if len(digest) != 64:
            raise ValueError("Every evidence digest must be a 64-character SHA-256 hex string.")
        try:
            digest_bytes = bytes.fromhex(digest)
        except ValueError as exc:
            raise ValueError("Evidence digest is not valid hexadecimal.") from exc
        if len(digest_bytes) != 32:
            raise ValueError("Every evidence digest must represent exactly 32 bytes.")
        level.append(hashlib.sha256(b"\x00" + digest_bytes).digest())

    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(b"\x01" + level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0].hex()


def record_observation_evidence(observation, acquisition_method: str = "passive_collection") -> EvidenceRecord:
    """Freeze the normalized observation and its provenance at acquisition time."""
    source = observation.source
    source_label = observation.source_label or (source.name if source else "Internal collector")
    payload = {
        "schema_version": 1,
        "organization_id": str(observation.organization_id),
        "collection_run_id": str(observation.run_id) if observation.run_id else None,
        "observation_id": str(observation.id),
        "source": {
            "configured_source_id": str(source.id) if source else None,
            "label": source_label,
            "url": observation.source_url or "",
        },
        "timestamps": {
            "published_at": observation.published_at.isoformat() if observation.published_at else None,
            "captured_at": observation.retrieved_at.isoformat(),
            "first_seen": observation.first_seen.isoformat() if observation.first_seen else None,
            "last_seen": observation.last_seen.isoformat() if observation.last_seen else None,
        },
        "content": {
            "title": observation.title,
            "body": observation.content,
            "iocs": observation.iocs or [],
            "classification": observation.classification or {},
            "entities": observation.entities or {},
        },
        "provenance": observation.provenance or {},
        "content_sha256": observation.content_sha256,
        "evidence_grade_at_capture": observation.evidence_grade,
        "source_reliability_at_capture": observation.source_reliability,
        "confidence_at_capture": observation.confidence,
        "tlp": observation.tlp,
    }
    return EvidenceRecord.objects.create(
        organization=observation.organization,
        run=observation.run,
        observation=observation,
        source=source,
        source_label=source_label,
        source_url=observation.source_url or "",
        acquisition_method=acquisition_method,
        captured_at=observation.retrieved_at,
        tlp=observation.tlp,
        payload=payload,
        payload_sha256=payload_digest(payload),
    )


def _manifest_signing_bytes(run_id: str, version: int, entries: list[dict[str, str]], root_hash: str) -> bytes:
    return canonical_json_bytes({
        "schema_version": 1,
        "run_id": run_id,
        "version": version,
        "hash_algorithm": HASH_ALGORITHM,
        "merkle_algorithm": MERKLE_ALGORITHM,
        "evidence_count": len(entries),
        "entries": entries,
        "root_hash": root_hash,
    })


@transaction.atomic
def build_run_manifest(run, signing_key=None, signing_key_id: str = "", generated_by=None) -> EvidenceManifest | None:
    """Append a new manifest version for every evidence record attached to a run."""
    records = list(
        EvidenceRecord.objects.filter(organization=run.organization, run=run)
        .order_by("id")
    )
    if not records:
        return None

    entries = [
        {"evidence_id": str(record.id), "payload_sha256": record.payload_sha256}
        for record in records
    ]
    root_hash = merkle_root([entry["payload_sha256"] for entry in entries])
    previous_version = EvidenceManifest.objects.filter(run=run).aggregate(value=Max("version"))["value"] or 0
    version = previous_version + 1

    signature = ""
    signature_algorithm = "none"
    if signing_key is not None:
        signature = base64.b64encode(
            signing_key.sign(_manifest_signing_bytes(str(run.id), version, entries, root_hash))
        ).decode("ascii")
        signature_algorithm = "Ed25519"

    return EvidenceManifest.objects.create(
        organization=run.organization,
        run=run,
        version=version,
        hash_algorithm=HASH_ALGORITHM,
        merkle_algorithm=MERKLE_ALGORITHM,
        evidence_count=len(entries),
        root_hash=root_hash,
        entries=entries,
        signature_algorithm=signature_algorithm,
        signature=signature,
        signing_key_id=signing_key_id,
        generated_by=generated_by,
    )


def verify_manifest(manifest: EvidenceManifest, public_key=None) -> dict[str, Any]:
    """Verify payload hashes, manifest membership, Merkle root and optional signature."""
    records_by_id = {
        str(record.id): record
        for record in EvidenceRecord.objects.filter(
            organization=manifest.organization,
            id__in=[entry.get("evidence_id") for entry in manifest.entries],
        )
    }
    payloads_valid = len(records_by_id) == manifest.evidence_count == len(manifest.entries)
    digests: list[str] = []
    for entry in manifest.entries:
        record = records_by_id.get(entry.get("evidence_id", ""))
        if record is None:
            payloads_valid = False
            continue
        try:
            calculated = payload_digest(record.payload)
        except (TypeError, ValueError):
            calculated = ""
        if calculated != entry.get("payload_sha256") or calculated != record.payload_sha256:
            payloads_valid = False
        digests.append(entry.get("payload_sha256", ""))

    calculated_root = merkle_root(digests) if len(digests) == len(manifest.entries) else ""
    root_valid = calculated_root == manifest.root_hash
    signature_valid = None
    if public_key is not None:
        signature_valid = False
        if manifest.signature and manifest.signature_algorithm == "Ed25519":
            try:
                public_key.verify(
                    base64.b64decode(manifest.signature, validate=True),
                    _manifest_signing_bytes(str(manifest.run_id), manifest.version, manifest.entries, manifest.root_hash),
                )
                signature_valid = True
            except Exception:
                signature_valid = False

    return {
        "valid": bool(payloads_valid and root_valid and (signature_valid is not False)),
        "payloads_valid": payloads_valid,
        "root_valid": root_valid,
        "signature_valid": signature_valid,
        "evidence_count": manifest.evidence_count,
        "expected_root": manifest.root_hash,
        "calculated_root": calculated_root,
    }
