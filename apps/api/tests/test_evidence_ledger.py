import pytest
from django.core.exceptions import ValidationError

from africanwatch.apps.intelligence.evidence import (
    build_run_manifest,
    merkle_root,
    record_observation_evidence,
    verify_manifest,
)
from africanwatch.apps.intelligence.models import (
    CollectionRun,
    CollectionSource,
    CollectionTarget,
    EvidenceRecord,
    IntelligenceObservation,
    IntelligenceRelation,
)
from africanwatch.apps.intelligence.services import save_observation, _correlate_observations


def make_run(org, suffix="one"):
    target = CollectionTarget.objects.create(
        organization=org,
        kind=CollectionTarget.Kind.DOMAIN,
        value=f"{suffix}.example.test",
        authorization_reference=f"TEST-AUTH-{suffix.upper()}",
        allowed=True,
    )
    return CollectionRun.objects.create(organization=org, target=target)


def make_observation(org, run, *, source=None, iocs=None, source_label="test-provider", content="Ransomware advisory"):
    return IntelligenceObservation.objects.create(
        organization=org,
        run=run,
        source=source,
        source_label=source.name if source else source_label,
        source_url=source.url if source else "https://intel.example.test/advisory",
        title="Test advisory",
        content=content,
        language="fr",
        content_sha256=("a" if not iocs else "b") * 64,
        evidence_grade="C",
        source_reliability=source.reliability if source else 0.5,
        confidence=0.5,
        relevance=0.5,
        classification={"categories": [{"name": "cyber_threat", "hits": 1}]},
        entities={},
        iocs=iocs or [],
        provenance={"collector": "test"},
    )


class TestMerklePrimitives:
    def test_merkle_root_is_deterministic_and_changes_with_a_leaf(self):
        hashes = ["a" * 64, "b" * 64, "c" * 64]
        first = merkle_root(hashes)
        assert first == merkle_root(list(hashes))
        assert len(first) == 64
        assert first != merkle_root(["a" * 64, "b" * 64, "d" * 64])

    def test_empty_merkle_root_is_defined(self):
        assert merkle_root([]) == __import__("hashlib").sha256(b"").hexdigest()


@pytest.mark.django_db
def test_evidence_record_is_append_only_and_manifest_detects_payload_tampering(org):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    run = make_run(org)
    observation = make_observation(org, run)
    evidence = record_observation_evidence(
        observation,
        run=run,
        source_label="CERT advisory",
        source_url="https://cert.example.test/advisory/1",
        acquisition_method="test_fixture",
    )

    with pytest.raises(ValidationError):
        evidence.save()

    signer = Ed25519PrivateKey.generate()
    manifest = build_run_manifest(run, signing_key=signer, signing_key_id="test-key-1")
    assert manifest is not None
    assert manifest.evidence_count == 1
    assert manifest.signature_algorithm == "Ed25519"
    assert verify_manifest(manifest)["valid"] is False  # signed manifests require the public verification key
    verified = verify_manifest(manifest, signer.public_key())
    assert verified["valid"] is True
    assert verified["signature_valid"] is True

    EvidenceRecord.objects.filter(pk=evidence.pk).update(payload={"tampered": True})
    tampered = verify_manifest(manifest, signer.public_key())
    assert tampered["valid"] is False
    assert tampered["payloads_valid"] is False


@pytest.mark.django_db
def test_repeat_retrieval_creates_new_acquisition_evidence_without_false_corroboration(org):
    first_run = make_run(org, "first")
    second_run = make_run(org, "second")
    configured_source = CollectionSource.objects.create(
        organization=org,
        name="CERT-X",
        kind=CollectionSource.Kind.CERT,
        url="https://cert.example.test/advisory/42",
        reliability=0.9,
    )

    first_observation, first_created = save_observation(
        first_run,
        configured_source,
        "CERT advisory",
        "Ransomware advisory for a test environment",
        url="https://cert.example.test/advisory/42",
        provider_label="CERT-X",
        acquisition_method="configured_rss",
    )
    second_observation, second_created = save_observation(
        second_run,
        None,
        "CERT advisory",
        "Ransomware advisory for a test environment",
        url="https://cert.example.test/advisory/42",
        provider_label="RDAP provider",
        acquisition_method="built_in_passive_collector",
    )

    assert first_created is True
    assert second_created is False
    assert first_observation.id == second_observation.id
    assert EvidenceRecord.objects.filter(observation=first_observation).count() == 2
    second_evidence = EvidenceRecord.objects.get(run=second_run)
    assert second_evidence.source is None
    assert second_evidence.source_label == "RDAP provider"
    first_observation.refresh_from_db()
    assert first_observation.corroboration_count == 0


@pytest.mark.django_db
def test_correlation_requires_shared_ioc_and_counts_distinct_sources(org):
    run = make_run(org, "correlation")
    source_a = CollectionSource.objects.create(
        organization=org, name="CERT A", kind=CollectionSource.Kind.CERT,
        url="https://cert-a.example.test/feed", reliability=0.9,
    )
    source_b = CollectionSource.objects.create(
        organization=org, name="CERT B", kind=CollectionSource.Kind.CERT,
        url="https://cert-b.example.test/feed", reliability=0.9,
    )
    source_c = CollectionSource.objects.create(
        organization=org, name="CERT C", kind=CollectionSource.Kind.CERT,
        url="https://cert-c.example.test/feed", reliability=0.9,
    )

    shared_ioc = [{"type": "domain", "value": "c2.example.test"}]
    row_a = make_observation(org, run, source=source_a, iocs=shared_ioc, content="A")
    row_b = make_observation(org, run, source=source_b, iocs=shared_ioc, content="B")
    row_c = make_observation(org, run, source=source_c, iocs=[], content="C")

    _correlate_observations(run, [row_a.id.hex, row_b.id.hex, row_c.id.hex])

    assert IntelligenceRelation.objects.filter(
        organization=org, left=row_a, right=row_b, relation_type="shared_ioc"
    ).count() == 1
    assert IntelligenceRelation.objects.count() == 1
    row_a.refresh_from_db()
    row_b.refresh_from_db()
    row_c.refresh_from_db()
    assert row_a.corroboration_count == 1
    assert row_b.corroboration_count == 1
    assert row_c.corroboration_count == 0


@pytest.mark.django_db
def test_evidence_endpoints_are_readable_by_authorized_tenant_user(org, api_client):
    run = make_run(org, "api")
    observation = make_observation(org, run)
    record_observation_evidence(observation, run=run, acquisition_method="test_api")
    manifest = build_run_manifest(run)
    assert manifest is not None

    records_response = api_client.get("/api/v1/evidence-records/")
    manifests_response = api_client.get("/api/v1/evidence-manifests/")

    assert records_response.status_code == 200
    assert manifests_response.status_code == 200
    assert records_response.data["count"] == 1
    assert manifests_response.data["count"] == 1
