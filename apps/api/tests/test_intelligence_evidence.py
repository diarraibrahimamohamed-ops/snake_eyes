"""Regression tests for the append-only intelligence evidence ledger."""
import pytest
from django.core.exceptions import ValidationError
from django.db.models import QuerySet

from africanwatch.apps.intelligence.evidence import merkle_root, verify_run_evidence
from africanwatch.apps.intelligence.models import (
    CollectionRun,
    CollectionSource,
    CollectionTarget,
    IntelligenceEvidence,
)
from africanwatch.apps.intelligence.services import _correlate_observations, save_observation


@pytest.mark.django_db
def test_evidence_append_creates_hash_chain_and_merkle_root(org):
    target = CollectionTarget.objects.create(
        organization=org,
        kind=CollectionTarget.Kind.DOMAIN,
        value="example.test",
        authorization_reference="TEST-AUTH-001",
        allowed=True,
    )
    source = CollectionSource.objects.create(
        organization=org,
        name="CERT test feed",
        kind=CollectionSource.Kind.RSS,
        url="https://cert.example.test/advisories.xml",
        reliability=0.9,
    )
    run = CollectionRun.objects.create(organization=org, target=target)
    run.sources.add(source)

    observation, created = save_observation(
        run,
        source,
        "Test advisory",
        "Ransomware activity observed at 203.0.113.20",
        url="https://cert.example.test/advisories/one",
        raw={"fixture": "first"},
    )

    assert created is True
    records = list(IntelligenceEvidence.objects.filter(run=run).order_by("sequence"))
    assert len(records) == 1
    assert records[0].sequence == 1
    assert records[0].previous_hash == ""
    assert len(records[0].payload_sha256) == 64
    assert len(records[0].record_hash) == 64
    assert run.evidence_root_hash == merkle_root([records[0].record_hash])
    assert verify_run_evidence(run)["status"] == "valid"


@pytest.mark.django_db
def test_repeated_retrieval_is_recorded_but_not_counted_as_independent_corroboration(org):
    target = CollectionTarget.objects.create(
        organization=org,
        kind=CollectionTarget.Kind.DOMAIN,
        value="repeat.example.test",
        authorization_reference="TEST-AUTH-002",
        allowed=True,
    )
    source = CollectionSource.objects.create(
        organization=org,
        name="CERT source",
        kind=CollectionSource.Kind.RSS,
        url="https://cert.example.test/repeat.xml",
        reliability=0.8,
    )
    run = CollectionRun.objects.create(organization=org, target=target)
    run.sources.add(source)

    args = (
        run,
        source,
        "Same advisory",
        "Phishing domain observed at bad.example.test",
    )
    observation, created = save_observation(
        *args, url="https://cert.example.test/advisories/repeat"
    )
    repeated, repeated_created = save_observation(
        *args, url="https://cert.example.test/advisories/repeat"
    )

    assert created is True
    assert repeated_created is False
    assert repeated.pk == observation.pk
    assert IntelligenceEvidence.objects.filter(run=run).count() == 2
    observation.refresh_from_db()
    assert observation.corroboration_count == 0
    assert verify_run_evidence(run)["status"] == "valid"


@pytest.mark.django_db
def test_distinct_registered_sources_count_as_corroboration(org):
    target = CollectionTarget.objects.create(
        organization=org,
        kind=CollectionTarget.Kind.DOMAIN,
        value="corroboration.example.test",
        authorization_reference="TEST-AUTH-003",
        allowed=True,
    )
    source_a = CollectionSource.objects.create(
        organization=org,
        name="CERT A",
        kind=CollectionSource.Kind.RSS,
        url="https://a.example.test/feed.xml",
        reliability=0.8,
    )
    source_b = CollectionSource.objects.create(
        organization=org,
        name="CERT B",
        kind=CollectionSource.Kind.RSS,
        url="https://b.example.test/feed.xml",
        reliability=0.8,
    )
    run = CollectionRun.objects.create(organization=org, target=target)
    run.sources.add(source_a, source_b)

    args = (
        run,
        "Matching advisory",
        "Malware IOC 203.0.113.77",
    )
    observation, _ = save_observation(
        run, source_a, args[1], args[2], url="https://intel.example.test/item/1"
    )
    repeated, _ = save_observation(
        run, source_b, args[1], args[2], url="https://intel.example.test/item/1"
    )

    assert repeated.pk == observation.pk
    observation.refresh_from_db()
    assert observation.corroboration_count == 1
    assert IntelligenceEvidence.objects.filter(run=run).count() == 2


@pytest.mark.django_db
def test_language_similarity_alone_does_not_create_intelligence_relation(org):
    target = CollectionTarget.objects.create(
        organization=org,
        kind=CollectionTarget.Kind.DOMAIN,
        value="relations.example.test",
        authorization_reference="TEST-AUTH-004",
        allowed=True,
    )
    source = CollectionSource.objects.create(
        organization=org,
        name="CERT relations",
        kind=CollectionSource.Kind.RSS,
        url="https://cert.example.test/relations.xml",
    )
    run = CollectionRun.objects.create(organization=org, target=target)
    run.sources.add(source)

    first, _ = save_observation(
        run, source, "First", "Ransomware advisory without an indicator",
        url="https://cert.example.test/1",
    )
    second, _ = save_observation(
        run, source, "Second", "Ransomware advisory with a different report",
        url="https://cert.example.test/2",
    )
    _correlate_observations(run, [str(first.id), str(second.id)])

    from africanwatch.apps.intelligence.models import IntelligenceRelation
    assert IntelligenceRelation.objects.filter(organization=org).count() == 0


@pytest.mark.django_db
def test_evidence_payload_tampering_is_detected(org):
    target = CollectionTarget.objects.create(
        organization=org,
        kind=CollectionTarget.Kind.DOMAIN,
        value="tamper.example.test",
        authorization_reference="TEST-AUTH-005",
        allowed=True,
    )
    source = CollectionSource.objects.create(
        organization=org,
        name="CERT integrity",
        kind=CollectionSource.Kind.RSS,
        url="https://cert.example.test/integrity.xml",
    )
    run = CollectionRun.objects.create(organization=org, target=target)
    run.sources.add(source)
    save_observation(
        run, source, "Integrity test", "A recorded advisory",
        url="https://cert.example.test/integrity/1",
    )

    record = IntelligenceEvidence.objects.get(run=run)
    # Simulate a privileged database-side modification, bypassing the model manager.
    QuerySet.update(
        IntelligenceEvidence.objects.filter(pk=record.pk),
        payload={"schema_version": 1, "observation": {"content_preview": "altered"}},
    )

    result = verify_run_evidence(run)
    assert result["status"] == "invalid"
    assert "payload_hash_mismatch:1" in result["errors"]
    assert "record_hash_mismatch:1" in result["errors"]
    assert "merkle_root_mismatch" in result["errors"]


@pytest.mark.django_db
def test_evidence_records_reject_application_level_mutation_and_deletion(org):
    target = CollectionTarget.objects.create(
        organization=org,
        kind=CollectionTarget.Kind.DOMAIN,
        value="immutable.example.test",
        authorization_reference="TEST-AUTH-006",
        allowed=True,
    )
    source = CollectionSource.objects.create(
        organization=org,
        name="CERT immutable",
        kind=CollectionSource.Kind.RSS,
        url="https://cert.example.test/immutable.xml",
    )
    run = CollectionRun.objects.create(organization=org, target=target)
    run.sources.add(source)
    save_observation(
        run, source, "Immutable test", "The evidence snapshot",
        url="https://cert.example.test/immutable/1",
    )
    record = IntelligenceEvidence.objects.get(run=run)

    with pytest.raises(ValidationError):
        record.save()
    with pytest.raises(ValidationError):
        record.delete()
    with pytest.raises(ValidationError):
        IntelligenceEvidence.objects.filter(pk=record.pk).update(source_label="changed")


def test_merkle_root_is_deterministic_and_empty_for_no_leaves():
    assert merkle_root([]) == ""
    assert merkle_root(["a" * 64]) == merkle_root(["a" * 64])
    assert merkle_root(["a" * 64, "b" * 64, "c" * 64]) == merkle_root(
        ["a" * 64, "b" * 64, "c" * 64]
    )
    assert merkle_root(["a" * 64, "b" * 64]) != merkle_root(
        ["b" * 64, "a" * 64]
    )
