"""API access-control tests for intelligence evidence records."""
import pytest

from africanwatch.apps.intelligence.models import (
    CollectionRun,
    CollectionSource,
    CollectionTarget,
)
from africanwatch.apps.intelligence.services import save_observation
from africanwatch.apps.organizations.models import Organization


def _create_evidence_run(org, suffix):
    target = CollectionTarget.objects.create(
        organization=org,
        kind=CollectionTarget.Kind.DOMAIN,
        value=f"{suffix}.example.test",
        authorization_reference=f"AUTH-{suffix}",
        allowed=True,
    )
    source = CollectionSource.objects.create(
        organization=org,
        name=f"{suffix} CERT feed",
        kind=CollectionSource.Kind.RSS,
        url=f"https://{suffix}.example.test/feed.xml",
    )
    run = CollectionRun.objects.create(organization=org, target=target)
    run.sources.add(source)
    save_observation(
        run,
        source,
        f"{suffix} advisory",
        "Credential phishing IOC at login.example.test",
        url=f"https://{suffix}.example.test/advisories/1",
    )
    return run


@pytest.mark.django_db
def test_evidence_api_honors_organization_tlp_clearance(api_client, org):
    run = _create_evidence_run(org, "tlp")
    observation = run.observations.first()
    source = run.sources.first()
    observation.tlp = "red"
    observation.save(update_fields=["tlp", "updated_at"])

    # A second capture snapshots the newly assigned TLP:RED classification.
    save_observation(
        run,
        source,
        "tlp advisory",
        "Credential phishing IOC at login.example.test",
        url="https://tlp.example.test/advisories/1",
    )

    response = api_client.get(
        "/api/v1/intelligence-evidence/", {"run": str(run.id)}
    )
    assert response.status_code == 200
    rows = response.data["results"] if isinstance(response.data, dict) and "results" in response.data else response.data
    assert len(rows) == 1
    assert rows[0]["payload"]["observation"]["tlp"] == "green"


@pytest.mark.django_db
def test_evidence_api_lists_tenant_records_and_verifies_scoped_run(api_client, org):
    own_run = _create_evidence_run(org, "own")
    foreign_org = Organization.objects.create(
        name="Foreign CERT",
        slug="foreign-cert-evidence",
        org_type="cert",
        country="SEN",
        country_name="Senegal",
        contact_email="foreign-evidence@example.test",
    )
    foreign_run = _create_evidence_run(foreign_org, "foreign")

    response = api_client.get("/api/v1/intelligence-evidence/")
    assert response.status_code == 200, response.data
    rows = response.data["results"] if isinstance(response.data, dict) and "results" in response.data else response.data
    visible_run_ids = {str(row["run"]) for row in rows}
    assert str(own_run.id) in visible_run_ids
    assert str(foreign_run.id) not in visible_run_ids

    filtered = api_client.get(
        "/api/v1/intelligence-evidence/", {"run": str(own_run.id)}
    )
    assert filtered.status_code == 200
    filtered_rows = filtered.data["results"] if isinstance(filtered.data, dict) and "results" in filtered.data else filtered.data
    assert len(filtered_rows) == 1
    assert str(filtered_rows[0]["run"]) == str(own_run.id)

    verification = api_client.get(
        f"/api/v1/collection-runs/{own_run.id}/verify-evidence/"
    )
    assert verification.status_code == 200
    assert verification.data["status"] == "valid"
    assert verification.data["record_count"] == 1

    forbidden_verification = api_client.get(
        f"/api/v1/collection-runs/{foreign_run.id}/verify-evidence/"
    )
    assert forbidden_verification.status_code == 404
