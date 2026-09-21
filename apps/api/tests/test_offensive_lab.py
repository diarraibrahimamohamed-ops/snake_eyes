import pytest
from datetime import timedelta
from unittest.mock import patch
from django.utils import timezone

from africanwatch.apps.offensive_lab.models import Engagement, EngagementTarget
from africanwatch.apps.organizations.models import Asset
from africanwatch.security.outbound import validate_scan_target


@pytest.mark.django_db
def test_private_scan_target_blocked_by_default(settings):
    settings.LAB_MODE = False
    with pytest.raises(ValueError):
        validate_scan_target("127.0.0.1")


@pytest.mark.django_db
def test_private_scan_target_allowed_only_in_lab(settings):
    settings.LAB_MODE = True
    assert validate_scan_target("127.0.0.1", allow_private=True) == "127.0.0.1"


@pytest.fixture
def asset(db, org):
    return Asset.objects.create(
        organization=org, name="example", asset_type="domain", value="example.com",
    )


@pytest.mark.django_db
def test_engagement_scope_hash_and_launch_gate(api_client, admin_user, org, asset):
    engagement = Engagement.objects.create(
        organization=org, name="Quarterly assessment", authorization_reference="AUTH-2026-001",
        starts_at=timezone.now() - timedelta(minutes=1), ends_at=timezone.now() + timedelta(hours=2),
    )
    target = EngagementTarget.objects.create(engagement=engagement, asset=asset)

    blocked = api_client.post(f"/api/v1/engagements/{engagement.id}/launch/", {"profile": "port_recon"}, format="json")
    assert blocked.status_code == 409

    approved = api_client.post(f"/api/v1/engagements/{engagement.id}/approve/")
    assert approved.status_code == 200
    engagement.refresh_from_db()
    assert engagement.approved is True
    assert len(engagement.scope_hash) == 64

    with patch("africanwatch.apps.offensive_lab.tasks.run_assessment") as task:
        task.delay.return_value.id = "task-1"
        launched = api_client.post(
            f"/api/v1/engagements/{engagement.id}/launch/",
            {"profile": "dns_recon", "target_id": str(target.id)}, format="json",
        )
    assert launched.status_code == 202
    assert launched.json()["status"] == "queued"


@pytest.mark.django_db
def test_self_profile_cannot_escalate(api_client, admin_user):
    response = api_client.patch("/api/v1/users/me/", {"role": "super_admin", "organization": None}, format="json")
    assert response.status_code == 200
    admin_user.refresh_from_db()
    assert admin_user.role == "org_admin"


@pytest.mark.django_db
def test_asset_cannot_cross_tenant(api_client, org):
    from africanwatch.apps.organizations.models import Organization
    other = Organization.objects.create(
        name="Other CERT", slug="other-cert", org_type="cert", country="SEN",
        country_name="Senegal", contact_email="other@example.com",
    )
    response = api_client.post("/api/v1/assets/", {
        "organization": str(other.id), "name": "foreign", "asset_type": "domain", "value": "example.org",
    }, format="json")
    assert response.status_code in (400, 403)

@pytest.mark.django_db
def test_scope_change_invalidates_approval(api_client, admin_user, org, asset):
    engagement = Engagement.objects.create(
        organization=org, name="Scope-change", authorization_reference="AUTH-SCOPE",
        starts_at=timezone.now() - timedelta(minutes=1), ends_at=timezone.now() + timedelta(hours=1),
    )
    EngagementTarget.objects.create(engagement=engagement, asset=asset)
    approved = api_client.post(f"/api/v1/engagements/{engagement.id}/approve/")
    assert approved.status_code == 200
    target = engagement.targets.first()
    target.enabled = False
    target.save()
    engagement.refresh_from_db()
    # Updating/deleting the registered scope must invalidate the previous approval.
    api_client.patch(f"/api/v1/engagement-targets/{target.id}/", {"enabled": True}, format="json")
    engagement.refresh_from_db()
    assert engagement.approved is False
    assert engagement.status == Engagement.Status.DRAFT


@pytest.mark.django_db
def test_private_url_requires_global_lab_mode(settings, monkeypatch):
    settings.LAB_MODE = False
    from africanwatch.security.outbound import validate_scan_target
    with pytest.raises(ValueError):
        validate_scan_target("http://127.0.0.1:8080", allow_private=True)
    settings.LAB_MODE = True
    assert validate_scan_target("http://127.0.0.1:8080", allow_private=True) == "http://127.0.0.1:8080"


@pytest.mark.django_db
def test_assessment_report_is_tenant_scoped(api_client, org, asset):
    engagement = Engagement.objects.create(
        organization=org, name="Report", authorization_reference="AUTH-REPORT",
        starts_at=timezone.now() - timedelta(minutes=1), ends_at=timezone.now() + timedelta(hours=1),
    )
    target = EngagementTarget.objects.create(engagement=engagement, asset=asset)
    from africanwatch.apps.offensive_lab.models import AssessmentJob, AssessmentFinding, AssessmentEvent
    job = AssessmentJob.objects.create(
        engagement=engagement, target=target, profile="dns_recon", status="completed",
        scope_hash_at_launch="x" * 64, result_sha256="y" * 64,
    )
    AssessmentFinding.objects.create(job=job, fingerprint="a" * 64, severity="medium", category="test", title="Finding")
    AssessmentEvent.objects.create(job=job, event_type="started", payload={}, previous_hash="", event_hash="0" * 64)
    resp = api_client.get(f"/api/v1/assessment-jobs/{job.id}/report/")
    assert resp.status_code == 200
    assert "summary" in resp.json()
    assert resp.json()["summary"]["event_chain_valid"] is False
