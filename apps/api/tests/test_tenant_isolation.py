"""Regression tests for tenant boundaries across inventory, SOC and threat intelligence."""
import pytest
from django.core.cache import cache
from django.utils import timezone
from rest_framework.test import APIClient

from africanwatch.apps.organizations.models import Asset, AuditLog, Organization, User
from africanwatch.apps.soc.models import Alert, Incident
from africanwatch.apps.threat_intel.models import Campaign, IOC, ThreatActor, ThreatFeed


def _items(response):
    data = response.data
    if isinstance(data, dict) and "results" in data:
        return data["results"]
    return data


def _other_org():
    return Organization.objects.create(
        name="Other Tenant",
        slug="other-tenant",
        org_type="cert",
        country="MLI",
        country_name="Mali",
        contact_email="other@example.test",
        tlp_level="red",
    )


def _ioc(value, tlp_level, org=None, feed=None):
    now = timezone.now()
    return IOC.objects.create(
        ioc_type=IOC.IOCType.IP,
        value=value,
        value_normalized=value,
        severity=IOC.Severity.HIGH,
        confidence=80,
        tlp_level=tlp_level,
        source_organization=org,
        feed=feed,
        first_seen=now,
        last_seen=now,
    )


@pytest.mark.django_db
def test_user_without_organization_sees_no_tenant_owned_collections(
    api_client, org, admin_user, sample_alert, sample_ioc, sample_feed
):
    Asset.objects.create(
        organization=org, name="Tenant asset", asset_type="domain", value="tenant.example.test"
    )
    AuditLog.objects.create(
        user=admin_user, organization=org, action=AuditLog.Action.API_CALL, success=True
    )
    Incident.objects.create(
        organization=org,
        title="Tenant incident",
        description="Private incident",
        severity=Incident.Severity.HIGH,
        detected_at=timezone.now(),
    )
    Campaign.objects.create(
        name="Tenant-visible campaign", description="TLP green", tlp_level="green"
    )
    unassigned = User.objects.create_user(
        email="unassigned@example.test",
        password="TestPassword@123!",
        first_name="No",
        last_name="Organization",
        organization=None,
        role=User.Role.VIEWER,
    )
    api_client.force_authenticate(user=unassigned)

    for endpoint in (
        "/api/v1/assets/",
        "/api/v1/audit-logs/",
        "/api/v1/alerts/",
        "/api/v1/incidents/",
        "/api/v1/iocs/",
        "/api/v1/feeds/",
        "/api/v1/campaigns/",
    ):
        response = api_client.get(endpoint)
        assert response.status_code == 200, (endpoint, response.data)
        assert _items(response) == [], (endpoint, response.data)


@pytest.mark.django_db
def test_tenant_inventory_and_soc_lists_do_not_include_other_organization(
    api_client, org, admin_user, sample_alert
):
    other_org = _other_org()
    own_asset = Asset.objects.create(
        organization=org, name="Own asset", asset_type="domain", value="own.example.test"
    )
    foreign_asset = Asset.objects.create(
        organization=other_org, name="Foreign asset", asset_type="domain", value="foreign.example.test"
    )
    foreign_alert = Alert.objects.create(
        organization=other_org,
        title="Foreign alert",
        description="Must not be visible",
        severity=Alert.Severity.CRITICAL,
        source=Alert.Source.MANUAL,
    )
    foreign_incident = Incident.objects.create(
        organization=other_org,
        title="Foreign incident",
        description="Must not be visible",
        severity=Incident.Severity.CRITICAL,
        detected_at=timezone.now(),
    )
    AuditLog.objects.create(
        user=admin_user, organization=org, action=AuditLog.Action.API_CALL, success=True
    )
    AuditLog.objects.create(
        organization=other_org, action=AuditLog.Action.API_CALL, success=True
    )

    response = api_client.get("/api/v1/assets/")
    assert response.status_code == 200
    assets = _items(response)
    asset_ids = {str(row["id"]) for row in assets}
    assert str(own_asset.id) in asset_ids
    assert str(foreign_asset.id) not in asset_ids

    response = api_client.get("/api/v1/alerts/")
    assert response.status_code == 200
    assert str(foreign_alert.id) not in {str(row["id"]) for row in _items(response)}

    response = api_client.get("/api/v1/incidents/")
    assert response.status_code == 200
    assert str(foreign_incident.id) not in {str(row["id"]) for row in _items(response)}

    response = api_client.get("/api/v1/audit-logs/")
    assert response.status_code == 200
    audit_rows = _items(response)
    assert len(audit_rows) == 1
    assert str(audit_rows[0]["user"]) == str(admin_user.id)


@pytest.mark.django_db
def test_tlp_clearance_filters_iocs_feeds_and_campaigns(
    api_client, org, sample_ioc, sample_feed
):
    org.tlp_level = Organization.TLPLevel.GREEN
    org.save(update_fields=["tlp_level", "updated_at"])
    white_ioc = _ioc("198.51.100.44", "white", feed=sample_feed)
    red_ioc = _ioc("198.51.100.45", "red", feed=sample_feed)
    public_red_feed = ThreatFeed.objects.create(
        name="Restricted red feed",
        feed_type=ThreatFeed.FeedType.PLAINTEXT,
        url="https://feed.example.test/red.txt",
        is_public=True,
        tlp_level="red",
    )
    private_white_feed = ThreatFeed.objects.create(
        name="Private white feed",
        feed_type=ThreatFeed.FeedType.PLAINTEXT,
        url="https://feed.example.test/private.txt",
        is_public=False,
        tlp_level="white",
    )
    actor = ThreatActor.objects.create(name="Shared actor for TLP regression")
    visible_campaign = Campaign.objects.create(
        name="Visible campaign", description="TLP green", tlp_level="green", threat_actor=actor
    )
    hidden_campaign = Campaign.objects.create(
        name="Restricted campaign", description="TLP red", tlp_level="red", threat_actor=actor
    )

    response = api_client.get("/api/v1/iocs/")
    assert response.status_code == 200
    ioc_ids = {str(row["id"]) for row in _items(response)}
    assert str(sample_ioc.id) in ioc_ids
    assert str(red_ioc.id) not in ioc_ids

    response = api_client.get("/api/v1/feeds/")
    assert response.status_code == 200
    feed_ids = {str(row["id"]) for row in _items(response)}
    assert str(sample_feed.id) in feed_ids
    assert str(public_red_feed.id) not in feed_ids
    assert str(private_white_feed.id) not in feed_ids

    response = api_client.get("/api/v1/campaigns/")
    assert response.status_code == 200
    campaign_ids = {str(row["id"]) for row in _items(response)}
    assert str(visible_campaign.id) in campaign_ids
    assert str(hidden_campaign.id) not in campaign_ids

    response = api_client.get(f"/api/v1/feeds/{sample_feed.id}/stats/")
    assert response.status_code == 200
    assert response.data["total_iocs"] == 1
    assert str(white_ioc.id) != str(red_ioc.id)

    response = api_client.get(f"/api/v1/threat-actors/{actor.id}/timeline/")
    assert response.status_code == 200
    timeline_ids = {str(row["id"]) for row in response.data}
    assert str(visible_campaign.id) in timeline_ids
    assert str(hidden_campaign.id) not in timeline_ids


@pytest.mark.django_db
def test_tenant_admin_cannot_mutate_shared_threat_intelligence_or_organizations(api_client):
    responses = [
        api_client.post("/api/v1/feeds/", {}, format="json"),
        api_client.post("/api/v1/iocs/", {}, format="json"),
        api_client.post("/api/v1/threat-actors/", {}, format="json"),
        api_client.post("/api/v1/campaigns/", {}, format="json"),
        api_client.post("/api/v1/organizations/", {}, format="json"),
    ]
    assert [response.status_code for response in responses] == [403, 403, 403, 403, 403]


@pytest.mark.django_db
def test_tenant_admin_cannot_create_soc_records_for_other_organization(api_client, org):
    other_org = _other_org()
    response = api_client.post(
        "/api/v1/alerts/",
        {
            "organization": str(other_org.id),
            "title": "Cross-tenant alert",
            "description": "Must be rejected",
            "severity": "high",
            "source": "manual",
        },
        format="json",
    )
    assert response.status_code == 403

    response = api_client.post(
        "/api/v1/incidents/",
        {
            "organization": str(org.id),
            "title": "Wrong tenant assignee",
            "description": "Must be rejected",
            "severity": "high",
            "detected_at": timezone.now().isoformat(),
            "assigned_to": str(
                User.objects.create_user(
                    email="foreign@example.test",
                    password="TestPassword@123!",
                    first_name="Foreign",
                    last_name="Assignee",
                    organization=other_org,
                    role=User.Role.ANALYST,
                ).id
            ),
        },
        format="json",
    )
    assert response.status_code == 403


@pytest.mark.django_db
def test_dashboard_metrics_and_cache_are_organization_scoped(api_client, org, sample_alert):
    other_org = _other_org()
    Alert.objects.create(
        organization=other_org,
        title="Other tenant alert",
        description="Must not affect this tenant's dashboard",
        severity=Alert.Severity.CRITICAL,
        source=Alert.Source.MANUAL,
    )
    cache.clear()

    response = api_client.get("/api/v1/dashboard/stats/")
    assert response.status_code == 200
    assert response.data["soc"]["alerts_open"] == 1
    assert response.data["infrastructure"]["organizations"] == 1

    response = api_client.get("/api/v1/dashboard/activity/")
    assert response.status_code == 200
    assert all(row.get("title") != "Other tenant alert" for row in response.data["alerts"])

    response = api_client.get("/api/v1/dashboard/soc-metrics/")
    assert response.status_code == 200
    assert response.data["alerts_open"] == 1


@pytest.mark.django_db
def test_unassigned_user_cannot_summarize_another_organizations_incident(api_client, org):
    incident = Incident.objects.create(
        organization=org,
        title="Private incident",
        description="Restricted to the owning tenant",
        severity=Incident.Severity.HIGH,
        detected_at=timezone.now(),
    )
    unassigned = User.objects.create_user(
        email="unassigned-summary@example.test",
        password="TestPassword@123!",
        first_name="No",
        last_name="Tenant",
        organization=None,
        role=User.Role.VIEWER,
    )
    api_client.force_authenticate(user=unassigned)
    response = api_client.post(
        "/api/v1/ai/summarize-incident/",
        {"incident_id": str(incident.id)},
        format="json",
    )
    assert response.status_code == 404

    response = api_client.get("/api/v1/ai/threat-prediction/")
    assert response.status_code == 200
    assert response.data["trending_threats"] == []
    assert response.data["observation_count_7d"] == 0
