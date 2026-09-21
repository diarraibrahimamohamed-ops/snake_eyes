"""AfricaWatch — API Tests"""
import pytest
from django.utils import timezone


class TestAuth:
    def test_login_success(self, client, admin_user):
        resp = client.post("/api/v1/auth/token/", {"email":"admin@test.aw","password":"TestPassword@123!"}, content_type="application/json")
        assert resp.status_code == 200
        data = resp.json()
        assert "access" in data
        assert "refresh" in data
        assert "user" in data

    def test_login_wrong_password(self, client, admin_user):
        resp = client.post("/api/v1/auth/token/", {"email":"admin@test.aw","password":"wrongpassword"}, content_type="application/json")
        assert resp.status_code in [400, 401]

    def test_unauthorized_access(self, client):
        resp = client.get("/api/v1/iocs/")
        assert resp.status_code == 401


class TestIOCAPI:
    def test_list_iocs(self, api_client, sample_ioc):
        resp = api_client.get("/api/v1/iocs/")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    def test_ioc_stats(self, api_client, sample_ioc):
        resp = api_client.get("/api/v1/iocs/stats/")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "african_threats" in data
        assert "by_type" in data

    def test_ioc_lookup_found(self, api_client, sample_ioc):
        resp = api_client.get("/api/v1/iocs/lookup/", {"value": "197.234.45.123"})
        assert resp.status_code == 200
        assert resp.json()["found"] is True

    def test_ioc_lookup_not_found(self, api_client):
        resp = api_client.get("/api/v1/iocs/lookup/", {"value": "1.2.3.4"})
        assert resp.status_code == 200
        assert resp.json()["found"] is False

    def test_create_ioc(self, api_client):
        now = timezone.now().isoformat()
        resp = api_client.post("/api/v1/iocs/", {
            "ioc_type": "domain", "value": "evil.example.com",
            "severity": "high", "confidence": 75,
            "first_seen": now, "last_seen": now,
        }, format="json")
        assert resp.status_code == 201

    def test_bulk_import(self, api_client):
        now = timezone.now().isoformat()
        iocs = [{"ioc_type":"ip","value":f"10.0.0.{i}","severity":"medium",
                 "confidence":60,"first_seen":now,"last_seen":now} for i in range(1,6)]
        resp = api_client.post("/api/v1/iocs/bulk-import/", {"iocs":iocs}, format="json")
        assert resp.status_code == 201
        assert resp.json()["created"] == 5

    def test_mark_false_positive(self, api_client, sample_ioc):
        resp = api_client.post(f"/api/v1/iocs/{sample_ioc.id}/false-positive/")
        assert resp.status_code == 200
        sample_ioc.refresh_from_db()
        assert sample_ioc.false_positive_count == 1

    def test_filter_african_threats(self, api_client, sample_ioc):
        resp = api_client.get("/api/v1/iocs/", {"is_african_threat": True})
        assert resp.status_code == 200
        for ioc in resp.json()["results"]:
            assert ioc["is_african_threat"] is True


class TestAlertAPI:
    def test_list_alerts(self, api_client, sample_alert):
        resp = api_client.get("/api/v1/alerts/")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    def test_alert_stats(self, api_client, sample_alert):
        resp = api_client.get("/api/v1/alerts/stats/")
        assert resp.status_code == 200
        assert "total" in resp.json()

    def test_acknowledge_alert(self, api_client, sample_alert):
        resp = api_client.post(f"/api/v1/alerts/{sample_alert.id}/acknowledge/")
        assert resp.status_code == 200
        sample_alert.refresh_from_db()
        assert sample_alert.status == "acknowledged"

    def test_escalate_alert(self, api_client, sample_alert):
        resp = api_client.post(f"/api/v1/alerts/{sample_alert.id}/escalate/",
                               {"incident_title": "Test Incident"}, format="json")
        assert resp.status_code == 201
        assert "incident_id" in resp.json()


class TestOrganizationAPI:
    def test_get_me(self, api_client, admin_user):
        resp = api_client.get("/api/v1/users/me/")
        assert resp.status_code == 200
        assert resp.json()["email"] == admin_user.email

    def test_patch_me(self, api_client, admin_user):
        resp = api_client.patch("/api/v1/users/me/", {"bio": "SOC Analyst"}, format="json")
        assert resp.status_code == 200
        assert resp.json()["bio"] == "SOC Analyst"

    def test_list_organizations(self, api_client, org):
        resp = api_client.get("/api/v1/organizations/")
        assert resp.status_code == 200


class TestDashboardAPI:
    def test_global_stats(self, api_client):
        resp = api_client.get("/api/v1/dashboard/stats/")
        assert resp.status_code == 200
        data = resp.json()
        assert "threat_intelligence" in data
        assert "soc" in data
        assert "threat_score" in data

    def test_recent_activity(self, api_client):
        resp = api_client.get("/api/v1/dashboard/activity/")
        assert resp.status_code == 200
        data = resp.json()
        assert "iocs" in data
        assert "alerts" in data

    def test_threat_map(self, api_client):
        resp = api_client.get("/api/v1/dashboard/threat-map/")
        assert resp.status_code == 200


class TestHealthCheck:
    def test_health(self, client):
        resp = client.get("/health/")
        assert resp.status_code in [200, 503]
        assert "status" in resp.json()
        assert "checks" in resp.json()

    def test_liveness(self, client):
        resp = client.get("/health/live/")
        assert resp.status_code == 200

    def test_readiness(self, client):
        resp = client.get("/health/ready/")
        assert resp.status_code == 200


class TestFeedAPI:
    def test_list_feeds(self, api_client, sample_feed):
        resp = api_client.get("/api/v1/feeds/")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    def test_create_feed(self, api_client):
        resp = api_client.post("/api/v1/feeds/", {
            "name": "New Test Feed", "feed_type": "plaintext",
            "url": "https://example.com/test.txt",
            "is_public": True, "is_african_specific": False,
            "fetch_frequency_hours": 6, "tlp_level": "white",
        }, format="json")
        assert resp.status_code == 201
