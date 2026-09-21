"""AfricaWatch — Test Fixtures"""
import pytest
from django.utils import timezone


@pytest.fixture
def org(db):
    from africanwatch.apps.organizations.models import Organization
    return Organization.objects.create(
        name="CERT-Test", slug="cert-test", org_type="cert",
        country="MLI", country_name="Mali", contact_email="test@cert.ml",
    )

@pytest.fixture
def admin_user(db, org):
    from africanwatch.apps.organizations.models import User
    user = User.objects.create_user(
        email="admin@test.aw", password="TestPassword@123!",
        first_name="Test", last_name="Admin",
        organization=org, role="org_admin",
    )
    return user

@pytest.fixture
def api_client(admin_user):
    from rest_framework.test import APIClient
    client = APIClient()
    client.force_authenticate(user=admin_user)
    return client

@pytest.fixture
def sample_ioc(db):
    from africanwatch.apps.threat_intel.models import IOC
    now = timezone.now()
    return IOC.objects.create(
        ioc_type="ip", value="197.234.45.123", value_normalized="197.234.45.123",
        severity="high", confidence=80, first_seen=now, last_seen=now,
        is_african_threat=True, country_code="NG", country_name="Nigeria",
    )

@pytest.fixture
def sample_alert(db, org):
    from africanwatch.apps.soc.models import Alert
    return Alert.objects.create(
        organization=org, title="Test Alert SSH Brute Force",
        description="SSH brute force from malicious IP",
        severity="high", source="wazuh", src_ip="197.234.45.123",
        raw_log={"test": True},
    )

@pytest.fixture
def sample_feed(db):
    from africanwatch.apps.threat_intel.models import ThreatFeed
    return ThreatFeed.objects.create(
        name="Test Feed", feed_type="plaintext",
        url="https://example.com/iocs.txt",
        is_public=True, tlp_level="white",
    )
