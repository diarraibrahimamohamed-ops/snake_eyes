"""API tests for tenant-scoped scanner report ingestion."""
import hashlib
from unittest.mock import patch

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from africanwatch.apps.organizations.models import Asset, Organization
from africanwatch.apps.vulns.models import ReportIngestion


@pytest.mark.django_db
def test_upload_report_returns_accepted_and_records_hash(api_client, org, admin_user):
    payload = b'{"info":{"name":"Example finding","severity":"medium"},"host":"app.example.test"}'
    upload = SimpleUploadedFile("nuclei.json", payload, content_type="application/json")
    with patch("africanwatch.apps.vulns.report_tasks.process_report_ingestion.delay") as enqueue:
        response = api_client.post(
            "/api/v1/report-ingestions/upload/",
            {"source_type": "nuclei_json", "file": upload},
            format="multipart",
        )
    assert response.status_code == 202
    report = ReportIngestion.objects.get(id=response.data["id"])
    assert report.organization == org
    assert report.uploaded_by == admin_user
    assert report.sha256 == hashlib.sha256(payload).hexdigest()
    assert report.status == ReportIngestion.Status.PENDING
    assert response.data["source_type"] == "nuclei_json"


@pytest.mark.django_db
def test_duplicate_report_is_rejected_within_same_tenant(api_client, org, admin_user):
    payload = b'{"info":{"name":"Duplicate","severity":"low"},"host":"app.example.test"}'
    ReportIngestion.objects.create(
        organization=org, uploaded_by=admin_user, source_type="nuclei_json",
        report_file="reports/test.json", original_filename="first.json",
        sha256=hashlib.sha256(payload).hexdigest(), size_bytes=len(payload),
    )
    upload = SimpleUploadedFile("second.json", payload, content_type="application/json")
    response = api_client.post(
        "/api/v1/report-ingestions/upload/",
        {"source_type": "nuclei_json", "file": upload},
        format="multipart",
    )
    assert response.status_code == 409


@pytest.mark.django_db
def test_report_list_is_tenant_scoped(api_client, org, admin_user):
    other = Organization.objects.create(
        name="Other CERT", slug="other-cert", org_type="cert",
        country="KEN", country_name="Kenya", contact_email="other@example.test",
    )
    ReportIngestion.objects.create(
        organization=other, uploaded_by=None, source_type="nuclei_json",
        report_file="reports/other.json", original_filename="other.json",
        sha256="b" * 64, size_bytes=1,
    )
    response = api_client.get("/api/v1/report-ingestions/")
    assert response.status_code == 200
    results = response.data["results"] if isinstance(response.data, dict) else response.data
    assert all(str(item["organization"]) == str(org.id) for item in results)


@pytest.mark.django_db
def test_upload_rejects_extension_mismatch(api_client):
    upload = SimpleUploadedFile("not-a-report.txt", b"hello", content_type="text/plain")
    response = api_client.post(
        "/api/v1/report-ingestions/upload/",
        {"source_type": "nmap_xml", "file": upload},
        format="multipart",
    )
    assert response.status_code == 400
