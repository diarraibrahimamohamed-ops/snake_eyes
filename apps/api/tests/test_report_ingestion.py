"""API tests for tenant-scoped scanner report ingestion."""
import hashlib
from unittest.mock import patch

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from africanwatch.apps.organizations.models import Asset, Organization
from africanwatch.apps.vulns.models import ReportIngestion


@pytest.mark.django_db(transaction=True)
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
    enqueue.assert_called_once_with(str(report.id))


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


@pytest.mark.django_db
def test_processing_links_only_to_exact_asset_in_same_tenant(org, admin_user, tmp_path, settings):
    settings.MEDIA_ROOT = tmp_path
    from africanwatch.apps.vulns.report_tasks import process_report_ingestion

    payload = (
        b'{"template-id":"CVE-2024-1234","host":"app.example.test",'
        b'"info":{"name":"Example CVE","severity":"high",'
        b'"description":"Test finding","classification":{"cve-id":["CVE-2024-1234"],"cvss-score":8.1}}}'
    )
    asset = Asset.objects.create(
        organization=org, name="App", asset_type="domain", value="app.example.test"
    )
    report = ReportIngestion.objects.create(
        organization=org, uploaded_by=admin_user, source_type="nuclei_json",
        report_file=SimpleUploadedFile("report.json", payload, content_type="application/json"),
        original_filename="report.json", sha256=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
    )
    result = process_report_ingestion.run(str(report.id))
    report.refresh_from_db()
    assert result["status"] == "completed"
    assert report.total_findings == 1
    assert report.linked_findings == 1
    assert report.unmatched_findings == 0
    finding = report.findings.get()
    assert finding.asset_id == asset.id
    assert finding.vulnerability is not None
    assert finding.vulnerability.cve_id == "CVE-2024-1234"


@pytest.mark.django_db
def test_processing_keeps_unknown_asset_unlinked(org, admin_user, tmp_path, settings):
    settings.MEDIA_ROOT = tmp_path
    from africanwatch.apps.vulns.report_tasks import process_report_ingestion

    payload = b'{"info":{"name":"Unknown host finding","severity":"low"},"host":"unknown.example.test"}'
    report = ReportIngestion.objects.create(
        organization=org, uploaded_by=admin_user, source_type="nuclei_json",
        report_file=SimpleUploadedFile("unknown.json", payload, content_type="application/json"),
        original_filename="unknown.json", sha256=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
    )
    result = process_report_ingestion.run(str(report.id))
    report.refresh_from_db()
    assert result["status"] == "completed"
    assert report.unmatched_findings == 1
    assert report.findings.get().asset is None


@pytest.mark.django_db
def test_legacy_active_scanning_tasks_are_disabled_by_default(org, settings):
    from africanwatch.apps.vulns.models import ScanJob
    from africanwatch.apps.vulns.tasks import run_scheduled_scans, scan_asset

    settings.ACTIVE_ASSESSMENTS_ENABLED = False
    asset = Asset.objects.create(
        organization=org, name="Protected app", asset_type="domain", value="protected.example.test",
        scan_enabled=True, is_active=True,
    )
    scheduled = run_scheduled_scans.run()
    result = scan_asset.run(str(asset.id), "full")
    assert scheduled == {"scheduled": 0, "status": "disabled_by_policy"}
    assert result["status"] == "blocked"
    job = ScanJob.objects.get(id=result["job_id"])
    assert job.status == ScanJob.Status.FAILED
    assert "désactivés" in job.error_message


@pytest.mark.django_db
def test_report_findings_are_tenant_scoped(api_client, org, admin_user):
    from africanwatch.apps.vulns.models import ReportFinding

    other = Organization.objects.create(
        name="Other CERT Findings", slug="other-cert-findings", org_type="cert",
        country="KEN", country_name="Kenya", contact_email="findings@example.test",
    )
    own_report = ReportIngestion.objects.create(
        organization=org, uploaded_by=admin_user, source_type="nuclei_json",
        report_file="reports/own.json", original_filename="own.json",
        sha256="c" * 64, size_bytes=1, status=ReportIngestion.Status.COMPLETED,
    )
    other_report = ReportIngestion.objects.create(
        organization=other, uploaded_by=None, source_type="nuclei_json",
        report_file="reports/other.json", original_filename="other.json",
        sha256="d" * 64, size_bytes=1, status=ReportIngestion.Status.COMPLETED,
    )
    ReportFinding.objects.create(
        report=own_report, fingerprint="e" * 64, title="Own finding", severity="high",
    )
    ReportFinding.objects.create(
        report=other_report, fingerprint="f" * 64, title="Other tenant finding", severity="critical",
    )

    response = api_client.get("/api/v1/report-findings/")
    assert response.status_code == 200
    results = response.data["results"] if isinstance(response.data, dict) else response.data
    assert [item["title"] for item in results] == ["Own finding"]



def test_celery_discovers_report_ingestion_task():
    from africanwatch.apps.vulns import tasks
    from africanwatch.apps.vulns.report_tasks import process_report_ingestion

    assert tasks._process_report_ingestion is process_report_ingestion
    assert process_report_ingestion.name == "africanwatch.apps.vulns.report_tasks.process_report_ingestion"
