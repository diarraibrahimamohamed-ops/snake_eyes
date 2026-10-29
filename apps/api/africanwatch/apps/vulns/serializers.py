"""Serializers for vulnerability management and report ingestion."""
from pathlib import PurePath

from rest_framework import serializers

from africanwatch.apps.vulns.models import ReportFinding, ReportIngestion, ScanJob, Vulnerability
from africanwatch.apps.vulns.report_parsers import MAX_REPORT_BYTES


class VulnerabilitySerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source="asset.name", read_only=True)
    asset_value = serializers.CharField(source="asset.value", read_only=True)

    class Meta:
        model = Vulnerability
        fields = [
            "id", "asset", "asset_name", "asset_value", "cve_id", "cvss_score", "severity",
            "title", "description", "affected_component", "affected_version", "fixed_version",
            "status", "discovered_at", "remediated_at", "remediation_notes", "scanner",
            "references", "is_exploitable", "exploit_available", "tags", "created_at",
        ]
        read_only_fields = ["discovered_at"]

    def validate_asset(self, asset):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        if (
            user
            and user.is_authenticated
            and not user.is_superuser
            and getattr(user, "role", "") != "super_admin"
            and (not user.organization_id or asset.organization_id != user.organization_id)
        ):
            raise serializers.ValidationError("Actif hors du périmètre de votre organisation.")
        return asset

    def validate_status(self, value):
        """Risk acceptance is an approval action, not a general analyst-editable field."""
        if value != Vulnerability.Status.ACCEPTED:
            return value

        request = self.context.get("request")
        user = getattr(request, "user", None)
        role = getattr(user, "role", "") if user and getattr(user, "is_authenticated", False) else ""
        if not (
            user
            and getattr(user, "is_authenticated", False)
            and (getattr(user, "is_superuser", False) or role in {"super_admin", "org_admin"})
        ):
            raise serializers.ValidationError(
                "Seul un administrateur d'organisation peut accepter un risque."
            )
        return value


class ScanJobSerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source="asset.name", read_only=True)
    triggered_by_name = serializers.CharField(source="triggered_by.get_full_name", read_only=True)

    class Meta:
        model = ScanJob
        fields = [
            "id", "asset", "asset_name", "scan_type", "status", "started_at", "completed_at",
            "findings_count", "critical_count", "high_count", "medium_count", "low_count",
            "error_message", "triggered_by", "triggered_by_name", "created_at",
        ]
        read_only_fields = [
            "started_at", "completed_at", "findings_count", "critical_count",
            "high_count", "medium_count", "low_count", "error_message", "status",
        ]


class ReportFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportFinding
        fields = [
            "id", "report", "asset", "vulnerability", "fingerprint", "external_asset",
            "scanner", "cve_id", "cvss_score", "severity", "title", "description",
            "affected_component", "remediation", "references", "evidence", "created_at",
        ]
        read_only_fields = fields


class ReportIngestionSerializer(serializers.ModelSerializer):
    uploaded_by_email = serializers.EmailField(source="uploaded_by.email", read_only=True)
    findings_url = serializers.SerializerMethodField()

    class Meta:
        model = ReportIngestion
        fields = [
            "id", "organization", "uploaded_by_email", "source_type", "original_filename",
            "sha256", "size_bytes", "status", "total_findings", "linked_findings",
            "unmatched_findings", "summary", "error_message", "started_at", "completed_at",
            "findings_url", "created_at",
        ]
        read_only_fields = fields

    def get_findings_url(self, obj):
        return f"/api/v1/report-findings/?report={obj.id}"


class ReportUploadSerializer(serializers.Serializer):
    source_type = serializers.ChoiceField(choices=ReportIngestion.SourceType.choices)
    file = serializers.FileField()

    EXTENSIONS = {
        "nmap_xml": {".xml"},
        "nessus_xml": {".nessus", ".xml"},
        "nuclei_json": {".json"},
        "nuclei_jsonl": {".jsonl", ".ndjson"},
        "shodan_json": {".json"},
        "shodan_csv": {".csv"},
    }

    def validate_file(self, uploaded):
        if not uploaded or uploaded.size <= 0:
            raise serializers.ValidationError("Le fichier est vide.")
        if uploaded.size > MAX_REPORT_BYTES:
            raise serializers.ValidationError("Taille maximale autorisée : 10 Mio.")
        return uploaded

    def validate(self, attrs):
        extension = PurePath(attrs["file"].name or "").suffix.lower()
        if extension not in self.EXTENSIONS[attrs["source_type"]]:
            raise serializers.ValidationError({
                "file": f"Extension incompatible avec le format {attrs['source_type']}."
            })
        return attrs
