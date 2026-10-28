"""AfricaWatch — Vulnerability Management Views"""
from django.core.files.base import ContentFile
from django.db import IntegrityError, transaction
from django.db.models import Count, Avg
from django.utils import timezone
from rest_framework import status, viewsets, permissions
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.decorators import action
from rest_framework.response import Response
from africanwatch.apps.organizations.models import AuditLog
from africanwatch.apps.vulns.models import ReportFinding, ReportIngestion, Vulnerability, ScanJob
from africanwatch.apps.vulns.serializers import (ReportFindingSerializer, ReportIngestionSerializer, ReportUploadSerializer, VulnerabilitySerializer, ScanJobSerializer)
from africanwatch.security.permissions import CanOperateSecurityAssessment


class VulnerabilityViewSet(viewsets.ModelViewSet):
    queryset = Vulnerability.objects.select_related("asset","asset__organization")
    serializer_class = VulnerabilitySerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ["severity","status","scanner","is_exploitable","asset"]
    search_fields = ["title","cve_id","description","affected_component"]
    ordering_fields = ["cvss_score","severity","discovered_at"]
    ordering = ["-cvss_score"]

    def get_queryset(self):
        qs = super().get_queryset()
        u = self.request.user
        if not u.is_superuser and getattr(u, "role", "") != "super_admin":
            if not u.organization_id:
                return qs.none()
            qs = qs.filter(asset__organization_id=u.organization_id)
        return qs

    @action(detail=True, methods=["post"])
    def remediate(self, request, pk=None):
        vuln = self.get_object()
        vuln.status = Vulnerability.Status.REMEDIATED
        vuln.remediated_at = timezone.now()
        vuln.remediation_notes = request.data.get("notes","")
        vuln.save(update_fields=["status","remediated_at","remediation_notes"])
        return Response({"status": "remediated"})

    @action(detail=True, methods=["post"], url_path="accept-risk")
    def accept_risk(self, request, pk=None):
        vuln = self.get_object()
        vuln.status = Vulnerability.Status.ACCEPTED
        vuln.remediation_notes = request.data.get("justification","")
        vuln.save(update_fields=["status","remediation_notes"])
        return Response({"status": "risk_accepted"})

    @action(detail=True, methods=["post"], url_path="false-positive")
    def mark_false_positive(self, request, pk=None):
        vuln = self.get_object()
        vuln.status = Vulnerability.Status.FALSE_POSITIVE
        vuln.save(update_fields=["status"])
        return Response({"status": "false_positive"})

    @action(detail=False, methods=["get"])
    def stats(self, request):
        qs = self.get_queryset()
        return Response({
            "total": qs.count(),
            "open": qs.filter(status="open").count(),
            "critical": qs.filter(severity="critical", status="open").count(),
            "exploitable": qs.filter(is_exploitable=True, status="open").count(),
            "avg_cvss": round(qs.aggregate(a=Avg("cvss_score"))["a"] or 0, 2),
            "by_severity": list(qs.values("severity").annotate(count=Count("id"))),
            "by_status": list(qs.values("status").annotate(count=Count("id"))),
        })


class ScanJobViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ScanJob.objects.select_related("asset","triggered_by")
    serializer_class = ScanJobSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ["status","scan_type","asset"]
    ordering = ["-created_at"]

    def get_queryset(self):
        qs = super().get_queryset()
        u = self.request.user
        if not u.is_superuser and getattr(u, "role", "") != "super_admin":
            if not u.organization_id:
                return qs.none()
            qs = qs.filter(asset__organization_id=u.organization_id)
        return qs

class ReportIngestionViewSet(viewsets.ReadOnlyModelViewSet):
    """Tenant-scoped report inventory plus a bounded multipart upload endpoint."""
    serializer_class = ReportIngestionSerializer
    permission_classes = [CanOperateSecurityAssessment]
    queryset = ReportIngestion.objects.select_related("organization", "uploaded_by")

    def get_queryset(self):
        qs = super().get_queryset()
        user = self.request.user
        if user.is_superuser or getattr(user, "role", "") == "super_admin":
            return qs
        if not user.organization_id:
            return qs.none()
        return qs.filter(organization_id=user.organization_id)

    @action(detail=False, methods=["post"], url_path="upload",
            parser_classes=[MultiPartParser, FormParser], serializer_class=ReportUploadSerializer)
    def upload(self, request):
        upload_serializer = ReportUploadSerializer(data=request.data, context={"request": request})
        upload_serializer.is_valid(raise_exception=True)
        organization = getattr(request.user, "organization", None)
        is_global_admin = request.user.is_superuser or getattr(request.user, "role", "") == "super_admin"
        if organization is None and not is_global_admin:
            return Response({"detail": "Votre compte doit être rattaché à une organisation."},
                            status=status.HTTP_403_FORBIDDEN)
        if organization is None:
            requested_org = request.data.get("organization")
            if not requested_org:
                return Response({"detail": "L'identifiant d'organisation est requis pour un administrateur global."},
                                status=status.HTTP_400_BAD_REQUEST)
            from africanwatch.apps.organizations.models import Organization
            try:
                organization = Organization.objects.get(id=requested_org, is_active=True)
            except (ValueError, TypeError, Organization.DoesNotExist):
                return Response({"detail": "Organisation inconnue ou inactive."}, status=status.HTTP_400_BAD_REQUEST)

        uploaded = upload_serializer.validated_data["file"]
        source_type = upload_serializer.validated_data["source_type"]
        raw = uploaded.read(10 * 1024 * 1024 + 1)
        if not raw or len(raw) > 10 * 1024 * 1024:
            return Response({"file": "Fichier vide ou supérieur à 10 Mio."}, status=status.HTTP_400_BAD_REQUEST)
        import hashlib
        digest = hashlib.sha256(raw).hexdigest()
        existing = ReportIngestion.objects.filter(organization=organization, sha256=digest).first()
        if existing:
            return Response({"detail": "Ce rapport a déjà été importé dans cette organisation.",
                             "report_id": str(existing.id), "status": existing.status},
                            status=status.HTTP_409_CONFLICT)

        safe_extension = {"nmap_xml": ".xml", "nessus_xml": ".nessus", "nuclei_json": ".json",
                          "nuclei_jsonl": ".jsonl", "shodan_json": ".json", "shodan_csv": ".csv"}[source_type]
        original_name = (uploaded.name or ("report" + safe_extension)).replace(chr(92), "/").split("/")[-1][:255]
        report = ReportIngestion(
            organization=organization, uploaded_by=request.user, source_type=source_type,
            original_filename=original_name, sha256=digest, size_bytes=len(raw),
            status=ReportIngestion.Status.PENDING,
        )
        try:
            with transaction.atomic():
                report.report_file.save("report-" + digest[:12] + safe_extension, ContentFile(raw), save=False)
                report.save()
                AuditLog.objects.create(
                    user=request.user, organization=organization, action="report_ingestion_uploaded",
                    resource_type="report_ingestion", resource_id=str(report.id),
                    details={"source_type": source_type, "sha256": digest, "size_bytes": len(raw)},
                    success=True,
                )
                from africanwatch.apps.vulns.report_tasks import process_report_ingestion
                transaction.on_commit(lambda: process_report_ingestion.delay(str(report.id)))
        except IntegrityError:
            if report.report_file:
                report.report_file.delete(save=False)
            existing = ReportIngestion.objects.filter(organization=organization, sha256=digest).first()
            return Response({"detail": "Ce rapport a déjà été importé dans cette organisation.",
                             "report_id": str(existing.id) if existing else None},
                            status=status.HTTP_409_CONFLICT)
        return Response(ReportIngestionSerializer(report, context={"request": request}).data,
                        status=status.HTTP_202_ACCEPTED)


class ReportFindingViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ReportFindingSerializer
    permission_classes = [CanOperateSecurityAssessment]
    queryset = ReportFinding.objects.select_related("report", "asset", "vulnerability")

    def get_queryset(self):
        qs = super().get_queryset()
        user = self.request.user
        if not user.is_superuser and getattr(user, "role", "") != "super_admin":
            if not user.organization_id:
                return qs.none()
            qs = qs.filter(report__organization_id=user.organization_id)
        report_id = self.request.query_params.get("report")
        if report_id:
            qs = qs.filter(report_id=report_id)
        return qs

