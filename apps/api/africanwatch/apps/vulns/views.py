"""AfricaWatch — Vulnerability Management Views"""
from django.db.models import Count, Avg
from django.utils import timezone
from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from africanwatch.apps.vulns.models import Vulnerability, ScanJob
from africanwatch.apps.vulns.serializers import VulnerabilitySerializer, ScanJobSerializer


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
        if not u.is_superuser and getattr(u,"role","") != "super_admin":
            if u.organization:
                qs = qs.filter(asset__organization=u.organization)
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
        if not u.is_superuser and getattr(u,"role","") != "super_admin":
            if u.organization:
                qs = qs.filter(asset__organization=u.organization)
        return qs
