"""AfricaWatch — SOC Views"""
from django.db.models import Count
from django.utils import timezone
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from africanwatch.apps.soc.models import Alert, Incident, IncidentTimeline, DetectionRule
from africanwatch.apps.soc.serializers import AlertSerializer, IncidentSerializer, IncidentTimelineSerializer, DetectionRuleSerializer


class DetectionRuleViewSet(viewsets.ModelViewSet):
    queryset = DetectionRule.objects.all()
    serializer_class = DetectionRuleSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ["rule_type","severity","status","is_african_specific"]
    search_fields = ["name","description"]
    ordering_fields = ["name","severity","hit_count"]


class AlertViewSet(viewsets.ModelViewSet):
    queryset = Alert.objects.select_related("organization","rule","assigned_to").all()
    serializer_class = AlertSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ["severity","status","source","organization"]
    search_fields = ["title","description","src_ip"]
    ordering_fields = ["created_at","severity"]
    ordering = ["-created_at"]

    def get_queryset(self):
        qs = super().get_queryset()
        u = self.request.user
        if not u.is_superuser and getattr(u, "role", "") != "super_admin":
            if u.organization:
                qs = qs.filter(organization=u.organization)
        return qs

    @action(detail=True, methods=["post"])
    def acknowledge(self, request, pk=None):
        alert = self.get_object()
        alert.status = Alert.Status.ACKNOWLEDGED
        alert.acknowledged_at = timezone.now()
        alert.acknowledged_by = request.user
        alert.save(update_fields=["status","acknowledged_at","acknowledged_by"])
        self._ws_notify(alert)
        return Response({"status": "acknowledged"})

    @action(detail=True, methods=["post"])
    def escalate(self, request, pk=None):
        alert = self.get_object()
        alert.status = Alert.Status.ESCALATED
        alert.save(update_fields=["status"])
        incident = Incident.objects.create(
            organization=alert.organization,
            title=request.data.get("incident_title", f"Incident — {alert.title}"),
            description=f"Escaladé depuis alerte: {alert.title}",
            incident_type=Incident.IncidentType.UNKNOWN,
            severity=alert.severity,
            detected_at=alert.created_at,
            assigned_to=request.user,
        )
        incident.alerts.add(alert)
        IncidentTimeline.objects.create(
            incident=incident, timestamp=timezone.now(), author=request.user,
            action="Incident créé par escalade d'alerte",
            details=f"Alert ID: {alert.id} — {alert.title}",
        )
        return Response({"status": "escalated", "incident_id": str(incident.id)}, status=201)

    @action(detail=True, methods=["post"], url_path="false-positive")
    def mark_false_positive(self, request, pk=None):
        alert = self.get_object()
        alert.status = Alert.Status.FALSE_POSITIVE
        alert.notes = request.data.get("reason", "")
        alert.resolved_at = timezone.now()
        alert.save(update_fields=["status","notes","resolved_at"])
        return Response({"status": "false_positive"})

    @action(detail=False, methods=["get"])
    def stats(self, request):
        qs = self.get_queryset()
        now = timezone.now()
        return Response({
            "total": qs.count(),
            "open": qs.filter(status="new").count(),
            "critical": qs.filter(severity="critical", status="new").count(),
            "last_24h": qs.filter(created_at__gte=now - timezone.timedelta(hours=24)).count(),
            "last_7d": qs.filter(created_at__gte=now - timezone.timedelta(days=7)).count(),
            "by_severity": list(qs.values("severity").annotate(count=Count("id"))),
            "by_status": list(qs.values("status").annotate(count=Count("id"))),
            "by_source": list(qs.values("source").annotate(count=Count("id")).order_by("-count")[:10]),
            "false_positive_rate": round(
                qs.filter(status="false_positive").count() / max(qs.count(), 1) * 100, 1),
        })

    def _ws_notify(self, alert):
        try:
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync
            async_to_sync(get_channel_layer().group_send)(
                f"aw.alerts.{alert.organization.id}",
                {"type": "alert_updated", "data": AlertSerializer(alert).data},
            )
        except Exception:
            pass


class IncidentViewSet(viewsets.ModelViewSet):
    queryset = Incident.objects.annotate(alert_count=Count("alerts")).select_related(
        "organization","assigned_to").prefetch_related("timeline")
    serializer_class = IncidentSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ["severity","status","incident_type","organization"]
    search_fields = ["title","description"]
    ordering_fields = ["detected_at","severity","status"]
    ordering = ["-detected_at"]

    def get_queryset(self):
        qs = super().get_queryset()
        u = self.request.user
        if not u.is_superuser and getattr(u, "role", "") != "super_admin":
            if u.organization:
                qs = qs.filter(organization=u.organization)
        return qs

    def perform_create(self, serializer):
        incident = serializer.save()
        IncidentTimeline.objects.create(
            incident=incident, timestamp=timezone.now(),
            author=self.request.user, action="Incident ouvert", is_automated=False,
        )

    @action(detail=True, methods=["post"], url_path="add-timeline")
    def add_timeline(self, request, pk=None):
        incident = self.get_object()
        entry = IncidentTimeline.objects.create(
            incident=incident, timestamp=timezone.now(), author=request.user,
            action=request.data.get("action",""), details=request.data.get("details",""),
        )
        return Response(IncidentTimelineSerializer(entry).data, status=201)

    @action(detail=True, methods=["post"], url_path="change-status")
    def change_status(self, request, pk=None):
        incident = self.get_object()
        new_status = request.data.get("status")
        valid = [c[0] for c in Incident.Status.choices]
        if new_status not in valid:
            return Response({"error": f"Statut invalide. Valeurs acceptées: {valid}"}, status=400)
        old_status = incident.status
        incident.status = new_status
        if new_status == "contained":
            incident.contained_at = timezone.now()
        if new_status in ["recovered","closed","false_positive"]:
            if not incident.resolved_at:
                incident.resolved_at = timezone.now()
        incident.save()
        IncidentTimeline.objects.create(
            incident=incident, timestamp=timezone.now(), author=request.user,
            action=f"Statut: {old_status} → {new_status}", is_automated=False,
        )
        return Response(IncidentSerializer(incident).data)

    @action(detail=False, methods=["get"])
    def stats(self, request):
        qs = self.get_queryset()
        return Response({
            "total": qs.count(),
            "active": qs.filter(status__in=["open","investigating"]).count(),
            "critical": qs.filter(severity="critical").count(),
            "by_type": list(qs.values("incident_type").annotate(count=Count("id"))),
            "by_severity": list(qs.values("severity").annotate(count=Count("id"))),
            "by_status": list(qs.values("status").annotate(count=Count("id"))),
        })
