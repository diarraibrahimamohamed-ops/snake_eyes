"""AfricaWatch — OSINT Views"""
from django.db.models import Count
from django.utils import timezone
from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from africanwatch.apps.osint.models import OSINTSource, OSINTEvent
from africanwatch.apps.osint.serializers import OSINTSourceSerializer, OSINTEventSerializer


class OSINTSourceViewSet(viewsets.ModelViewSet):
    queryset = OSINTSource.objects.annotate(event_count=Count("events"))
    serializer_class = OSINTSourceSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ["source_type","is_african_source","is_active"]
    search_fields = ["name","url","handle"]
    ordering_fields = ["name","last_crawled_at","last_event_count"]

    @action(detail=True, methods=["post"])
    def collect(self, request, pk=None):
        source = self.get_object()
        from africanwatch.apps.osint.tasks import collect_source
        task = collect_source.delay(str(source.id))
        return Response({"message": f"Collecte lancée pour {source.name}", "task_id": task.id}, status=202)

    @action(detail=False, methods=["post"], url_path="collect-all")
    def collect_all(self, request):
        from africanwatch.apps.osint.tasks import run_all_collections
        task = run_all_collections.delay()
        return Response({"message": "Collecte globale lancée", "task_id": task.id}, status=202)

    @action(detail=False, methods=["get"])
    def stats(self, request):
        qs = self.get_queryset()
        return Response({
            "total_sources": qs.count(),
            "active_sources": qs.filter(is_active=True).count(),
            "african_sources": qs.filter(is_african_source=True).count(),
            "by_type": list(qs.values("source_type").annotate(count=Count("id")).order_by("-count")),
        })


class OSINTEventViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = OSINTEvent.objects.select_related("source").order_by("-published_at")
    serializer_class = OSINTEventSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ["source","language_detected","is_threat_relevant","sentiment","is_verified"]
    search_fields = ["content","content_translated","author"]
    ordering_fields = ["published_at","threat_relevance_score","created_at"]

    def get_queryset(self):
        qs = super().get_queryset()
        min_score = self.request.query_params.get("min_score")
        if min_score:
            try:
                qs = qs.filter(threat_relevance_score__gte=float(min_score))
            except ValueError:
                pass
        return qs

    @action(detail=False, methods=["get"])
    def stats(self, request):
        qs = self.get_queryset()
        last_24h = timezone.now() - timezone.timedelta(hours=24)
        return Response({
            "total": qs.count(),
            "threat_relevant": qs.filter(is_threat_relevant=True).count(),
            "last_24h": qs.filter(created_at__gte=last_24h).count(),
            "by_source_type": list(qs.values("source__source_type").annotate(count=Count("id")).order_by("-count")),
            "by_language": list(qs.values("language_detected").annotate(count=Count("id")).order_by("-count")[:10]),
            "by_sentiment": list(qs.values("sentiment").annotate(count=Count("id"))),
        })

    @action(detail=True, methods=["post"])
    def verify(self, request, pk=None):
        event = self.get_object()
        event.is_verified = True
        event.save(update_fields=["is_verified"])
        return Response({"status": "verified"})
