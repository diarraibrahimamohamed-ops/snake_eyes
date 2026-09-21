"""AfricaWatch — Threat Intelligence Views & Serializers"""
from django.db.models import Count, Q
from django.utils import timezone
from django_filters import rest_framework as filters
from rest_framework import permissions, serializers, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from africanwatch.apps.threat_intel.models import Campaign, IOC, ThreatActor, ThreatFeed


# ─── SERIALIZERS ─────────────────────────────────────────────────────────────

class ThreatFeedSerializer(serializers.ModelSerializer):
    ioc_count = serializers.IntegerField(read_only=True)
    class Meta:
        model = ThreatFeed
        fields = ["id","name","description","feed_type","url","is_public","is_african_specific",
                  "fetch_frequency_hours","last_fetched_at","total_iocs_imported","status",
                  "last_error","tlp_level","tags","ioc_count","created_at"]
        read_only_fields = ["last_fetched_at","total_iocs_imported","status","last_error"]
        extra_kwargs = {"api_key": {"write_only": True}}


class IOCSerializer(serializers.ModelSerializer):
    feed_name = serializers.CharField(source="feed.name", read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    class Meta:
        model = IOC
        fields = ["id","ioc_type","value","severity","confidence","tlp_level","feed","feed_name",
                  "source_reference","is_african_threat","african_countries_targeted",
                  "first_seen","last_seen","expiry_date","is_active","is_expired",
                  "description","tags","malware_families","country_code","country_name",
                  "asn","asn_name","latitude","longitude","mitre_tactics","mitre_techniques",
                  "hit_count","false_positive_count","created_at","updated_at"]
        read_only_fields = ["country_code","country_name","asn","asn_name","latitude","longitude","hit_count"]

    def validate_value(self, value):
        import re
        t = self.initial_data.get("ioc_type","")
        if t == "md5" and not re.match(r'^[a-fA-F0-9]{32}$', value):
            raise serializers.ValidationError("Hash MD5 invalide (32 hex chars)")
        if t == "sha256" and not re.match(r'^[a-fA-F0-9]{64}$', value):
            raise serializers.ValidationError("Hash SHA-256 invalide (64 hex chars)")
        if t == "cve" and not re.match(r'^CVE-\d{4}-\d{4,}$', value, re.IGNORECASE):
            raise serializers.ValidationError("Format CVE invalide (ex: CVE-2024-12345)")
        return value.strip()


class IOCBulkSerializer(serializers.Serializer):
    iocs = IOCSerializer(many=True)
    def validate_iocs(self, v):
        if len(v) > 10000:
            raise serializers.ValidationError("Maximum 10 000 IOCs par import")
        return v


class ThreatActorSerializer(serializers.ModelSerializer):
    ioc_count = serializers.IntegerField(read_only=True)
    campaign_count = serializers.IntegerField(read_only=True)
    class Meta:
        model = ThreatActor
        fields = ["id","name","aliases","description","motivation","sophistication",
                  "country_of_origin","targets_africa","target_countries","target_sectors",
                  "known_tools","known_techniques","first_seen","last_activity","is_active",
                  "references","ioc_count","campaign_count","created_at"]


class CampaignSerializer(serializers.ModelSerializer):
    threat_actor_name = serializers.CharField(source="threat_actor.name", read_only=True)
    ioc_count = serializers.IntegerField(read_only=True)
    class Meta:
        model = Campaign
        fields = ["id","name","description","threat_actor","threat_actor_name","start_date",
                  "end_date","is_ongoing","target_countries","target_sectors",
                  "mitre_tactics","mitre_techniques","severity","tlp_level","references",
                  "ioc_count","created_at"]


# ─── FILTERS ─────────────────────────────────────────────────────────────────

class IOCFilter(filters.FilterSet):
    ioc_type = filters.MultipleChoiceFilter(choices=IOC.IOCType.choices)
    severity = filters.MultipleChoiceFilter(choices=IOC.Severity.choices)
    tlp_level = filters.MultipleChoiceFilter(choices=IOC.TLPLevel.choices)
    is_african_threat = filters.BooleanFilter()
    country_code = filters.CharFilter(lookup_expr="iexact")
    is_active = filters.BooleanFilter()
    confidence_min = filters.NumberFilter(field_name="confidence", lookup_expr="gte")
    first_seen_after = filters.DateTimeFilter(field_name="first_seen", lookup_expr="gte")
    last_seen_after = filters.DateTimeFilter(field_name="last_seen", lookup_expr="gte")
    search = filters.CharFilter(method="filter_search")

    def filter_search(self, qs, name, value):
        return qs.filter(Q(value__icontains=value) | Q(description__icontains=value))

    class Meta:
        model = IOC
        fields = ["ioc_type","severity","tlp_level","is_african_threat","country_code","is_active","feed"]


# ─── VIEWSETS ────────────────────────────────────────────────────────────────

class ThreatFeedViewSet(viewsets.ModelViewSet):
    queryset = ThreatFeed.objects.annotate(ioc_count=Count("iocs"))
    serializer_class = ThreatFeedSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ["feed_type","is_public","is_african_specific","status"]
    search_fields = ["name","description","url"]
    ordering_fields = ["name","last_fetched_at","total_iocs_imported"]

    @action(detail=True, methods=["post"], url_path="fetch")
    def trigger_fetch(self, request, pk=None):
        from africanwatch.apps.threat_intel.tasks import fetch_feed
        feed = self.get_object()
        task = fetch_feed.delay(str(feed.id))
        return Response({"message": f"Récupération lancée pour '{feed.name}'", "task_id": task.id}, status=202)

    @action(detail=True, methods=["get"])
    def stats(self, request, pk=None):
        feed = self.get_object()
        iocs = feed.iocs.all()
        return Response({"total_iocs":iocs.count(),"active_iocs":iocs.filter(is_active=True).count(),
            "african_threats":iocs.filter(is_african_threat=True).count(),
            "by_severity":list(iocs.values("severity").annotate(count=Count("id"))),
            "by_type":list(iocs.values("ioc_type").annotate(count=Count("id"))),
            "last_fetched_at":feed.last_fetched_at})


class IOCViewSet(viewsets.ModelViewSet):
    queryset = IOC.objects.select_related("feed","source_organization").all()
    serializer_class = IOCSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_class = IOCFilter
    search_fields = ["value","description"]
    ordering_fields = ["created_at","last_seen","severity","confidence","hit_count"]
    ordering = ["-last_seen"]

    def get_queryset(self):
        qs = super().get_queryset()
        user = self.request.user
        if user.organization:
            tlp_order = ["white","green","amber","red"]
            idx = tlp_order.index(user.organization.tlp_level)
            qs = qs.filter(tlp_level__in=tlp_order[:idx+1])
        return qs

    @action(detail=False, methods=["post"], url_path="bulk-import")
    def bulk_import(self, request):
        from africanwatch.apps.threat_intel.tasks import enrich_ioc
        s = IOCBulkSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        created = updated = 0
        now = timezone.now()
        for d in s.validated_data["iocs"]:
            d.setdefault("first_seen", now)
            d.setdefault("last_seen", now)
            ioc, c = IOC.objects.update_or_create(
                ioc_type=d["ioc_type"],
                value_normalized=d["value"].strip().lower(),
                defaults=d,
            )
            if c:
                created += 1
                enrich_ioc.delay(str(ioc.id))
            else:
                updated += 1
        return Response({"created": created, "updated": updated}, status=201)

    @action(detail=True, methods=["post"])
    def enrich(self, request, pk=None):
        from africanwatch.apps.threat_intel.tasks import enrich_ioc
        ioc = self.get_object()
        task = enrich_ioc.delay(str(ioc.id))
        return Response({"message": "Enrichissement lancé", "task_id": task.id}, status=202)

    @action(detail=True, methods=["post"], url_path="false-positive")
    def mark_false_positive(self, request, pk=None):
        ioc = self.get_object()
        ioc.false_positive_count += 1
        if ioc.false_positive_count >= 3:
            ioc.is_active = False
        ioc.save(update_fields=["false_positive_count","is_active"])
        return Response({"message": "Marqué comme faux positif", "is_active": ioc.is_active})

    @action(detail=False, methods=["get"])
    def stats(self, request):
        qs = self.get_queryset()
        now = timezone.now()
        return Response({
            "total": qs.count(),
            "active": qs.filter(is_active=True).count(),
            "african_threats": qs.filter(is_african_threat=True).count(),
            "critical": qs.filter(severity="critical").count(),
            "high": qs.filter(severity="high").count(),
            "new_last_24h": qs.filter(created_at__gte=now - timezone.timedelta(hours=24)).count(),
            "new_last_7d": qs.filter(created_at__gte=now - timezone.timedelta(days=7)).count(),
            "by_type": list(qs.values("ioc_type").annotate(count=Count("id")).order_by("-count")),
            "by_severity": list(qs.values("severity").annotate(count=Count("id"))),
            "by_country": list(qs.exclude(country_code="").values("country_code","country_name")
                              .annotate(count=Count("id")).order_by("-count")[:20]),
        })

    @action(detail=False, methods=["get"])
    def lookup(self, request):
        value = request.query_params.get("value","").strip()
        if not value:
            return Response({"error": "Paramètre 'value' requis"}, status=400)
        qs = self.get_queryset().filter(
            Q(value__iexact=value) | Q(value_normalized__iexact=value.lower())
        )
        if not qs.exists():
            return Response({"found": False, "iocs": []})
        return Response({"found": True, "count": qs.count(), "iocs": self.get_serializer(qs, many=True).data})


class ThreatActorViewSet(viewsets.ModelViewSet):
    queryset = ThreatActor.objects.annotate(ioc_count=Count("iocs"), campaign_count=Count("campaigns"))
    serializer_class = ThreatActorSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ["motivation","sophistication","targets_africa","is_active"]
    search_fields = ["name","description"]
    ordering_fields = ["last_activity","name"]

    @action(detail=True, methods=["get"])
    def timeline(self, request, pk=None):
        actor = self.get_object()
        return Response(list(actor.campaigns.order_by("start_date").values(
            "id","name","start_date","end_date","is_ongoing","severity")))


class CampaignViewSet(viewsets.ModelViewSet):
    queryset = Campaign.objects.annotate(ioc_count=Count("iocs")).select_related("threat_actor")
    serializer_class = CampaignSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ["severity","is_ongoing","tlp_level"]
    search_fields = ["name","description"]
    ordering_fields = ["start_date","name","severity"]
