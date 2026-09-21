"""AfricaWatch — WebSocket Consumers"""
import logging
from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger("africanwatch.ws")

class BaseConsumer(AsyncJsonWebsocketConsumer):
    require_auth = True
    async def connect(self):
        self.user = self.scope.get("user")
        if self.require_auth and (not self.user or not self.user.is_authenticated):
            await self.close(code=4001); return
        self.room = self.get_room()
        await self.channel_layer.group_add(self.room, self.channel_name)
        await self.accept()
        await self.on_connect()
    async def disconnect(self, code):
        await self.channel_layer.group_discard(self.room, self.channel_name)
    def get_room(self): return "aw.global"
    async def on_connect(self): pass
    async def push(self, t, p):
        await self.send_json({"type":t,"payload":p,"ts":timezone.now().isoformat()})

class DashboardConsumer(BaseConsumer):
    def get_room(self):
        if self.user and (self.user.is_superuser or getattr(self.user, "role", "") == "super_admin"):
            return "aw.dashboard.global"
        if self.user and getattr(self.user, "organization", None):
            return f"aw.dashboard.{self.user.organization.id}"
        return "aw.dashboard.denied"
    async def on_connect(self):
        score = cache.get("african_threat_score") or {"score":0,"level":"stable","iocs_24h":0}
        await self.push("threat_score.update", score)
        await self.push("stats.update", await self._stats())
    @database_sync_to_async
    def _stats(self):
        from africanwatch.apps.threat_intel.models import IOC
        from africanwatch.apps.soc.models import Alert, Incident
        now = timezone.now()
        alert_qs = Alert.objects.all()
        incident_qs = Incident.objects.all()
        if not self.user.is_superuser and getattr(self.user, "role", "") != "super_admin":
            org = getattr(self.user, "organization", None)
            if not org:
                return {"iocs_total": 0, "iocs_24h": 0, "alerts_open": 0, "incidents_active": 0}
            alert_qs = alert_qs.filter(organization=org)
            incident_qs = incident_qs.filter(organization=org)
        return {"iocs_total":IOC.objects.filter(is_active=True).count(),
                "iocs_24h":IOC.objects.filter(created_at__gte=now-timezone.timedelta(hours=24)).count(),
                "alerts_open":alert_qs.filter(status="new").count(),
                "incidents_active":incident_qs.filter(status__in=["open","investigating"]).count()}
    async def threat_score_update(self, event): await self.push("threat_score.update", event["data"])
    async def alert_new(self, event): await self.push("alert.new", event["data"])
    async def ioc_new(self, event): await self.push("ioc.new", event["data"])
    async def stats_update(self, event): await self.push("stats.update", event["data"])

class AlertConsumer(BaseConsumer):
    def get_room(self):
        if self.user and getattr(self.user,"organization",None): return f"aw.alerts.{self.user.organization.id}"
        return "aw.alerts"
    async def alert_new(self, event): await self.push("alert.new", event["data"])
    async def alert_updated(self, event): await self.push("alert.updated", event["data"])

class SOCConsumer(BaseConsumer):
    def get_room(self):
        if self.user and getattr(self.user,"organization",None): return f"aw.soc.{self.user.organization.id}"
        return "aw.soc"
    async def soc_metrics_update(self, event): await self.push("soc.metrics", event["data"])

class IOCConsumer(BaseConsumer):
    def get_room(self):
        if self.user and (self.user.is_superuser or getattr(self.user, "role", "") == "super_admin"):
            return "aw.iocs.global"
        if self.user and getattr(self.user, "organization", None):
            return f"aw.iocs.{self.user.organization.id}"
        return "aw.iocs.denied"
    async def receive_json(self, content):
        if content.get("action")=="lookup":
            v = content.get("value","").strip()
            if v: await self.push("ioc.lookup_result", await self._lookup(v))
    @database_sync_to_async
    def _lookup(self, value):
        from africanwatch.apps.threat_intel.models import IOC
        qs = IOC.objects.filter(value_normalized__iexact=value.lower())
        if not self.user.is_superuser and getattr(self.user, "role", "") != "super_admin":
            org = getattr(self.user, "organization", None)
            if org:
                tlp_order = ["white", "green", "amber", "red"]
                idx = tlp_order.index(org.tlp_level)
                qs = qs.filter(tlp_level__in=tlp_order[:idx+1])
            else:
                qs = qs.none()
        ioc = qs.first()
        if ioc: return {"found":True,"value":ioc.value,"type":ioc.ioc_type,"severity":ioc.severity}
        return {"found":False,"value":value}
    async def ioc_new(self, event): await self.push("ioc.new", event["data"])
