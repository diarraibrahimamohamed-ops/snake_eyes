"""AfricaWatch — ASGI"""
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE","africanwatch.settings.dev")
from django.core.asgi import get_asgi_application
django_asgi_app = get_asgi_application()
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from django.urls import path
from africanwatch.consumers import DashboardConsumer, AlertConsumer, SOCConsumer, IOCConsumer
application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AllowedHostsOriginValidator(AuthMiddlewareStack(URLRouter([
        path("ws/dashboard/", DashboardConsumer.as_asgi()),
        path("ws/alerts/", AlertConsumer.as_asgi()),
        path("ws/soc/", SOCConsumer.as_asgi()),
        path("ws/iocs/", IOCConsumer.as_asgi()),
    ]))),
})
