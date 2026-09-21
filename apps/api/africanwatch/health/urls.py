"""AfricaWatch — Health Checks"""
from django.http import JsonResponse
from django.urls import path
from django.utils import timezone

def health(request):
    checks, ok = {}, True
    try:
        from django.db import connection; connection.ensure_connection(); checks["database"]="ok"
    except Exception as e: checks["database"]=f"error:{e}"; ok=False
    try:
        from django.core.cache import cache; cache.set("_hc","1",5); checks["cache"]="ok"
    except Exception as e: checks["cache"]=f"error:{e}"; ok=False
    try:
        import httpx, django.conf
        r=httpx.get(f"{django.conf.settings.ELASTICSEARCH_URL}/_cluster/health",timeout=3)
        checks["elasticsearch"]="ok" if r.status_code==200 else "degraded"
    except Exception as e: checks["elasticsearch"]=f"unavailable"
    return JsonResponse({"status":"healthy" if ok else "degraded","checks":checks,"version":"1.0.0","ts":timezone.now().isoformat()},status=200 if ok else 503)

urlpatterns = [
    path("",health,name="health"),
    path("live/",lambda r:JsonResponse({"status":"alive"}),name="liveness"),
    path("ready/",lambda r:JsonResponse({"status":"ready"}),name="readiness"),
]
