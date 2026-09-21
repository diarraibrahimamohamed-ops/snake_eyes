"""AfricaWatch — Middleware"""
import time, logging
logger = logging.getLogger("africanwatch.middleware")

class AuditLogMiddleware:
    def __init__(self, get_response): self.get_response = get_response
    def __call__(self, request):
        start = time.time()
        response = self.get_response(request)
        if request.method in ("POST","PUT","PATCH","DELETE") and "/api/" in request.path:
            self._log(request, response, round((time.time()-start)*1000,2))
        return response
    def _log(self, request, response, ms):
        try:
            from africanwatch.apps.organizations.models import AuditLog
            u = getattr(request,"user",None)
            if u and u.is_authenticated:
                AuditLog.objects.create(user=u,organization=getattr(u,"organization",None),
                    action=AuditLog.Action.API_CALL,ip_address=self._get_ip(request),
                    user_agent=request.META.get("HTTP_USER_AGENT","")[:500],
                    details={"method":request.method,"path":request.path,"status":response.status_code,"ms":ms},
                    success=response.status_code<400)
        except Exception: pass
    def _get_ip(self, r):
        xff = r.META.get("HTTP_X_FORWARDED_FOR")
        return xff.split(",")[0].strip() if xff else r.META.get("REMOTE_ADDR","")
