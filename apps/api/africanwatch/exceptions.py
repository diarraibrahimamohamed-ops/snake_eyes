"""AfricaWatch — Exceptions"""
from django.http import JsonResponse
from django.utils import timezone
from rest_framework.views import exception_handler

def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if response is not None:
        msg = str(response.data.get("detail","")) if isinstance(response.data,dict) else str(response.data)
        response.data = {"error":True,"status_code":response.status_code,"message":msg,"details":response.data,"ts":timezone.now().isoformat()}
    return response

def lockout_response(request, credentials, *args, **kwargs):
    return JsonResponse({"error":True,"message":"Compte bloqué. Réessayez dans 30 minutes.","status_code":403},status=403)
