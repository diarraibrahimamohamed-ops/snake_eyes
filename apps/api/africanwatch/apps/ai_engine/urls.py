from django.urls import path
from africanwatch.apps.ai_engine.views import analyze_text, summarize_incident, threat_prediction
urlpatterns = [
    path("ai/analyze/", analyze_text, name="ai-analyze"),
    path("ai/summarize-incident/", summarize_incident, name="ai-summarize"),
    path("ai/threat-prediction/", threat_prediction, name="ai-prediction"),
]
