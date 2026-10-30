from django.contrib import admin
from .models import CollectionTarget, CollectionSource, CollectionRun, IntelligenceObservation, IntelligenceRelation, IntelligenceEvidence, ThreatForecast
for model in [CollectionTarget, CollectionSource, CollectionRun, IntelligenceObservation, IntelligenceEvidence, IntelligenceRelation, ThreatForecast]: admin.site.register(model)
