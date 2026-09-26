from django.contrib import admin
from .models import CollectionTarget, CollectionSource, CollectionRun, IntelligenceObservation, IntelligenceRelation, ThreatForecast
for model in [CollectionTarget, CollectionSource, CollectionRun, IntelligenceObservation, IntelligenceRelation, ThreatForecast]: admin.site.register(model)
