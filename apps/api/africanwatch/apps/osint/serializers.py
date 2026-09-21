"""AfricaWatch — OSINT Serializers"""
from rest_framework import serializers
from africanwatch.apps.osint.models import OSINTSource, OSINTEvent

class OSINTSourceSerializer(serializers.ModelSerializer):
    event_count = serializers.IntegerField(read_only=True)
    class Meta:
        model = OSINTSource
        fields = ["id","name","source_type","url","handle","description","countries","languages",
                  "is_african_source","is_active","crawl_frequency_minutes","last_crawled_at",
                  "last_event_count","error_count","keywords","exclude_keywords","event_count","created_at"]
        read_only_fields = ["last_crawled_at","last_event_count","error_count"]

class OSINTEventSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source="source.name", read_only=True)
    source_type = serializers.CharField(source="source.source_type", read_only=True)
    class Meta:
        model = OSINTEvent
        fields = ["id","source","source_name","source_type","content","content_translated",
                  "language_detected","url","author","published_at","sentiment",
                  "threat_relevance_score","is_threat_relevant","entities_persons",
                  "entities_organizations","entities_locations","entities_iocs",
                  "keywords_matched","is_processed","is_verified","created_at"]
        read_only_fields = ["content_translated","language_detected","sentiment",
                            "threat_relevance_score","is_threat_relevant","entities_persons",
                            "entities_organizations","entities_locations","entities_iocs",
                            "keywords_matched","is_processed"]
