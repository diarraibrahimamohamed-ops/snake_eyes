"""AfricaWatch — OSINT Models"""
import uuid
from django.db import models
from africanwatch.apps.organizations.models import TimeStampedModel, Organization


class OSINTSource(TimeStampedModel):
    class SourceType(models.TextChoices):
        TWITTER = "twitter","Twitter/X"
        TELEGRAM = "telegram","Telegram"
        NEWS_SITE = "news_site","Site d'actualité"
        BLOG = "blog","Blog/Forum"
        PASTE = "paste","Paste/Leak"
        DARK_WEB = "dark_web","Dark Web"
        RSS = "rss","Flux RSS"
        GITHUB = "github","GitHub"
        CERT = "cert","CERT/Advisory"
        GOVERNMENT = "government","Site gouvernemental"

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True, related_name="osint_sources")
    name = models.CharField(max_length=255)
    source_type = models.CharField(max_length=20, choices=SourceType.choices)
    url = models.URLField(blank=True)
    handle = models.CharField(max_length=255, blank=True)
    description = models.TextField(blank=True)
    countries = models.JSONField(default=list, blank=True)
    languages = models.JSONField(default=list, blank=True)
    is_african_source = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    crawl_frequency_minutes = models.IntegerField(default=60)
    last_crawled_at = models.DateTimeField(null=True, blank=True)
    last_event_count = models.IntegerField(default=0)
    error_count = models.IntegerField(default=0)
    keywords = models.JSONField(default=list, blank=True)
    exclude_keywords = models.JSONField(default=list, blank=True)
    class Meta:
        ordering = ["name"]
        verbose_name = "Source OSINT"
    def __str__(self): return f"{self.name} ({self.source_type})"


class OSINTEvent(TimeStampedModel):
    class Sentiment(models.TextChoices):
        POSITIVE = "positive","Positif"
        NEUTRAL = "neutral","Neutre"
        NEGATIVE = "negative","Négatif"
        ALARMING = "alarming","Alarmant"

    source = models.ForeignKey(OSINTSource, on_delete=models.CASCADE, related_name="events")
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True, related_name="osint_events")
    content = models.TextField()
    content_translated = models.TextField(blank=True)
    language_detected = models.CharField(max_length=10, blank=True)
    url = models.URLField(blank=True)
    author = models.CharField(max_length=255, blank=True)
    published_at = models.DateTimeField(null=True, blank=True)
    sentiment = models.CharField(max_length=20, choices=Sentiment.choices, default=Sentiment.NEUTRAL)
    threat_relevance_score = models.FloatField(default=0.0)
    is_threat_relevant = models.BooleanField(default=False, db_index=True)
    entities_persons = models.JSONField(default=list, blank=True)
    entities_organizations = models.JSONField(default=list, blank=True)
    entities_locations = models.JSONField(default=list, blank=True)
    entities_iocs = models.JSONField(default=list, blank=True)
    keywords_matched = models.JSONField(default=list, blank=True)
    related_iocs = models.ManyToManyField("threat_intel.IOC", blank=True)
    raw_data = models.JSONField(default=dict, blank=True)
    is_processed = models.BooleanField(default=False, db_index=True)
    is_verified = models.BooleanField(default=False)
    class Meta:
        ordering = ["-published_at"]
        verbose_name = "Event OSINT"
    def __str__(self): return f"{self.source.name} — {self.content[:80]}"
