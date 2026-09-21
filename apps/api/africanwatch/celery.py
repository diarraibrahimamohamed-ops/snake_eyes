"""AfricaWatch — Celery"""
import os
from celery import Celery
from celery.schedules import crontab

os.environ.setdefault("DJANGO_SETTINGS_MODULE","africanwatch.settings.dev")
app = Celery("africanwatch")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

app.conf.beat_schedule = {
    "fetch-feeds-hourly": {"task":"africanwatch.apps.threat_intel.tasks.fetch_all_feeds","schedule":crontab(minute=0)},
    "expire-iocs-nightly": {"task":"africanwatch.apps.threat_intel.tasks.expire_old_iocs","schedule":crontab(hour=2,minute=0)},
    "african-threat-score": {"task":"africanwatch.apps.threat_intel.tasks.compute_african_threat_score","schedule":crontab(minute="*/5")},
    "osint-collection": {"task":"africanwatch.apps.osint.tasks.run_all_collections","schedule":crontab(minute="*/30")},
    "scheduled-scans": {"task":"africanwatch.apps.vulns.tasks.run_scheduled_scans","schedule":crontab(hour=1,minute=0)},
    "soc-metrics": {"task":"africanwatch.apps.soc.tasks.update_soc_metrics","schedule":crontab(minute="*/1")},
    "risk-scores": {"task":"africanwatch.apps.ai_engine.tasks.compute_risk_scores","schedule":crontab(hour="*/6")},
    "daily-report": {"task":"africanwatch.apps.dashboard.tasks.generate_daily_report","schedule":crontab(hour=8,minute=0)},
    "correlate-iocs": {"task":"africanwatch.apps.soc.tasks.auto_correlate_iocs","schedule":crontab(minute="*/15")},
}
