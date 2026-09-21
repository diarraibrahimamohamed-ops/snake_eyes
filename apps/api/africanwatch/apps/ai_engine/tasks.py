"""AfricaWatch — AI Engine Tasks"""
import logging
from celery import shared_task

logger = logging.getLogger("africanwatch.ai")

@shared_task(queue="ai")
def compute_risk_scores():
    from africanwatch.apps.organizations.models import Asset
    from africanwatch.apps.vulns.models import Vulnerability
    updated = 0
    for asset in Asset.objects.filter(is_active=True):
        vulns = Vulnerability.objects.filter(asset=asset, status="open")
        c = vulns.filter(severity="critical").count()
        h = vulns.filter(severity="high").count()
        m = vulns.filter(severity="medium").count()
        score = min(100, c*25 + h*10 + m*3)
        if asset.risk_score != score:
            asset.risk_score = score
            asset.save(update_fields=["risk_score"])
            updated += 1
    logger.info(f"Risk scores updated: {updated} assets")
    return {"updated": updated}
