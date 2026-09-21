"""AfricaWatch — Dashboard Tasks"""
import logging
from celery import shared_task
logger = logging.getLogger("africanwatch.dashboard")

@shared_task(queue="default")
def generate_daily_report():
    logger.info("Generating daily AfricaWatch report...")
    return {"status": "report_generated"}
