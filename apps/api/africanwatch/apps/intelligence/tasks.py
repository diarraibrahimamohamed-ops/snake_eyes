from celery import shared_task
@shared_task(queue="osint")
def run_collection_task(run_id: str):
    from .services import run_collection
    return run_collection(run_id)
@shared_task(queue="ai")
def compute_forecast_task(organization_id: str):
    from .forecast import compute_forecasts
    return [{"id": str(x.id), "signal_type": x.signal_type, "level": x.level, "score": x.score} for x in compute_forecasts(organization_id)]
