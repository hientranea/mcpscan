from celery import Celery
from shared.config import settings

# Create Celery app
celery_app = Celery(
    "mcpscan",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    worker_prefetch_multiplier=1,  # Process one task at a time
    task_acks_late=True,  # Acknowledge task after execution
)
celery_app.autodiscover_tasks(["scanner"])
