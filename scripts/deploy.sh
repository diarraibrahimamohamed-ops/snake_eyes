#!/bin/bash
set -e
ENVIRONMENT=${1:-production}
echo "Deploying AfricaWatch — $ENVIRONMENT"
command -v docker >/dev/null 2>&1 || { echo "Docker required"; exit 1; }
git pull origin main
docker compose build --no-cache api web
docker compose up -d --no-deps api web celery_worker celery_beat
docker compose exec api python manage.py migrate --noinput
docker compose exec api python manage.py collectstatic --noinput
echo "Deployment complete"
docker compose ps
