#!/bin/bash
set -e

echo "Starting AfricaWatch..."
echo "Waiting for postgres..."
until nc -z postgres 5432 2>/dev/null; do 
  echo "Postgres not ready yet..."
  sleep 1
done
echo "Postgres is ready!"

echo "Waiting for redis..."
until nc -z redis 6379 2>/dev/null; do 
  echo "Redis not ready yet..."
  sleep 1
done
echo "Redis is ready!"

echo "Waiting for elasticsearch..."
for i in $(seq 1 30); do 
  if curl -sf http://elasticsearch:9200/_cluster/health>/dev/null 2>&1; then
    echo "Elasticsearch is ready!"
    break
  fi
  echo "Elasticsearch not ready yet... (attempt $i/30)"
  sleep 2
done

echo "Running migrations..."
python manage.py migrate --noinput || {
  echo "MIGRATIONS FAILED"
  exit 1
}

echo "Collecting static files..."
python manage.py collectstatic --noinput --clear 2>/dev/null || true

echo "Creating superuser if needed..."
if [ -n "$DJANGO_SUPERUSER_EMAIL" ]; then
  python manage.py create_superuser_if_not_exists --email="$DJANGO_SUPERUSER_EMAIL" --password="$DJANGO_SUPERUSER_PASSWORD" 2>/dev/null || echo "Superuser creation failed (may already exist)"
fi

echo "Bootstrapping feeds..."
python manage.py bootstrap_feeds 2>/dev/null || echo "Bootstrap feeds failed (may be optional)"
python manage.py seed_security_tools 2>/dev/null || echo "Security tool catalog seed failed (may be optional)"

echo "Starting Django server..."
exec "$@"
