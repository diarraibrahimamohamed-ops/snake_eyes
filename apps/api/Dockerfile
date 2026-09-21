FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libpq-dev curl netcat-traditional git nmap && rm -rf /var/lib/apt/lists/*

FROM base AS dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt && python -m spacy download fr_core_news_sm || true

FROM dependencies AS development
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
COPY . .
RUN pip install -r requirements.txt
EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python","manage.py","runserver","0.0.0.0:8000"]

FROM dependencies AS production
COPY . .
RUN printf "#!/bin/bash\nset -e\nuntil nc -z postgres 5432 2>/dev/null; do sleep 1; done\nuntil nc -z redis 6379 2>/dev/null; do sleep 1; done\nfor i in $(seq 1 30); do curl -sf http://elasticsearch:9200/_cluster/health>/dev/null 2>&1 && break; sleep 2; done\npython manage.py migrate --noinput\npython manage.py collectstatic --noinput --clear 2>/dev/null||true\n[ -n \"$DJANGO_SUPERUSER_EMAIL\" ] && python manage.py create_superuser_if_not_exists --email=\"$DJANGO_SUPERUSER_EMAIL\" --password=\"$DJANGO_SUPERUSER_PASSWORD\" 2>/dev/null||true\npython manage.py bootstrap_feeds 2>/dev/null||true\nexec \"$@\"\n" > /entrypoint.sh && chmod +x /entrypoint.sh
RUN addgroup --system aw && adduser --system --ingroup aw aw && chown -R aw:aw /app
USER aw
EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
CMD ["daphne","-b","0.0.0.0","-p","8000","africanwatch.asgi:application"]
