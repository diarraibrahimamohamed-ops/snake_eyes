.PHONY: help up lab ai intel security down build logs test lint seed

GREEN=\033[0;32m
CYAN=\033[0;36m
RESET=\033[0m

help:
	@echo ""
	@echo "  $(CYAN)AFRICANWATCH$(RESET)"
	@echo ""
	@echo "  $(GREEN)up$(RESET)              Mode LITE (8 Go RAM recommandé)"
	@echo "  $(GREEN)lab$(RESET)             Ajouter Elastic/Kafka/monitoring"
	@echo "  $(GREEN)ai$(RESET)              Ajouter Ollama (modèle léger)"
	@echo "  $(GREEN)intel$(RESET)           Activer le collecteur Onion/Tor (passif)"
	@echo "  $(GREEN)security$(RESET)        Activer le lab malware / code"
	@echo "  $(GREEN)down$(RESET)            Arrêter"
	@echo "  $(GREEN)build$(RESET)           Rebuild images"
	@echo "  $(GREEN)logs$(RESET)            Logs temps réel"
	@echo "  $(GREEN)migrate$(RESET)         Appliquer les migrations"
	@echo "  $(GREEN)seed$(RESET)            Charger les données de démo"
	@echo "  $(GREEN)test$(RESET)            Lancer les tests"
	@echo "  $(GREEN)lint$(RESET)            Linter le code"
	@echo "  $(GREEN)shell$(RESET)           Shell Django"
	@echo "  $(GREEN)backup$(RESET)          Sauvegarder la base"
	@echo ""

up:
	@echo "$(CYAN)Démarrage AfricaWatch...$(RESET)"
	@cp -n .env.example .env 2>/dev/null || true
	docker compose up -d
	@echo "$(GREEN)Mode LITE démarré$(RESET)"
	@echo ""
	@echo "  Frontend  → http://localhost:3000"
	@echo "  API       → http://localhost:8000"
	@echo "  API Docs  → http://localhost:8000/api/docs/"
	@echo "  Health    → http://localhost:8000/health/"
	@echo "  Kibana    → http://localhost:5601"
	@echo "  Offensive Lab → http://localhost:3000/offensive-lab"
	@echo "  Pour le stack lourd : make lab"
	@echo "  Pour l'IA légère  : make ai"
	@echo ""

lab:
	docker compose --profile lab up -d

ai:
	docker compose --profile ai up -d
	@echo "Installe ensuite un petit modèle : docker compose --profile ai exec ollama ollama pull qwen2.5:1.5b-instruct-q3_K_S"

intel:
	docker compose --profile intel up -d

security:
	docker compose --profile security up -d

down:
	docker compose down

down-v:
	docker compose down -v

build:
	docker compose build --no-cache

ps:
	docker compose ps

logs:
	docker compose logs -f

logs-api:
	docker compose logs -f api celery_worker celery_beat

logs-web:
	docker compose logs -f web

restart-api:
	docker compose restart api celery_worker celery_beat

shell:
	docker compose exec api python manage.py shell_plus

shell-db:
	docker compose exec postgres psql -U aw_user -d africanwatch

migrate:
	docker compose exec api python manage.py migrate

makemigrations:
	docker compose exec api python manage.py makemigrations

seed:
	@echo "$(CYAN)Chargement données de démo...$(RESET)"
	docker compose exec api python manage.py seed_db
	@echo "$(GREEN)Done$(RESET)"

bootstrap-feeds:
	@echo "$(CYAN)Bootstrap flux TI...$(RESET)"
	docker compose exec api python manage.py bootstrap_feeds
	@echo "$(GREEN)Done$(RESET)"

createsuperuser:
	docker compose exec api python manage.py createsuperuser

test:
	docker compose exec api pytest -v --tb=short

test-cov:
	docker compose exec api pytest --cov=. --cov-report=html --cov-report=term-missing

lint:
	docker compose exec api ruff check .
	docker compose exec web npm run lint

format:
	docker compose exec api ruff format .

typecheck:
	docker compose exec web npm run typecheck

backup:
	@mkdir -p backups
	docker compose exec postgres pg_dump -U aw_user africanwatch | gzip > backups/backup_$$(date +%Y%m%d_%H%M%S).sql.gz
	@echo "$(GREEN)Backup créé$(RESET)"

.DEFAULT_GOAL := help


offensive-status:
	@docker compose exec celery_worker sh -lc 'command -v nmap >/dev/null && echo "nmap: OK" || echo "nmap: ABSENT"; command -v nuclei >/dev/null && echo "nuclei: OK" || echo "nuclei: optionnel/ABSENT"'

security-tools:
	@echo "Security Lab roots: ./security-lab/{code,containers,credentials,wordlists}"
	@echo "Run the API/worker normally, then use /security-lab for assessments."

security-tool-catalog:
	docker compose run --rm api python manage.py seed_security_tools

intel-seed:
	docker compose run --rm api python manage.py seed_intelligence_sources
