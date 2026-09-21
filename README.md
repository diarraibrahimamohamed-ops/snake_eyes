# 🛡️ AfricaWatch
### Plateforme Africaine de Cybersécurité, Threat Intelligence & OSINT

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://python.org)
[![Django](https://img.shields.io/badge/Django-5.0-green)](https://djangoproject.com)
[![Next.js](https://img.shields.io/badge/Next.js-14-black)](https://nextjs.org)

> *La première plateforme de cybersécurité souveraine conçue pour et par l'Afrique.*

---

## 🚀 Démarrage en 3 commandes

```bash
git clone https://github.com/YOUR_ORG/africanwatch.git
cd africanwatch
make up
```

Après ~2 minutes :

| Service | URL |
|---|---|
| 🖥️ Dashboard | http://localhost:3000 |
| 🔌 API REST | http://localhost:8000 |
| 📚 API Docs | http://localhost:8000/api/docs/ |
| ❤️ Health | http://localhost:8000/health/ |
| 📊 Kibana | http://localhost:5601 |
| 📈 Grafana | http://localhost:3001 |

**Environnement de démo :** configurez vos propres identifiants via `.env`. Aucun mot de passe de démonstration n’est destiné à la production.

---

## 🏗️ Architecture

```
africanwatch/
├── apps/
│   ├── api/                    # Backend Django 5
│   │   └── africanwatch/
│   │       ├── apps/
│   │       │   ├── organizations/  # Users, Orgs, Assets, Audit
│   │       │   ├── threat_intel/   # IOCs, Feeds, Actors, Campaigns
│   │       │   ├── soc/            # Alerts, Incidents, Rules
│   │       │   ├── osint/          # Sources, Events, NLP
│   │       │   ├── vulns/          # Vulnerabilities, Scans
│   │       │   ├── ai_engine/      # Analysis, Summarization, Prediction
│   │       │   └── dashboard/      # Stats, Maps, Metrics
│   │       ├── consumers.py        # WebSocket temps réel
│   │       └── celery.py           # Tâches planifiées
│   └── web/                    # Frontend Next.js 14
│       └── src/
│           ├── app/            # Pages (dashboard, IOCs, SOC, OSINT, Vulns...)
│           ├── components/     # ThreatMap, widgets, Sidebar
│           ├── lib/            # API client, stores Zustand
│           └── hooks/          # WebSocket hook
├── infra/docker/               # Nginx, Postgres, Prometheus, Grafana, TheHive
├── docker-compose.yml
└── Makefile
```

---

## 🧩 Modules

| Module | Description |
|---|---|
| 🦠 **Threat Intelligence** | IOCs, Flux (MISP/OTX/STIX/TAXII), Campagnes, Acteurs |
| 🌐 **OSINT Engine** | News africaines, Telegram, RSS, GitHub, NLP multilingue |
| 🔴 **SOC Center** | Alertes WebSocket, Incidents, Règles Sigma/YARA |
| 🔍 **Vulnerability Mgmt** | Scan Nuclei/Nmap, CVSS, Remédiation |
| 🤖 **AI Engine** | Extraction IOCs, Résumés LLM local, Prédiction |
| 🌍 **African Context** | Score menace africain, BGP, Mobile Money, langues locales |

---

## 🧭 Mode LITE et Offensive Lab

Le projet démarre désormais en **mode LITE** pour une machine de 8 Go de RAM : PostgreSQL, Redis, API, Celery et frontend. Elasticsearch, Kafka, Kibana et le monitoring lourd sont optionnels (`make lab`). L’IA locale est optionnelle (`make ai`) et peut utiliser un petit modèle Ollama ; le code conserve un fallback déterministe lorsqu’elle est désactivée.

**Offensive Lab** ajoute une couche d’évaluation active sous contrôle : un opérateur crée un engagement, indique une référence d’autorisation, associe des actifs existants, active une fenêtre temporelle et lance uniquement des profils de reconnaissance/configuration prédéfinis. Les commandes sont construites côté serveur ; il n’existe pas d’exécution shell arbitraire depuis l’API. Les cibles privées/réservées restent bloquées sauf `LAB_MODE=True` dans un environnement isolé.

Profils disponibles : `dns_recon`, `dns_posture`, `web_recon`, `web_posture`, `tls_audit`, `port_recon`, `exposure_audit`, `adversary_recon`, `exposure_chain`, `nuclei_safe`, `combined_recon`. Le Lab ajoute un préflight d’engagement, une analyse de chaîne d’exposition, une estimation de visibilité SOC et une comparaison avec l’assessment précédent. Chaque job produit un condensat SHA-256 de son résultat et participe à une chaîne d’événements vérifiable.

## 🛠️ Commandes

```bash
make up              # Démarrer le mode LITE
make lab             # Activer Elastic/Kafka/monitoring
make ai              # Activer Ollama optionnel
make down            # Arrêter
make logs            # Logs temps réel
make shell           # Shell Django
make migrate         # Migrations
make seed            # Données de démo
make bootstrap-feeds # Flux TI publics
make test            # Tests
make lint            # Linter
make backup          # Sauvegarde DB
```

---

## 🔑 API Quick Start

```bash
# Utilisez les identifiants que vous avez définis dans .env
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"email":"VOTRE_EMAIL","password":"VOTRE_MOT_DE_PASSE"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access'])")

# IOCs africains critiques
curl "http://localhost:8000/api/v1/iocs/?is_african_threat=true&severity=critical" \
  -H "Authorization: Bearer $TOKEN"

# Stats dashboard
curl "http://localhost:8000/api/v1/dashboard/stats/" \
  -H "Authorization: Bearer $TOKEN"

# Lookup d'un IOC
curl "http://localhost:8000/api/v1/iocs/lookup/?value=197.234.45.123" \
  -H "Authorization: Bearer $TOKEN"
```

---

## 🔐 Sécurité

- JWT avec rotation automatique des tokens
- MFA TOTP pour les admins
- RBAC : SuperAdmin → OrgAdmin → Analyst → ThreatHunter → Viewer
- Audit log immuable de toutes les actions
- TLP (Traffic Light Protocol) appliqué sur toutes les données
- Rate limiting API + protection anti-brute force (Axes)
- LLM local Ollama — aucune donnée ne quitte l'infrastructure

---

## 📜 Licence

AGPL v3 — Libre pour usage non-commercial et institutionnel.
Déploiements gratuits pour CERTs africains et universités.

**Construit en Afrique. Pour l'Afrique. Et le monde.**

## Offensive Lab — mode d'assessment contrôlé

Le module `offensive_lab` sert à orchestrer des évaluations de sécurité **autorisées** sur des actifs préalablement enregistrés dans l'organisation. Il ne fournit pas d'exécution de commandes arbitraires, d'exploitation, de vol d'identifiants, de persistance ou de mouvement latéral. Les profils actifs sont volontairement conçus pour de la reconnaissance et de la validation de surface.

### Profils disponibles

- `dns_recon` : A/AAAA/MX/NS/TXT/CNAME + résolution contrôlée.
- `web_recon` : HTTP, en-têtes de sécurité, bannière serveur, titre HTML et indices technologiques.
- `tls_audit` : protocole, chiffrement, certificat, expiration et détection de protocoles anciens.
- `port_recon` : Nmap `-sT -sV --version-light --top-ports 100`, sans scripts NSE et sans options d'évasion.
- `exposure_audit` : corrélation web + ports + règles de surface d'exposition.
- `nuclei_safe` : adaptateur optionnel Nuclei limité à `info/low/medium` avec tags d'exposition/misconfiguration/TLS/technologie et exclusions des catégories intrusives/exploitatives.
- `combined_recon` : chaîne DNS + Web + TLS + ports.

### Garde-fous

Une mission doit avoir une référence d'autorisation, une fenêtre temporelle, au moins une cible enregistrée et une approbation humaine. Toute modification du périmètre invalide l'approbation et force une nouvelle validation. Chaque job enregistre le hash du périmètre au lancement, un nonce d'exécution, le hash du résultat et une chaîne d'événements SHA-256 vérifiable.

Les URL et cibles sont soumises à une validation anti-SSRF. Les cibles privées/réservées restent bloquées par défaut et ne deviennent disponibles qu'en `LAB_MODE=True` côté serveur **et** sur un engagement marqué `lab_mode=True`.

Le `SECURITY_ASSESSMENT_KILL_SWITCH=True` bloque immédiatement les nouveaux scans sans arrêter la plateforme.

### Threat-informed red team

Le raisonnement « attaquant » est simulé par l'analyse des points d'entrée, des services exposés, des contrôles Web/DNS, des changements de surface et des lacunes de télémétrie. Le système ne fournit pas de mécanisme d'exploitation, de credential attack, de persistance, de mouvement latéral ou d'évasion.

Les endpoints utiles sont : `GET /api/v1/engagements/{id}/preflight/`, `GET /api/v1/engagements/{id}/adversary_plan/`, `GET /api/v1/assessment-jobs/{id}/report/`, `GET /api/v1/assessment-jobs/{id}/attack_path/` et `GET /api/v1/assessment-jobs/{id}/integrity/`.

### Architecture 8 Go

Le mode LITE est recommandé sur les postes disposant de 8 Go de RAM : PostgreSQL + Redis + API + Celery + frontend. Elasticsearch, Kafka, Kibana, Prometheus et Grafana restent derrière le profil `lab`. Ollama est séparé derrière le profil `ai` et limité à un modèle chargé et une exécution parallèle.

## Security Lab — application, DB et outillage

La V5 ajoute un espace `Security Lab` qui complète l'Offensive Lab sans transformer l'API en moteur d'exploitation autonome.

- OWASP Top 10:2025 / API Security Top 10:2023 / WSTG / ASVS 5.0.0
- audit Web et OpenAPI, avec contrôles de configuration et d'authentification déclarative
- audit PostgreSQL en lecture seule, avec DSN isolés par organisation
- SAST/SCA local via Semgrep/Trivy et audit de secrets via Gitleaks
- OWASP ZAP Baseline en plan DAST non intrusif
- John the Ripper en audit de hashes strictement hors-ligne et opt-in
- Hashcat en outil de station dédiée, non lancé par l'API
- Hydra et sqlmap en mode readiness/plan seulement

Les profils réseau utilisent toujours le périmètre d'engagement, le kill-switch, les limites de concurrence et les contrôles SSRF existants.
