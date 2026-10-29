# 🛡️ AfricaWatch
### Plateforme Africaine de Cybersécurité, Threat Intelligence & OSINT

[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://python.org)
[![Django](https://img.shields.io/badge/Django-5.2-green)](https://djangoproject.com)
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
| 🤖 **AI Engine** | Extraction IOCs, Résumés LLM local, Signaux de tendance |
| 🌍 **African Context** | Score menace africain, BGP, Mobile Money, langues locales |
| 🛰️ **Intelligence Center v6** | Reconnaissance passive, RDAP/DNS/CT, GDELT, sources Web/Social publiques, Onion allowlisté, provenance et corrélation |
| 🧪 **Malware & Code Lab v6** | Quarantaine, SHA-256, ClamAV, YARA, SAST, limites anti-archive-bomb, scanner isolé |

---

## 🛡️ Profil institutionnel défensif

La transformation défensive institutionnelle a été fusionnée dans `main` au commit `0dba01a293e3e1abc0900be6d8238d08a1f381c9`. Les évaluations réseau actives sont **désactivées par défaut** par le paramètre serveur `ACTIVE_ASSESSMENTS_ENABLED=False`. L'API et le worker Celery appliquent tous deux cette politique. Le chemin privilégié est l'import de rapports d'outils tiers, leur normalisation, leur rattachement aux actifs autorisés et leur corrélation avec la Threat Intelligence. N'activez pas les évaluations actives en production ; toute activation expérimentale doit rester explicite et confinée à un laboratoire isolé.

La cartographie de l'existant, les écarts documentés/non démontrés et la feuille de route se trouvent dans [`docs/DEFENSIVE_TRANSFORMATION_AUDIT.md`](docs/DEFENSIVE_TRANSFORMATION_AUDIT.md). Les éléments présents dans le code ne sont pas automatiquement considérés comme validés en production : les tests d'intégration, l'isolation des workers et les contrôles de séparation des tenants restent des critères de livraison.

## 🧭 Mode LITE et Offensive Lab

Le projet démarre désormais en **mode LITE** pour une machine de 8 Go de RAM : PostgreSQL, Redis, API, Celery et frontend. Elasticsearch, Kafka, Kibana et le monitoring lourd sont optionnels (`make lab`). L’IA locale est optionnelle (`make ai`) et peut utiliser un petit modèle Ollama ; le code conserve un fallback déterministe lorsqu’elle est désactivée.

Le module historique `Offensive Lab` reste dans le dépôt, mais les évaluations actives sont **désactivées par défaut** par `ACTIVE_ASSESSMENTS_ENABLED=False`. La politique est vérifiée à la frontière API et dans les workers Celery. La page de navigation principale privilégie l'import de rapports. N'activez le runner historique qu'en laboratoire isolé, pour un périmètre explicitement autorisé, et après validation des contrôles.


## 🛰️ Intelligence Center v6

Le nouveau centre de renseignement sépare clairement la collecte passive de l'assessment actif. Il enrichit les domaines et IP par DNS/RDAP/Certificate Transparency, collecte des contenus publics, accepte des sources Web/Social publiques sous forme d'URL modèle `{target}`, et fournit une voie Onion via Tor avec allowlist. Chaque observation est hashée et enrichie d'une provenance, d'une note de fiabilité, d'une confiance, d'une actionnabilité, d'une corroboration et d'un TLP.

Les contenus multilingues sont triés en français, anglais, arabe, haoussa, fulfulde et bambara. Les signaux d'influence nuisible sont traités comme des indicateurs de triage et ne servent pas à profiler ou persuader politiquement des personnes.

## 🧪 Malware & Code Lab v6

Les fichiers entrants sont placés dans une quarantaine propre au tenant. Le moteur calcule le SHA-256, refuse les fichiers trop gros ou les archives potentiellement explosives, puis lance les moteurs disponibles : ClamAV, YARA et SAST. Les fichiers soumis ne sont jamais exécutés par le système. Le scanner optionnel tourne sans réseau, sans privilèges et en lecture seule sur la quarantaine.

## 🕵️ Collecte discrète — limite technique

La confidentialité de la collecte est une propriété différente de l'effacement de traces. AfricaWatch n'essaie pas de supprimer ou contourner les journaux d'une infrastructure distante. Tor est limité à la collecte passive de sources Onion autorisées ; les scans actifs restent dans l'Offensive Lab avec scope, autorisation, audit et kill-switch.

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
- Journal d’audit applicatif; l’immutabilité et l’ancrage externe des journaux restent à valider en déploiement
- Prise en charge de champs TLP; l’application systématique des règles de partage doit être validée par flux
- Rate limiting API + protection anti-brute force (Axes)
- LLM local Ollama — aucune donnée ne quitte l'infrastructure

---

## 📜 Licence

GPL v2 (voir `LICENSE`) — licence libre à copyleft; l’usage commercial est permis sous réserve du respect des conditions de la licence.
Les déploiements pour CERTs africains et universités peuvent suivre les modalités du projet.

**Construit en Afrique. Pour l'Afrique. Et le monde.**

## Offensive Lab — état de disponibilité

Le code historique d’évaluation active reste présent pour préserver les artefacts et tests du projet, mais les tâches et lancements d’assessment sont **désactivés par défaut côté serveur**. Une interface ou un endpoint qui existe dans le dépôt ne constitue pas une autorisation de production. Avant toute expérimentation, il faut activer explicitement la politique uniquement dans un laboratoire isolé, documenter l’autorisation et tester le kill-switch, le contrôle de cible et l’isolation réseau. Pour l'usage institutionnel courant, privilégiez l'import de rapports hors ligne via `/report-ingestion`.

## Security Lab — application, DB et outillage

La V5 ajoute un espace `Security Lab` pour les contrôles défensifs. Les capacités réellement disponibles doivent être distinguées des plans et des outils simplement détectés.

- OWASP/API et contrôles de configuration déclaratifs
- audit PostgreSQL en lecture seule, avec périmètre organisationnel
- SAST/SCA local via Semgrep/Trivy et audit de secrets via Gitleaks
- OWASP ZAP Baseline en mode non intrusif lorsqu'il est configuré
- audit de politique de format de hash hors ligne : métadonnées/formats uniquement, sans craquage de mots de passe ni vérification d'identifiants
- Hydra/sqlmap : planification ou vérification de disponibilité uniquement; aucune exécution ne doit être lancée depuis l’API

Les affirmations de disponibilité des outils doivent être confirmées par les tests et la configuration du déploiement.