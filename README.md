# AfricaWatch

### Plateforme défensive de cybersécurité, Threat Intelligence, OSINT et réponse SOC

[![Licence : GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://www.python.org/)
[![Django](https://img.shields.io/badge/Django-5.2-green)](https://www.djangoproject.com/)
[![Next.js](https://img.shields.io/badge/Next.js-14-black)](https://nextjs.org/)

AfricaWatch est une plateforme de cybersécurité organisée autour du suivi des actifs, de la Threat Intelligence, de la collecte OSINT, de la gestion des alertes et incidents, de la gestion des vulnérabilités et de l'analyse défensive. Le dépôt contient une API Django/DRF, une interface Next.js et des services asynchrones Celery.

> **État du dépôt :** la branche principale intègre les premières tranches de transformation défensive et de durcissement multi-tenant. Le code, les tests CI et la documentation ne constituent pas à eux seuls une certification de sécurité ni une autorisation de mise en production.

Dernière base vérifiée : `main` — commit `c1943ba0687252d07954e05ad748a47451bc0c95` (29 octobre 2026).

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [État fonctionnel et limites](#état-fonctionnel-et-limites)
- [Architecture](#architecture)
- [Démarrage local](#démarrage-local)
- [API et import de rapports](#api-et-import-de-rapports)
- [Sécurité et modèle multi-tenant](#sécurité-et-modèle-multi-tenant)
- [Tests et qualité](#tests-et-qualité)
- [Licence](#licence)

## Fonctionnalités

| Domaine | Ce que contient le dépôt |
|---|---|
| Organisations et actifs | Comptes, organisations, rôles, inventaire d'actifs et journaux d'audit |
| Threat Intelligence | Indicateurs de compromission (IOC), flux, acteurs et campagnes, avec filtrage selon le niveau TLP sur les chemins couverts |
| SOC | Alertes, incidents, chronologie d'incident, règles de détection et notifications temps réel |
| Gestion des vulnérabilités | Vulnérabilités, suivi de statut et éléments de preuve importés depuis des rapports tiers |
| Import de rapports | Import borné, traitement asynchrone, normalisation des constats et rattachement contrôlé aux actifs existants |
| OSINT | Sources et événements provenant de sources configurées, avec traitement et analyse des données |
| AI Engine | Extraction d'IOC, résumé d'incident et signaux de tendance ; l'usage d'un modèle local est optionnel |
| Intelligence Center | Collecte et enrichissement à partir de sources configurées, avec provenance et métadonnées de partage |
| Malware & Code Lab | Voie d'analyse de fichiers avec quarantaine et moteurs disponibles selon la configuration |
| Interface Web | Tableau de bord, modules de renseignement, SOC, inventaire et vulnérabilités dans l'application Next.js |

La présence d'un module ou d'un connecteur dans le dépôt ne signifie pas que toutes ses intégrations sont configurées, validées ou prêtes pour un service institutionnel.

## État fonctionnel et limites

### Import défensif de rapports

Le parcours privilégié pour intégrer des résultats de scanners consiste à **importer et analyser des rapports déjà produits**, sans lancer automatiquement un scan réseau depuis le processus d'importation.

Formats pris en charge par le parseur :

- Nmap XML
- Nuclei JSON et JSONL
- Nessus XML
- Shodan JSON et CSV

Limites et contrôles implémentés :

- taille maximale d'un rapport : **10 Mio** ;
- plafond de traitement : **20 000 constats par rapport** ;
- empreinte SHA-256 conservée pour vérifier l'intégrité et détecter les doublons au sein d'une organisation ;
- rejet des déclarations DTD/entités dans les rapports Nessus ;
- traitement asynchrone par Celery ; les rapports importés sont traités comme des données, pas comme des commandes ;
- association d'un constat uniquement à un actif existant correspondant dans la même organisation ;
- absence de création automatique d'actifs à partir de noms d'hôtes fournis dans un rapport ;
- constats non associés conservés pour revue, plutôt que rattachés arbitrairement à un actif.

Les contrôles des permissions et les tests disponibles doivent encore être complétés par des essais d'acceptation en staging portant notamment sur le stockage des fichiers, la rétention et les droits d'accès effectifs.

### Évaluations actives désactivées par défaut

Le code historique de l'Offensive Lab et certaines tâches de scan restent dans le dépôt. Le paramètre serveur `ACTIVE_ASSESSMENTS_ENABLED=False` désactive par défaut les évaluations actives à la frontière API et dans les workers Celery. L'exécutable Nmap a été retiré de l'image Docker de l'API.

Cette politique par défaut ne remplace pas une suppression du code historique ni une validation complète des chemins d'exécution. **Ne réactivez pas les évaluations actives en production.** Toute expérimentation doit se dérouler dans un laboratoire isolé, sur un périmètre explicitement autorisé, après vérification des garde-fous et du mécanisme d'arrêt.

### Sécurité multi-tenant

Les dernières modifications ont renforcé les contrôles sur les organisations, actifs, alertes et incidents SOC, les accès aux constats d'importation, les écritures de Threat Intelligence partagée, certains chemins secondaires et les agrégats du tableau de bord. Les collections protégées doivent se fermer par défaut pour un compte sans organisation ; les données Threat Intelligence filtrées par TLP ne doivent pas réapparaître dans les compteurs, statistiques ou chronologies correspondants.

Ces protections couvrent les chemins implémentés et testés, mais ne sont pas une preuve exhaustive de l'absence de défaut de contrôle d'accès dans toutes les routes, tâches, WebSockets et intégrations. Une campagne de tests d'acceptation multi-organisations reste nécessaire.

### Capacités qui ne sont pas certifiées comme prêtes pour la production

- orchestration SOAR complète avec playbooks versionnés, approbations, compensations et journal de preuves validé ;
- partage inter-CERT de production avec cycle complet d'authentification partenaire, gouvernance, révocation et validation des accords de partage ;
- isolation opérationnelle démontrée de tous les workers et connecteurs sortants ;
- contrôles d'accès au stockage des rapports, politique de rétention, sauvegarde et restauration éprouvées en environnement cible ;
- preuve de l'intégrité des journaux avec ancrage externe protégé ;
- validation de performance, gestion des incidents et procédures opérationnelles d'un déploiement institutionnel.

## Architecture

```text
snake_eyes/
├── apps/
│   ├── api/                    # Django REST Framework, règles métier et workers Celery
│   │   └── africanwatch/apps/
│   │       ├── organizations/  # Comptes, organisations, actifs et audit
│   │       ├── threat_intel/   # IOC, flux, acteurs et campagnes
│   │       ├── soc/            # Alertes, incidents et règles
│   │       ├── osint/          # Sources et événements OSINT
│   │       ├── vulns/          # Vulnérabilités et import de rapports
│   │       ├── ai_engine/      # Analyse, résumé et tendances
│   │       └── dashboard/      # Statistiques et visualisations
│   └── web/                    # Frontend Next.js
├── infra/                      # Configuration d'infrastructure et du scanner
├── security-lab/               # Répertoires locaux de quarantaine/outils
├── docker-compose.yml
├── .env.example
├── Makefile
└── docs/DEFENSIVE_TRANSFORMATION_AUDIT.md
```

### Stack technique

- **API :** Python 3.12, Django 5.2, Django REST Framework
- **Frontend :** Next.js 14, React et TypeScript
- **Données et tâches :** PostgreSQL, Redis, Celery et Celery Beat
- **Qualité :** pytest/pytest-django, Ruff, ESLint, TypeScript, build Next.js et scan Trivy via GitHub Actions
- **Composants optionnels :** Elasticsearch/Kibana, Kafka, Prometheus/Grafana, Ollama, Tor et scanner malware selon le profil Docker activé

## Démarrage local

Le Compose standard est orienté développement. Il définit des valeurs de démonstration dans `.env.example` : il faut les remplacer avant toute utilisation avec des données réelles.

### 1. Cloner et configurer l'environnement

```bash
git clone https://github.com/diarraibrahamohamed-ops/snake_eyes.git
cd snake_eyes
cp .env.example .env
```

Avant de démarrer, éditez `.env` et configurez au minimum un secret Django fort et unique, les mots de passe PostgreSQL/Redis, les hôtes autorisés et les origines CORS adaptées à votre poste. Gardez `DEBUG=True` uniquement pour le développement local. Ne commitez jamais le fichier `.env`.

### 2. Démarrer les services de base

```bash
make up
make migrate
make createsuperuser
```

Accès local :

| Service | Adresse locale |
|---|---|
| Interface Web | http://localhost:3000 |
| API REST | http://localhost:8000 |
| Documentation API | http://localhost:8000/api/docs/ |
| Schéma OpenAPI | http://localhost:8000/api/schema/ |
| Santé de l'application | http://localhost:8000/health/ |

Les ports de l'API, du frontend, de PostgreSQL et de Redis sont liés à l'interface locale dans le Compose principal. N'exposez pas ces services sur un réseau public sans une configuration de production adaptée.

### Profils optionnels

```bash
make lab       # Elasticsearch, Kafka et outils de monitoring
make ai        # Ollama local (ressources supplémentaires requises)
make intel     # Service Tor optionnel, pour la collecte passive configurée
make security  # Scanner malware optionnel
make down      # Arrêter la stack
```

Ces profils augmentent la consommation de ressources et peuvent nécessiter des réglages supplémentaires. Les activer ne signifie pas que tous les connecteurs sont configurés.

### Commandes utiles

```bash
make logs
make shell
make test
make lint
make typecheck
make backup
```

Le contrôle CI est ciblé sur la syntaxe Python, les noms non définis et certains contrôles Ruff sur les modules concernés. La commande locale `make lint` exécute un contrôle plus large qui peut révéler une dette de style préexistante ; le résultat du CI ciblé ne doit pas être interprété comme une remise à zéro de toute cette dette.

## API et import de rapports

### Authentification

L'API utilise un jeton JWT. Après avoir créé votre compte administrateur local, récupérez un jeton avec vos propres identifiants :

```bash
TOKEN=$(curl -sS -X POST http://localhost:8000/api/v1/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"email":"VOTRE_EMAIL","password":"VOTRE_MOT_DE_PASSE"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access'])")
```

Exemples de lecture :

```bash
curl "http://localhost:8000/api/v1/iocs/?is_african_threat=true&severity=critical" \
  -H "Authorization: Bearer $TOKEN"

curl "http://localhost:8000/api/v1/dashboard/stats/" \
  -H "Authorization: Bearer $TOKEN"
```

### Importer un rapport de scan existant

L'exemple suivant importe un rapport Nuclei JSONL. Utilisez un fichier généré précédemment par un outil autorisé :

```bash
curl -X POST "http://localhost:8000/api/v1/report-ingestions/upload/" \
  -H "Authorization: Bearer $TOKEN" \
  -F "source_type=nuclei_jsonl" \
  -F "file=@nuclei-report.jsonl"
```

Autres valeurs possibles pour `source_type` : `nmap_xml`, `nuclei_json`, `nessus_xml`, `shodan_json` et `shodan_csv`.

Routes associées :

| Méthode | Route | Objet |
|---|---|---|
| POST | `/api/v1/report-ingestions/upload/` | Importer le rapport |
| GET | `/api/v1/report-ingestions/` | Lister les imports visibles par le compte |
| GET | `/api/v1/report-ingestions/{id}/` | Consulter le statut et les métadonnées d'un import |
| GET | `/api/v1/report-findings/?report={id}` | Consulter les constats normalisés d'un rapport |

L'import nécessite un utilisateur authentifié ayant un rôle opérationnel autorisé et rattaché à une organisation. Un administrateur global sans organisation doit préciser l'organisation cible conformément à l'API. Les fichiers importés sont limités à 10 Mio et traités de façon asynchrone.

## Sécurité et modèle multi-tenant

Le projet définit les rôles `viewer`, `analyst`, `threat_hunter`, `org_admin` et `super_admin`. Les autorisations dépendent de l'action et du module : une lecture, une modification d'actif, une acceptation de risque et une modification de données Threat Intelligence partagées n'ont pas les mêmes exigences.

Principes implémentés dans les chemins couverts par les contrôles et tests :

- filtrage des ressources organisationnelles et fermeture par défaut des collections tenant-scoped pour les comptes sans organisation ;
- vérification du rôle pour les actions sensibles de gestion des vulnérabilités, avec approbation du risque réservée aux administrateurs d'organisation ;
- filtrage TLP de certains ensembles et agrégats de Threat Intelligence ;
- clés de cache du tableau de bord séparées par organisation et niveau TLP ;
- analyse hors ligne des rapports importés et vérification de leur empreinte SHA-256 ;
- évaluations actives désactivées par défaut par la politique serveur.

Points d'attention avant un déploiement réel :

1. tester toutes les routes API, permissions objet, tâches Celery et groupes WebSocket avec plusieurs organisations et tous les rôles ;
2. confirmer les ACL de stockage, le chiffrement, la rétention et la suppression des rapports ;
3. vérifier l'isolation réseau, les privilèges et les limites de ressources des workers ;
4. valider les configurations de production, TLS, secrets, sauvegarde/restauration et journaux d'audit ;
5. examiner tous les connecteurs qui établissent des connexions sortantes, notamment les collecteurs OSINT et les flux de Threat Intelligence.

Le moteur d'IA local utilise Ollama lorsque cette intégration est activée et configurée. Les connecteurs OSINT, Threat Intelligence et autres services optionnels peuvent effectuer des communications réseau : ne supposez pas que toutes les données restent locales simplement parce qu'un moteur LLM local est disponible.

## Tests et qualité

Le workflow `.github/workflows/defensive-ci.yml` est déclenché sur les pull requests vers `main`. Il exécute :

- tests Django/API avec PostgreSQL et Redis ;
- vérifications syntaxiques Python et contrôles Ruff ciblés ;
- ESLint, TypeScript et build Next.js de production ;
- analyse du dépôt avec Trivy pour les vulnérabilités HIGH et CRITICAL non ignorées comme non corrigibles.

La dernière validation complète de la tranche de durcissement multi-tenant a passé les quatre jobs sur le commit testé avant sa fusion. Le résultat peut être consulté dans [GitHub Actions](https://github.com/diarraibrahamohamed-ops/snake_eyes/actions/runs/40800370761). Cette validation CI ne remplace pas une campagne d'acceptation sur l'environnement de staging cible.

La feuille de route, les risques résiduels et les critères d'acceptation détaillés sont décrits dans [l'audit de transformation défensive](docs/DEFENSIVE_TRANSFORMATION_AUDIT.md).

## Licence

Ce dépôt contient le fichier de licence **GNU General Public License, version 2 (GPL-2.0)**. Consultez le fichier [LICENSE](LICENSE) pour les conditions de redistribution et de modification.

---

**AfricaWatch — conçu pour renforcer les capacités défensives de cybersécurité et de partage de renseignement, avec des limites explicites et des garanties vérifiables.**
