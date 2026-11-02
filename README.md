# AfricaWatch

### Plateforme défensive de cybersécurité, Threat Intelligence, OSINT et réponse SOC

[![Licence : GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://www.python.org/)
[![Django](https://img.shields.io/badge/Django-5.2-green)](https://www.djangoproject.com/)
[![Next.js](https://img.shields.io/badge/Next.js-14-black)](https://nextjs.org/)

AfricaWatch est une plateforme défensive composée d'une API Django/DRF, d'une interface Next.js et de workers Celery. Elle regroupe l'inventaire des actifs, la Threat Intelligence, la collecte OSINT passive, le suivi SOC, la gestion des vulnérabilités, l'analyse de fichiers et des outils d'évaluation de sécurité.

> **Périmètre et assurance.** Ce dépôt contient du code applicatif, des tests et des configurations de développement. Leur présence ne constitue ni une certification de sécurité, ni une validation opérationnelle de tous les connecteurs, ni une autorisation de mise en production. Les évaluations actives restent désactivées par défaut.

**Révision documentaire : 2 novembre 2026.** Le snapshot de code candidat vérifié pour cette documentation est le commit `2f07cf7` de la branche de travail associée à la PR #8, construite sur `main` au commit `93ccb71`. La CI du commit testé a réussi sur ses quatre jobs ; les vérifications de staging et de déploiement restent distinctes. Voir [GitHub Actions](https://github.com/diarraibrahimamohamed-ops/snake_eyes/actions/runs/41372748323).

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [État fonctionnel et limites](#état-fonctionnel-et-limites)
- [Architecture](#architecture)
- [Démarrage local](#démarrage-local)
- [API principales](#api-principales)
- [Sécurité et modèle multi-tenant](#sécurité-et-modèle-multi-tenant)
- [Tests et qualité](#tests-et-qualité)
- [Documentation détaillée](#documentation-détaillée)
- [Licence](#licence)

## Fonctionnalités

| Domaine | Capacités présentes dans le dépôt |
|---|---|
| Organisations et actifs | Comptes, organisations, rôles, inventaire d'actifs et journaux d'audit |
| Threat Intelligence | IOC, flux, observations, relations, enrichissements et partage selon les contrôles TLP couverts |
| Intelligence Center | Collectes passives, provenance, export STIX, corrélation d'IOC et Evidence Ledger |
| Dashboard | Statistiques, alertes, IOC, activité OSINT et agrégats de menaces par pays alimentés par l'API |
| SOC | Alertes, incidents, règles de détection, chronologie et notifications |
| Vulnérabilités | Suivi des vulnérabilités et import/normalisation de rapports de scanners tiers |
| OSINT | Sources et événements provenant de sources configurées |
| Malware & Code Lab | Quarantaine, précontrôles, analyse statique et moteurs ClamAV/YARA/Semgrep selon la configuration |
| Security Lab | Contrôles Web/API, posture PostgreSQL, SAST/SCA, secrets et plans de tests non exécutants |
| Offensive Lab | Code de reconnaissance/assessment autorisé, protégé par une politique serveur désactivée par défaut |
| AI Engine | Extraction d'IOC, assistance à l'analyse et tendances heuristiques ; IA locale optionnelle |

Une fonctionnalité listée ici décrit du code disponible, pas nécessairement un service entièrement intégré, configuré, mesuré et prêt pour un usage institutionnel.

## État fonctionnel et limites

### Dashboard alimenté par l'API

Le tableau de bord récupère les statistiques, alertes, IOC, événements OSINT et données cartographiques depuis les endpoints existants. La carte agrège les IOC par pays et sévérité ; l'API ne renvoie pas les coordonnées individuelles des IOC dans cette réponse. Les positions affichées sur la carte sont des repères de représentation au niveau national, pas la géolocalisation d'un incident. Le frontend distingue les états vides, indisponibles et les dernières données conservées, avec une actualisation périodique.

### Intelligence Center et Evidence Ledger

Chaque événement d'acquisition traité par le pipeline de collecte peut produire un enregistrement `IntelligenceEvidence`, même lorsque l'observation analytique correspondante est dédupliquée. Le registre conserve un instantané borné, des empreintes SHA-256, une chaîne par collecte et une racine de Merkle. Les API de consultation et de vérification sont en lecture seule et limitées à l'organisation et au niveau TLP autorisés.

**Limites importantes :** les contrôles append-only sont applicatifs/ORM, pas une protection contre un administrateur DB privilégié. La racine est stockée dans la même base ; aucune ancre indépendante KMS/HSM ou horodatage externe n'est fournie par cette tranche. Ce mécanisme détecte certaines altérations du contenu conservé, mais ne prouve ni la véracité d'une source ni l'authenticité de son producteur. Les collectes antérieures ne sont pas rétroactivement enregistrées. Voir [Evidence Ledger](docs/INTELLIGENCE_CENTER.md#evidence-ledger-v1).

### Import défensif de rapports

Le parcours privilégié pour intégrer des résultats de scanners consiste à **importer des rapports déjà produits**, sans déclencher automatiquement un scan réseau depuis le processus d'importation.

Formats pris en charge par le parseur :

- Nmap XML
- Nuclei JSON et JSONL
- Nessus XML
- Shodan JSON et CSV

Contrôles documentés dans le code : taille maximale de 10 Mio, plafond de 20 000 constats par rapport, empreinte SHA-256, rejet des déclarations DTD/entités dans Nessus XML, traitement asynchrone par Celery et association d'un constat uniquement à un actif existant de la même organisation. Les cibles non associées restent à examiner ; elles ne créent pas automatiquement de nouveaux actifs.

Le stockage, la rétention, les ACL et la restauration des rapports doivent encore être validés en staging.

### Évaluations actives désactivées par défaut

Le code historique de l'Offensive Lab et certains runners d'évaluation restent présents. Le paramètre serveur `ACTIVE_ASSESSMENTS_ENABLED=False` est la valeur par défaut ; la politique est contrôlée à l'API et à nouveau dans le worker Celery afin qu'une tâche déjà en file ne contourne pas la désactivation. La configuration standard du conteneur API ne fournit pas Nmap.

Ne réactivez pas les évaluations actives en production sans revue spécifique, runner isolé, autorisation explicite, scope borné, fenêtre, validation du kill-switch et procédure d'arrêt. Le mode laboratoire pour les cibles privées nécessite également `LAB_MODE=True` côté serveur et un engagement configuré en mode LAB.

### Analyse Malware & Code

Les fichiers sont déposés en quarantaine, empreintés et soumis à des contrôles de type, taille et archive. Le code d'analyse ne charge pas les fichiers comme modules et ne les exécute pas ou ne les compile pas. Le profil Compose `security` définit un service scanner `network_mode: none`.

**Limite d'isolation à connaître :** si le worker ne reçoit pas le résultat du scanner dédié dans le délai prévu, le code actuel peut exécuter `scan_file` comme solution de repli dans le worker Celery. Le worker standard n'est pas lui-même en `network_mode: none`. Il ne faut donc pas affirmer que tous les chemins d'analyse bénéficient de l'isolation réseau du service scanner. Une mise en production doit rendre le scanner dédié obligatoire ou supprimer ce fallback après validation opérationnelle. Voir [Malware & Code Lab](docs/MALWARE_CODE_LAB.md).

### Capacités non certifiées comme prêtes pour la production

- SOAR complet avec playbooks versionnés, approbations, compensations et journal d'actions ;
- partage inter-CERT de production avec authentification partenaire, gouvernance, révocation et accords de partage ;
- ancrage externe indépendant des racines de preuve ;
- isolation opérationnelle démontrée de tous les workers et connecteurs sortants ;
- politique complète de rétention, chiffrement, sauvegarde/restauration et ACL des preuves et fichiers ;
- tests exhaustifs de permissions sur toutes les API, tâches Celery, WebSockets et intégrations ;
- validation de charge, procédures d'incident, SLA et pilote institutionnel.

## Architecture

```text
snake_eyes/
├── apps/
│   ├── api/                         # Django REST Framework, domaine et workers Celery
│   │   └── africanwatch/apps/
│   │       ├── organizations/       # Comptes, organisations, actifs et audit
│   │       ├── threat_intel/        # IOC, flux, acteurs et campagnes
│   │       ├── osint/               # Sources et événements OSINT
│   │       ├── soc/                 # Alertes, incidents et règles
│   │       ├── vulns/               # Vulnérabilités et import de rapports
│   │       ├── ai_engine/           # Assistance analytique et tendances
│   │       ├── intelligence/        # Collectes, provenance, STIX et Evidence Ledger
│   │       ├── dashboard/           # Statistiques et agrégats cartographiques
│   │       ├── malware_lab/         # Quarantaine et analyse de fichiers
│   │       ├── security_lab/        # Contrôles de sécurité défensifs
│   │       └── offensive_lab/       # Assessment autorisé, désactivé par défaut
│   └── web/                         # Frontend Next.js
├── infra/                           # Images, scanner, monitoring et configuration
├── security-lab/                    # Racines locales de quarantaine/outils
├── docs/                            # Documentation fonctionnelle et audits
├── docker-compose.yml
├── .env.example
├── Makefile
└── README.md
```

### Stack technique

- **API :** Python 3.12, Django 5.2, Django REST Framework
- **Frontend :** Next.js 14.2.3, React 18 et TypeScript
- **Données et tâches :** PostgreSQL 16, Redis 7, Celery et Celery Beat
- **Qualité :** pytest/pytest-django, Ruff, ESLint, TypeScript, build Next.js et Trivy via GitHub Actions
- **Composants optionnels :** Elasticsearch/Kibana, Kafka, Prometheus/Grafana, Ollama, Tor et service scanner malware, selon les profils Compose

## Démarrage local

Le Compose principal est un environnement de **développement** : l'API utilise `africanwatch.settings.dev` et `runserver`. Ce n'est pas une configuration de production.

### 1. Cloner le dépôt

```bash
git clone https://github.com/diarraibrahimamohamed-ops/snake_eyes.git
cd snake_eyes
cp .env.example .env
```

Le dépôt réel est `diarraibrahimamohamed-ops/snake_eyes`. Le fichier `.env.example` contient des valeurs de développement. Avant le premier démarrage, remplacez au minimum le `SECRET_KEY`, les mots de passe PostgreSQL et Redis, les origines CORS et les hôtes autorisés. Gardez `DEBUG=True` uniquement en local. Ne commitez jamais `.env`.

### 2. Démarrer et initialiser

```bash
make up
make migrate
make createsuperuser
```

`make up` copie automatiquement `.env.example` vers `.env` s'il n'existe pas, puis démarre Compose. Modifiez les secrets du fichier avant d'exposer ou d'utiliser l'environnement avec des données réelles.

| Service | Adresse locale |
|---|---|
| Interface Web | http://localhost:3000 |
| API REST | http://localhost:8000 |
| Swagger | http://localhost:8000/api/docs/ |
| Schéma OpenAPI | http://localhost:8000/api/schema/ |
| ReDoc | http://localhost:8000/api/redoc/ |
| Santé de l'application | http://localhost:8000/health/ |

Les ports des services principaux sont liés à `127.0.0.1` dans le Compose standard. N'exposez pas PostgreSQL, Redis, l'API ou le frontend sur un réseau public sans architecture et configuration de production adaptées.

### Profils Compose optionnels

```bash
make lab       # Elasticsearch, Kafka et monitoring
make ai        # Ollama local
make intel     # Service Tor optionnel pour collectes Onion passives
make security  # Scanner malware et mise à jour des signatures ClamAV
make down      # Arrêter les services
```

Ces profils ajoutent des services et de la consommation mémoire. Leur activation ne garantit pas que les connecteurs associés soient configurés.

### Commandes utiles

```bash
make logs
make shell
make test
make lint
make typecheck
make backup
```

`make lint` lance Ruff sur l'ensemble de l'API et le lint frontend ; il peut révéler une dette de style historique. La CI applique des contrôles Python ciblés et une suite de tests définie : son succès ne signifie pas que toute la base a été formatée ou que tous les scénarios de production ont été testés.

## API principales

### Authentification

L'API utilise JWT. Après création d'un utilisateur administrateur local, obtenez un jeton avec vos propres identifiants :

```bash
TOKEN=$(curl -sS -X POST http://localhost:8000/api/v1/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"email":"VOTRE_EMAIL","password":"VOTRE_MOT_DE_PASSE"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access'])")
```

Exemples :

```bash
curl "http://localhost:8000/api/v1/iocs/?is_african_threat=true&severity=critical" \
  -H "Authorization: Bearer $TOKEN"

curl "http://localhost:8000/api/v1/dashboard/stats/" \
  -H "Authorization: Bearer $TOKEN"
```

### Importer un rapport de scanner existant

```bash
curl -X POST "http://localhost:8000/api/v1/report-ingestions/upload/" \
  -H "Authorization: Bearer $TOKEN" \
  -F "source_type=nuclei_jsonl" \
  -F "file=@nuclei-report.jsonl"
```

Valeurs `source_type` : `nmap_xml`, `nuclei_json`, `nuclei_jsonl`, `nessus_xml`, `shodan_json`, `shodan_csv`.

| Méthode | Route | Objet |
|---|---|---|
| POST | `/api/v1/report-ingestions/upload/` | Importer un rapport |
| GET | `/api/v1/report-ingestions/` | Lister les imports du périmètre autorisé |
| GET | `/api/v1/report-ingestions/{uuid}/` | Statut et métadonnées |
| GET | `/api/v1/report-findings/?report={uuid}` | Constats normalisés |

L'import exige un utilisateur habilité et rattaché à une organisation. Les imports sont traités de façon asynchrone. Ils ne déclenchent pas le scanner mentionné dans le rapport.

### Evidence Ledger

| Méthode | Route | Accès |
|---|---|---|
| GET | `/api/v1/intelligence-evidence/` | Liste des preuves visibles pour le tenant et le niveau TLP du compte |
| GET | `/api/v1/intelligence-evidence/?run={uuid}` | Filtrer par collecte |
| GET | `/api/v1/collection-runs/{uuid}/verify-evidence/` | Vérifier séquence, empreintes, chaîne et racine Merkle |

La consultation et la vérification nécessitent au minimum le rôle `analyst` (ou un rôle supérieur) et restent soumises au cloisonnement organisationnel. Les réponses ne constituent pas une certification de chaîne de conservation. Les détails sont dans [INTELLIGENCE_CENTER.md](docs/INTELLIGENCE_CENTER.md).

## Sécurité et modèle multi-tenant

Les rôles applicatifs incluent `viewer`, `analyst`, `threat_hunter`, `org_admin` et `super_admin`. Les autorisations varient selon l'action ; l'authentification seule ne donne pas le droit de lancer une collecte ou une opération sensible.

Contrôles implémentés dans les chemins couverts par les tests :

- filtrage organisationnel de ressources et fermeture par défaut pour les comptes sans organisation sur les vues tenant-scoped ;
- contrôles de rôle sur certaines écritures, importations et actions sensibles ;
- filtrage TLP sur les chemins Threat Intelligence couverts et sur les preuves du registre ;
- séparation de certaines clés de cache du dashboard par organisation et niveau TLP ;
- évaluations actives désactivées par défaut à l'API et dans le worker ;
- empreintes SHA-256 des rapports importés et du contenu du registre de preuves.

Ces protections ne sont pas une preuve exhaustive de l'absence de défaut de contrôle d'accès. Une campagne multi-organisations doit couvrir toutes les routes, permissions objet, tâches Celery, canaux WebSocket, exports et téléchargements.

Avant un déploiement réel, validez TLS, secrets, réseau sortant, droits des volumes, rétention, sauvegarde/restauration, isolation des workers, supervision, procédures d'incident et tests d'acceptation.

## Tests et qualité

Le workflow `.github/workflows/defensive-ci.yml` se déclenche sur les pull requests vers `main` et comprend quatre jobs :

1. tests Django/API avec PostgreSQL et Redis ;
2. syntaxe Python, noms non définis et contrôles Ruff ciblés ;
3. ESLint, TypeScript et build Next.js de production ;
4. scan du dépôt avec Trivy pour les vulnérabilités HIGH et CRITICAL non ignorées comme non corrigibles.

Le code du snapshot `2f07cf7` a passé les quatre jobs lors du run [#53](https://github.com/diarraibrahimamohamed-ops/snake_eyes/actions/runs/41372748323). Toute modification ultérieure déclenche une nouvelle exécution ; vérifiez toujours le run correspondant au commit que vous souhaitez intégrer.

## Documentation détaillée

- [Index et statut des documents](docs/README.md)
- [Audit de transformation défensive et risques résiduels](docs/DEFENSIVE_TRANSFORMATION_AUDIT.md)
- [Intelligence Center et Evidence Ledger](docs/INTELLIGENCE_CENTER.md)
- [Security Lab](docs/SECURITY_LAB.md)
- [Matrice des outils de sécurité](docs/SECURITY_TOOLING_MATRIX.md)
- [Malware & Code Lab](docs/MALWARE_CODE_LAB.md)
- [Offensive Lab — limites et politique d'exécution](docs/OFFENSIVE_LAB.md)
- [Threat-informed assessment](docs/THREAT_INFORMED_OFFENSIVE.md)
- [Notes de capacités V6](docs/V6_RELEASE_NOTES.md)

## Licence

Le dépôt est distribué sous **GNU General Public License, version 2 (GPL-2.0)**. Consultez [LICENSE](LICENSE) pour les conditions applicables.

---

**AfricaWatch — renforcer les capacités défensives et la traçabilité du renseignement, avec des limites explicites et des garanties vérifiables.**
