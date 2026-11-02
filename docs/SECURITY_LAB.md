# AfricaWatch — Security Lab

## Mission et limites

Le Security Lab regroupe des contrôles défensifs applicatifs, API, base de données, code, dépendances, secrets et configuration. La présence d'un profil dans le catalogue ne garantit pas que son exécutable soit installé ni qu'un contrôle ait été réalisé.

Les profils sont soumis à une authentification, au cloisonnement organisationnel et aux rôles applicatifs. Les actions de création/exécution sont réservées aux rôles opérationnels autorisés ; les droits effectifs doivent être testés dans l'environnement déployé.

## Référentiels

- OWASP Top 10:2025.
- OWASP API Security Top 10:2023.
- OWASP ASVS 5.0.0 comme référentiel de vérification.
- OWASP WSTG comme méthodologie de test.

Le module ne détecte pas automatiquement l'ensemble de ces référentiels. Les défauts de conception, les contrôles d'accès et la logique métier exigent une revue humaine et des tests adaptés.

## Profils de contrôle présents

### Web et API

- `owasp_web` : observe notamment HTTPS, HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORS et cookies.
- `owasp_api` : examine un document OpenAPI, notamment les schémas de sécurité et les déclarations de serveurs.
- `zap_baseline_plan` : prépare un plan ZAP baseline ; ce profil ne doit pas être décrit comme un scan DAST actif lancé par l'API.

### Bases de données

`db_posture` utilise un profil DSN défini côté serveur (`SECURITY_DB_DSN_<PROFILE>`) et réalise des contrôles PostgreSQL en lecture seule, par exemple SSL, superusers et privilèges de création de rôles/schémas. Le DSN ne doit jamais être fourni librement par un utilisateur via une requête.

### Code, conteneurs et secrets

- `local_code` : lance Semgrep si le binaire est disponible dans l'environnement d'exécution.
- `local_container` : lance Trivy filesystem si disponible.
- `local_secrets` : lance Gitleaks avec sortie expurgée si disponible.
- `toolchain` : vérifie la disponibilité de certains outils locaux.

Les chemins sont résolus sous les racines de laboratoire définies côté serveur et séparés par organisation. Les outils ne sont pas garantis installés dans toutes les images ou tous les environnements.

### Audit de formats de hash

`local_credential` est un **audit de politique de format uniquement**. Le backend lit un fichier local de hashes, classe les formats reconnus et produit des avertissements sur les formats historiques. Il ne lance pas John the Ripper ou Hashcat, ne tente pas de casser les mots de passe, ne vérifie pas des identifiants et ne retourne pas les valeurs de hash dans le résultat.

Les fichiers sont limités à 5 Mio et à 100 000 entrées. Les chemins doivent rester sous `CREDENTIAL_LAB_ROOT/<organization_id>`.

### Profils de préparation non exécutants

- `hydra_readiness` : prépare les préconditions d'un audit de politique d'authentification ; aucune tentative de connexion réseau n'est effectuée.
- `sqlmap_readiness` : prépare le cadrage d'une vérification d'injection ; aucune exploitation automatisée n'est effectuée.

Ces profils sont des plans, pas des résultats de pentest.

## Création d'une revue

Le routeur expose les revues sous `/api/v1/security-reviews/`. Une revue est créée avec un profil et, selon le cas, un actif ou une référence d'entrée locale. L'action `run` déclenche une tâche Celery pour les profils implémentés.

Exemple de séquence API (adapter le JSON au serializer et au profil choisi) :

```text
POST /api/v1/security-reviews/
POST /api/v1/security-reviews/<uuid>/run/
GET  /api/v1/security-reviews/<uuid>/
GET  /api/v1/security-reviews/<uuid>/findings/
```

Pour les profils locaux, les fichiers doivent déjà être présents sous les racines montées côté serveur ; un chemin client arbitraire n'est pas une source valide.

## Références

- OWASP Top 10:2025 — https://top10.owasp.org/2025/
- OWASP ASVS — https://owasp.org/www-project-application-security-verification-standard/
- OWASP API Security Top 10:2023 — https://owasp.org/API-Security/
- OWASP WSTG — https://owasp.org/www-project-web-security-testing-guide/
- ZAP Baseline — https://www.zaproxy.org/docs/docker/baseline-scan/
