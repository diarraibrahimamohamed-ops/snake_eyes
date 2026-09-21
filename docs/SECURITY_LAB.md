# AfricaWatch — Security Assessment Lab

Le Security Lab combine analyse applicative, audit de base de données, supply-chain, secrets et préparation d'assessments offensifs.

## Référentiels

- OWASP Top 10:2025 : A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging & Alerting Failures, A10 Mishandling of Exceptional Conditions.
- OWASP API Security Top 10:2023.
- OWASP ASVS 5.0.0 comme standard de vérification détaillée.
- OWASP WSTG comme méthodologie de tests.

Le module ne prétend pas détecter automatiquement tout l'OWASP Top 10 : les risques de conception et de logique métier exigent notamment une revue humaine.

## Modules

### Web/API

`owasp_web` vérifie des contrôles HTTP observables : HTTPS, HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORS et cookies sensibles. `owasp_api` analyse un document OpenAPI et repère l'absence de schémas de sécurité, les serveurs HTTP et les problèmes d'inventaire déclaratif.

`zap_baseline_plan` prépare un DAST ZAP baseline ; l'intégration API ne lance pas de scan actif.

### Bases de données

`db_posture` utilise un profil DSN défini côté serveur (`SECURITY_DB_DSN_<PROFILE>`) et exécute uniquement des requêtes PostgreSQL en lecture seule : SSL, superusers, privilèges de création de rôles et CREATE accordé à PUBLIC sur les schémas non système.

`db_code_surface` / `local_code` permettent de faire passer la base de code par les règles SAST/SCA disponibles localement.

### Identifiants

`local_credential` est strictement hors-ligne. John the Ripper est désactivé par défaut et ne peut lire que des fichiers sous `CREDENTIAL_LAB_ROOT`. Aucun test d'authentification réseau n'est effectué par l'API.

Hashcat est déclaré dans le catalogue pour une station dédiée, mais n'est pas lancé par le backend.

### Outils offensifs

Hydra et sqlmap sont présents en mode `readiness-only` : le système produit le cadrage, les préconditions et la traçabilité attendue, sans envoyer de rafales d'identifiants ni automatiser l'exploitation réseau.

Nmap et Nuclei restent limités par l'Offensive Lab existant, l'engagement, le périmètre, le kill-switch et les profils autorisés.

## Lancement

Créer une revue via `POST /api/v1/security-reviews/` avec un `profile` et, selon le profil, un `asset` ou un `input_ref`, puis appeler `POST /api/v1/security-reviews/<id>/run/`.

Pour les entrées locales, les chemins sont relatifs aux racines du labo montées en lecture seule.

## Références officielles

- OWASP Top 10:2025: https://top10.owasp.org/2025/
- OWASP ASVS 5.0.0: https://owasp.org/projects/asvs
- OWASP API Security Top 10:2023: https://api-security.owasp.org/editions/2023/
- OWASP WSTG: https://wstg.owasp.org/
- ZAP Baseline: https://www.zaproxy.org/docs/docker/baseline-scan/
