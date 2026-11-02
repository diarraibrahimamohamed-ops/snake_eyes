# Audit de transformation défensive — snake_eyes / AfricaWatch

**Date de cette révision : 2 novembre 2026**  
**Dépôt :** `diarraibrahimamohamed-ops/snake_eyes`  
**Référence `main` :** `93ccb717d26c36fc1eff2b761fbd54d399ed5e87` (intégration du dashboard live, PR #6).  
**Snapshot candidat examiné :** `2f07cf7eb80b45afad895a205af67a94ff7330e2` (branche `feat/evidence-ledger-v1`, PR #8, avant les révisions documentaires).  
**CI du snapshot candidat :** run #53, quatre jobs réussis : tests Django, syntaxe/lint API ciblé, ESLint/TypeScript/build Next.js et Trivy. [Détails du run](https://github.com/diarraibrahimamohamed-ops/snake_eyes/actions/runs/41372748323).

> Cet audit distingue le code présent, les tests automatisés et les garanties opérationnelles à démontrer. Une CI verte ne certifie pas une architecture déployée.

## Décision exécutive

AfricaWatch dispose d'une base défensive substantielle : organisations et actifs, SOC, Threat Intelligence, OSINT, import de rapports, analyse de fichiers et outils de sécurité. Le dashboard est désormais alimenté par l'API et l'Intelligence Center possède une première couche de traçabilité des acquisitions.

Le dépôt **n'est pas certifié prêt pour une production institutionnelle**. Les plus grands risques résiduels sont l'exhaustivité du cloisonnement multi-tenant, l'isolation effective des workers, la gouvernance des preuves, les chemins réseau sortants et les garanties opérationnelles (secrets, sauvegardes, rétention, supervision et réponse à incident).

## État vérifié par domaine

| Domaine | État dans le code examiné | Limite ou travail restant |
|---|---|---|
| Organisations, rôles et actifs | Modèles, API et helpers RBAC présents | Couverture d'autorisation à démontrer sur toutes les routes, tâches et canaux |
| SOC | Alertes, incidents, règles et tâches présents | Pas de SOAR complet avec approbations, compensation et connecteurs éprouvés |
| Threat Intelligence | IOC, flux, collecteurs, observations et export STIX | Qualité des sources, gouvernance et partage inter-CERT à valider |
| OSINT | Collecteurs et sources configurées présents | Tests et garde-fous spécifiques à chaque connecteur sortant |
| Dashboard | Données API, carte agrégée par pays, états indisponibles | Tests staging sur données réelles et habilitations TLP multi-organisations |
| Import de rapports | Formats Nmap XML, Nuclei JSON/JSONL, Nessus XML, Shodan JSON/CSV ; traitement Celery | ACL de stockage, rétention, volumétrie et restauration à tester en environnement cible |
| Evidence Ledger | Entrées append-only au niveau applicatif, SHA-256, chaîne par collecte et racine Merkle | Ancrage externe, clés, vérification hors ligne et chaîne de conservation formelle absents |
| Malware & Code Lab | Quarantaine, limites d'archives, ClamAV/YARA et analyse statique | Le fallback d'analyse dans le worker empêche de conclure à une isolation réseau uniforme |
| Security Lab | Contrôles Web/API, DB, SAST/SCA/secrets, audit de format de hash | Les outils optionnels doivent être disponibles et les profils testés sur des cibles de laboratoire |
| Offensive Lab | Runners de reconnaissance et contrôles de périmètre présents | Exécution active désactivée par défaut ; disponibilité des binaires et isolation de runner non garanties |
| Prévision / AI Engine | Règles, résumés et tendances heuristiques | Pas de benchmark de calibration, précision/rappel ou dérive démontré |
| Supply chain | CI et scan Trivy du dépôt | SBOM par version, signature d'artefacts et politique complète de mise à jour à compléter |

## Carte du dépôt

- `apps/api/africanwatch/apps/organizations` : identités, organisations, actifs et audit.
- `threat_intel`, `osint`, `intelligence` : IOC, sources, collectes, observations, relations, STIX et preuves.
- `soc` : alertes, incidents et règles de détection.
- `vulns` : vulnérabilités et ingestion de rapports tiers.
- `dashboard` : agrégats API pour le frontend.
- `malware_lab` : quarantaine et analyse de fichiers.
- `security_lab` : contrôles de sécurité et analyses locales.
- `offensive_lab` : workflow d'assessment autorisé protégé par politique serveur.
- `apps/web` : interface Next.js, composants, stores et clients API.
- `infra`, `docker-compose.yml`, `Makefile` : images, services et exploitation locale.

## Correctifs et garanties présents dans le snapshot

### Dashboard et données présentées

Le dashboard ne doit plus synthétiser de données de démonstration comme si elles étaient réelles. Les statistiques, alertes, IOC et événements sont hydratés depuis l'API. La carte renvoie des agrégats nationaux et n'expose pas les coordonnées individuelles des IOC par cette route. Les centroïdes nationaux sont des points de représentation, pas une localisation d'incident.

### Evidence Ledger

`save_observation` ajoute un enregistrement par acquisition, même si l'observation est déjà connue. L'empreinte du payload, le chaînage et la racine Merkle sont recalculés à partir des preuves du run. Les routes de lecture et de vérification sont limitées au tenant, filtrées par TLP et protégées par un rôle minimal analyste.

La migration `0004_intelligence_evidence` crée le modèle, ajoute la relation `CollectionRun.sources` manquante dans l'historique des migrations et met à jour la longueur de `IntelligenceObservation.source_url`. La protection append-only reste au niveau applicatif/ORM ; elle ne résiste pas à un administrateur DB privilégié. La racine étant stockée dans la même base, l'ancrage externe demeure un prérequis pour une garantie plus forte.

### Évaluations actives

`ACTIVE_ASSESSMENTS_ENABLED` vaut `False` par défaut. L'API vérifie la politique et le worker Celery la réévalue avant l'exécution, afin qu'un job déjà en file ne contourne pas la désactivation. `LAB_MODE` est également requis côté serveur pour les cibles privées. Le code du runner demeure présent et ne doit pas être interprété comme autorisation d'exécuter des évaluations sur Internet.

### Import et analyse des fichiers

L'import de rapports traite les fichiers comme des données, limite leur taille et le nombre de constats, rejette les déclarations DTD/entités dans Nessus XML et lie les constats aux actifs existants du tenant. Le scanner malware inspecte les fichiers sans les importer comme modules ni les exécuter. Cependant, si le scanner dédié ne remet pas son résultat dans le délai prévu, le task Celery peut appeler directement `scan_file`. Le worker standard n'est pas isolé par `network_mode: none` : il faut donc valider ou supprimer ce fallback avant de prétendre à une isolation complète.

### Security Lab et outils d'identifiants

L'audit local des identifiants classe uniquement les formats de hash reconnus et produit des avertissements de politique. Le backend ne lance plus John the Ripper ni Hashcat. Les profils Hydra et sqlmap sont des plans de préparation non exécutants ; ils ne lancent pas de tentatives réseau ni d'exploitation.

## Risques résiduels prioritaires

1. **Contrôle d'accès multi-tenant** — compléter les tests IDOR/permissions objet pour chaque viewset, action, export, téléchargement, tâche Celery, groupe WebSocket et cache.
2. **Workers et réseau sortant** — séparer les queues de confiance, contrôler DNS/redirects/SSRF, limiter les destinations, les privilèges, les ressources et l'accès aux secrets.
3. **Malware scanner** — rendre obligatoire le scanner isolé ou retirer le fallback dans le worker ; vérifier que les volumes et les droits correspondent au modèle attendu.
4. **Evidence Ledger** — ajouter une ancre indépendante des hashes, une gestion externe de clés, une vérification hors ligne et des exercices de restauration.
5. **Stockage et données** — formaliser chiffrement, ACL, rétention, suppression, sauvegarde, restauration et accès opérateur.
6. **Prévisions et IA** — documenter les limites, les données d'entraînement/heuristiques et un protocole d'évaluation avant toute affirmation prédictive.
7. **Production** — ne pas utiliser le Compose de développement tel quel ; imposer settings prod, TLS, secrets gérés, réseau restreint, non-root et supervision.
8. **Supply chain** — générer un SBOM versionné, analyser les images construites et définir la signature/provenance des artefacts.

## Plan d'acceptation recommandé

### Avant tout pilote

- appliquer les migrations sur une base vierge et sur une copie d'une base existante ;
- tester les cinq rôles avec au moins deux organisations, y compris les accès directs par UUID ;
- vérifier les limites TLP des preuves, IOC, agrégats, événements et exports ;
- exécuter une collecte synthétique avec plusieurs acquisitions, puis vérifier la chaîne et la racine ;
- vérifier que le scanner malware ne peut emprunter un chemin non isolé ;
- tester une restauration de sauvegarde et la cohérence des preuves ;
- vérifier secrets, TLS, CORS, ALLOWED_HOSTS, accès aux volumes et réseau sortant.

### Avant production institutionnelle

- réaliser une revue de menace et un audit indépendant ;
- produire SBOM et rapports de vulnérabilités des images ;
- définir rétention, classification, gouvernance de partage TLP et procédures d'incident ;
- réaliser un pilote sur données synthétiques et télémétrie autorisée ;
- établir des objectifs de disponibilité, performance, sauvegarde, support et réponse opérationnelle.

## Références de validation

- [README et démarrage](../README.md)
- [Intelligence Center et Evidence Ledger](INTELLIGENCE_CENTER.md)
- [Security Lab](SECURITY_LAB.md)
- [Malware & Code Lab](MALWARE_CODE_LAB.md)
- [Workflow CI](../.github/workflows/defensive-ci.yml)
- [Run CI #53 — snapshot de code testé](https://github.com/diarraibrahimamohamed-ops/snake_eyes/actions/runs/41372748323)
