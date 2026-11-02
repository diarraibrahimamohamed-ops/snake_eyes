# Documentation AfricaWatch

Cette page est l'index des documents suivis dans le dépôt. Les capacités sont décrites à partir du code et des tests consultés ; elles ne valent pas certification de production.

| Document | Sujet | À consulter pour |
|---|---|---|
| [README](../README.md) | Présentation générale, installation, API et sécurité | Premier démarrage et vue d'ensemble |
| [Audit de transformation défensive](DEFENSIVE_TRANSFORMATION_AUDIT.md) | État technique, risques résiduels et critères d'acceptation | Décider d'un pilote ou d'un durcissement |
| [Intelligence Center](INTELLIGENCE_CENTER.md) | Sources, provenance, corrélation, STIX et Evidence Ledger | Comprendre le pipeline de renseignement et les garanties cryptographiques |
| [Security Lab](SECURITY_LAB.md) | Contrôles Web/API, DB, code, secrets et profils non exécutants | Utiliser les revues de sécurité |
| [Matrice des outils](SECURITY_TOOLING_MATRIX.md) | Adaptateurs, disponibilité et limites | Savoir ce qui est réellement exécuté |
| [Malware & Code Lab](MALWARE_CODE_LAB.md) | Quarantaine, scanner, moteurs et isolation | Évaluer le traitement des fichiers non fiables |
| [Offensive Lab](OFFENSIVE_LAB.md) | Engagements, scope et politique d'évaluations actives | Comprendre pourquoi l'exécution est désactivée par défaut |
| [Threat-Informed Assessment](THREAT_INFORMED_OFFENSIVE.md) | Profils de reconnaissance et limites d'interprétation | Interpréter les résultats d'assessment |
| [V6 Release Notes](V6_RELEASE_NOTES.md) | Résumé des capacités V6 | Consulter les grandes tranches fonctionnelles |

## Règles de maintenance documentaire

1. Ne documenter comme disponible que ce qui existe dans le code et peut être relié à une route, une tâche, une configuration ou un test.
2. Distinguer le code présent, l'intégration configurée, le résultat testé et la disponibilité en production.
3. Pour chaque garantie de sécurité, préciser son niveau d'application (API, ORM, base, conteneur ou infrastructure).
4. Ne pas qualifier un hash, une racine Merkle ou un statut CI de certification ou de preuve d'authenticité.
5. Mettre à jour ce fichier et les documents spécialisés dans la même pull request que les changements fonctionnels.
6. Revalider les chemins, noms de paramètres, limites numériques, rôles et exemples de commandes sur le code actuel.
7. Toute modification ultérieure du code candidat doit déclencher une nouvelle CI ; le résultat d'un ancien commit ne s'applique pas automatiquement au nouveau.

Dernière revue documentaire : **2 novembre 2026**.
