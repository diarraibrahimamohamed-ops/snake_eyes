# Security Tooling Matrix

Cette matrice décrit les intégrations et les limites visibles dans le code. « Disponible » signifie que le backend possède un adaptateur ; l'exécutable peut rester absent de l'image ou de l'environnement local. Les profils non exécutants ne doivent pas être interprétés comme un scan.

| Outil / contrôle | Domaine | Intégration | Mode dans l'application | Limite vérifiée |
|---|---|---|---|---|
| Semgrep | SAST | Security Lab / analyse de code | Local, si binaire disponible | Racine de code organisationnelle ; pas de preuve de couverture exhaustive |
| Trivy | SCA / filesystem | Security Lab et CI | Local ou CI | Scan du dépôt CI distinct d'un audit complet de runtime |
| Gitleaks | Secrets | Security Lab | Local, si binaire disponible | Sortie expurgée ; chemins sous racine autorisée |
| PostgreSQL posture | Base de données | Security Lab | Lecture seule | DSN défini côté serveur, pas fourni par l'appelant |
| OWASP Web checks | Web | Security Lab | Vérifications HTTP/configuration | Ne remplace pas une revue de logique métier |
| OpenAPI checks | API | Security Lab | Analyse de schéma | Dépend de la qualité et de l'exhaustivité du document OpenAPI |
| OWASP ZAP | DAST | Security Lab | Plan baseline | Le profil API est un plan, pas un scan actif exécuté |
| Hydra | Audit d'authentification | Security Lab | Plan de préparation seulement | Aucune tentative réseau d'identifiants |
| sqlmap | Injection | Security Lab | Plan de préparation seulement | Aucune exploitation automatisée |
| Nmap | Reconnaissance réseau | Offensive Lab historique | Runner protégé par politique serveur | `ACTIVE_ASSESSMENTS_ENABLED=False` par défaut ; binaire absent de l'image API standard |
| Nuclei | Vérification d'exposition | Offensive Lab historique | Profil restreint dans le code | Évaluations actives désactivées par défaut ; ne pas supposer le binaire présent |
| ClamAV | Analyse de fichiers | Malware & Code Lab | Scanner optionnel | Le chemin d'exécution effectif dépend du service scanner et de sa configuration |
| YARA | Analyse de fichiers | Malware & Code Lab | Scanner optionnel | Dépend des règles montées et du binaire |
| Analyse statique intégrée | Code | Malware & Code Lab | Local au scanner | Heuristique, faux positifs/négatifs possibles |

## Outils explicitement non exécutés

Le backend d'audit d'identifiants ne lance ni John the Ripper ni Hashcat. Il identifie uniquement des formats de hash et retourne des comptages/avertissements de politique. Les profils Hydra et sqlmap produisent des plans sans exécution réseau.

## Exploitation et ressources

Le catalogue est conçu pour un environnement de développement limité en RAM : les composants lourds sont optionnels et ne doivent pas être démarrés en permanence. Les profils Docker `lab`, `ai`, `intel` et `security` ajoutent des services ; ils augmentent les besoins mémoire, CPU et stockage.
