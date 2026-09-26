# Intelligence Center v6

## Mission
AfricaWatch v6 est pensé comme un système de renseignement défensif : collecter des faits publics, les analyser, les corroborer, leur associer une provenance et produire des signaux exploitables pour la défense.

## Sources
Les sources peuvent être : presse, RSS, CERT/CSIRT, Certificate Transparency, RDAP, APIs publiques, pages web publiques, profils/publications sociaux accessibles sans authentification et sources Onion explicitement allowlistées par l'organisation.

Une source web peut utiliser une URL modèle contenant `{target}`. Le moteur remplace cette variable avec la cible encodée, sans connexion à un compte et sans interaction d'écriture.

## Dark Web / Tor
Tor est utilisé uniquement comme **canal d'accès pour la collecte passive de sources Onion allowlistées**. Le moteur n'utilise pas Tor pour des scans Nmap/Nuclei ni pour tenter de masquer une activité active.

Tor protège la confidentialité du chemin réseau, mais il ne crée pas une garantie d'« invisibilité absolue » : l'architecture de collecte doit donc continuer à produire ses propres journaux d'audit et preuves d'intégrité. Voir la documentation officielle Tor sur les garanties et limites de l'anonymat. 

## Multilingue
Le triage léger couvre actuellement le français, l'anglais, l'arabe, le haoussa, le fulfulde et le bambara via détection automatique + lexiques locaux. Le résultat est un **signal de triage**, pas une attribution.

Les signaux de contenu incluent : cybermenace, fuite de données, fraude et signaux d'influence nuisible. Le moteur ne produit pas de consignes de persuasion ni de profilage politique d'individus.

## Fiabilité d'une observation
Chaque observation contient : source, URL, horodatage de collecte, SHA-256, niveau de fiabilité de la source, confiance, pertinence, actionnabilité, corroboration, classification, IOC et TLP.

Un grade A-F est calculé comme indication de qualité de preuve. Un grade n'est pas une preuve de vérité : l'analyste doit rechercher la corroboration indépendante avant diffusion institutionnelle.

## Prévision
`deterministic-threat-trend-v1` agrège les signaux récents, l'exposition et les vulnérabilités ouvertes. Il fournit des tendances et des horizons de surveillance, pas des probabilités scientifiquement calibrées d'une attaque future.


## V6+ — Renseignement multi-source

Le centre supporte désormais les cibles `email`, `phone_public` et `social_public` lorsqu’elles sont reliées à un actif organisationnel enregistré; le lookup rapide reste volontairement limité aux domaines/IP. Il ne fait pas de reverse lookup de particuliers ni d'accès à des comptes privés.

Les sources RSS et API publiques peuvent être attachées à une collecte; les sources `social_public` utilisent des modèles URL configurés par l'organisation. Les sources Onion restent strictement allowlistées et passives.

Les observations peuvent être exportées au format STIX depuis `GET /api/v1/collection-runs/<id>/export-stix/`. Le radar de campagne agrège les IOC partagés et signaux multilingues sur 7 jours; il s'agit d'une aide à la détection et non d'une attribution.

### Limite de furtivité

Le mode Tor réduit l'exposition du collecteur lors de l'accès à des services Onion autorisés, mais AfricaWatch ne prétend pas rendre une opération active invisible et n'emploie pas Tor pour contourner les journaux, IDS ou contrôles d'une cible. Les scans actifs restent identifiables et explicitement bornés.
