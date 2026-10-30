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


## Evidence Ledger v1

Chaque acquisition enregistrée par `save_observation` produit désormais une entrée `IntelligenceEvidence`, y compris lorsqu'elle correspond à une observation déjà connue. L'observation peut être dédupliquée; l'événement d'acquisition, lui, reste distinct.

Une entrée conserve notamment :

- l'organisation, la collecte, l'observation et la source enregistrée lorsqu'elle existe ;
- le nom et les URL de provenance déclarés, y compris l'URL de la source institutionnelle configurée ;
- l'horodatage de capture, le numéro de séquence et la version du schéma et la classification TLP au moment de la capture ;
- un instantané du titre, d'un aperçu du contenu, des IOC et de la classification ;
- le SHA-256 du contenu reçu et, lorsqu'un objet brut est fourni, son empreinte ;
- le SHA-256 du contenu canonique de l'entrée, le hash précédent et le hash de l'entrée.

Les entrées sont chaînées par collecte. `CollectionRun.evidence_root_hash` contient la racine de Merkle calculée sur les hashes des entrées, et non plus une empreinte calculée uniquement à partir des identifiants d'observations.

### Vérification et consultation

- `GET /api/v1/intelligence-evidence/?run=<uuid>` — consulter les entrées visibles dans le périmètre de l'utilisateur ;
- `GET /api/v1/collection-runs/<uuid>/verify-evidence/` — recalculer les empreintes, vérifier la séquence, la chaîne et la racine de Merkle.

La vérification renvoie `valid`, `invalid` ou `empty`, avec les anomalies et les racines calculées/enregistrées.

### Corroboration et provenance

Une répétition de collecte depuis la même source n'est pas comptée comme une confirmation indépendante. Le compteur de corroboration est alimenté à partir des sources enregistrées distinctes (ou des URL externes distinctes lorsqu'aucune source institutionnelle n'est liée).

Les enrichissements RDAP, DNS, Certificate Transparency et les fournisseurs passifs ne sont plus attribués arbitrairement à la première source RSS/API attachée à la collecte. Les sources configurées restent associées uniquement aux éléments qu'elles ont effectivement fournis.

La corrélation entre observations n'est créée que lorsqu'au moins un IOC est partagé. Une langue commune ne suffit pas à établir une relation.

### Limites de garantie

Cette version est une fondation de traçabilité et de détection d'altérations, pas un système de preuve inviolable certifié :

- le contenu de l'observation est conservé sous forme d'aperçu limité à 10 000 caractères ; le hash porte sur le contenu complet reçu ;
- le corps brut des réponses externes n'est pas archivé par ce mécanisme ; son empreinte est conservée lorsqu'il est fourni ;
- les contrôles append-only sont imposés au niveau applicatif/ORM et par des clés étrangères restrictives ; un administrateur de base de données privilégié peut contourner ces contrôles ;
- la racine de Merkle est stockée dans la même base. Une signature périodique et un ancrage indépendant (KMS/HSM ou service d'horodatage externe) restent nécessaires pour résister à un administrateur capable de modifier la base et ses empreintes ;
- les collectes historiques antérieures à cette version ne sont pas rétroactivement transformées en entrées de preuve. Leur vérification renvoie `empty`.

Ne présente pas un hash ou une racine de Merkle seule comme une preuve d'authenticité de la source ou de vérité de l'observation.
