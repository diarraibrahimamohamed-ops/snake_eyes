# Intelligence Center — collecte, analyse et Evidence Ledger

## Mission et périmètre

L'Intelligence Center d'AfricaWatch traite des informations publiques et des observations issues de sources configurées afin d'aider les équipes de défense à détecter, contextualiser et suivre des signaux de menace. Il n'est pas conçu pour accéder à des comptes privés, contourner des contrôles d'accès ou attribuer automatiquement une activité à une personne ou à un acteur.

Une observation analytique dédupliquée et un événement d'acquisition sont deux objets différents : plusieurs collectes peuvent rencontrer la même observation, mais chaque acquisition doit rester traçable.

## Sources et collectes

Les collecteurs et types de sources présents dans le code couvrent notamment :

- presse, RSS et bulletins CERT/CSIRT ;
- RDAP, DNS et Certificate Transparency ;
- GDELT et APIs publiques ;
- pages Web publiques et modèles d'URL configurés par l'organisation ;
- sources Onion explicitement autorisées ;
- enrichissements passifs optionnels selon les clés et paramètres déployés.

Une URL modèle peut contenir `{target}`. La valeur cible est encodée avant remplacement. Les sources sociales ou les identifiants publics ne doivent être utilisés que dans un périmètre organisationnel autorisé ; le code ne donne pas accès à des comptes privés.

### Tor

Tor est prévu comme canal de collecte passive pour des hôtes Onion explicitement allowlistés. Les variables pertinentes sont `TOR_ENABLED`, `TOR_SOCKS_PROXY`, `TOR_PASSIVE_ONLY` et `ONION_ALLOWED_HOSTS`. Tor n'est pas un mécanisme d'invisibilité absolue et ne doit pas servir à masquer une évaluation active.

## Triage multilingue et interprétation

Le classifier local utilise des règles et lexiques pour le français, l'anglais, l'arabe, le haoussa, le fulfulde et le bambara. Les catégories, IOC extraits, notes de confiance et grades de preuve sont des signaux de triage. Ils ne remplacent pas une validation par un analyste, une source indépendante ou une procédure d'investigation.

Le modèle `deterministic-threat-trend-v1` produit des tendances heuristiques à partir de signaux récents, de l'exposition et de vulnérabilités. Il ne fournit pas de probabilités calibrées scientifiquement sur la survenue d'une attaque.

## Provenance et corroboration

Le service `save_observation` conserve l'observation normalisée et enregistre la provenance de l'acquisition. Les collecteurs intégrés (RDAP, DNS, CT, GDELT et enrichissements passifs) ne doivent pas être attribués artificiellement à la première source institutionnelle associée à la collecte.

La répétition d'une collecte depuis la même source ne constitue pas une confirmation indépendante. Le compteur de corroboration repose sur les origines distinctes représentées dans les preuves d'acquisition ; la diversité des origines ne prouve toutefois pas leur indépendance éditoriale ou opérationnelle.

Les relations automatiques entre observations sont créées lorsqu'au moins un IOC est effectivement partagé. Une langue commune ou une proximité textuelle seule ne suffit pas à établir une relation. Un IOC partagé signale un lien observable ; il ne prouve ni campagne commune, ni causalité, ni attribution.

## Evidence Ledger v1

### Modèle d'enregistrement

Chaque acquisition traitée par `save_observation` ajoute un enregistrement `IntelligenceEvidence`, y compris lorsqu'une observation existe déjà. L'observation analytique reste dédupliquée, tandis que le nouvel événement d'acquisition reçoit son propre numéro de séquence.

Une preuve contient notamment :

- les références d'organisation, de collecte, d'observation et, si elle existe, de source configurée ;
- le libellé de la source, l'URL d'acquisition et l'URL enregistrée de la source ;
- l'heure de capture, le numéro de séquence et la version du schéma ;
- un instantané du titre, des métadonnées de classification, des IOC et du niveau TLP au moment de la capture ;
- le hash SHA-256 du contenu intégral reçu et, lorsqu'un objet brut est fourni, son empreinte ;
- un aperçu du texte limité à 10 000 caractères ;
- l'empreinte SHA-256 du payload canonique, le hash précédent et le hash de l'enregistrement.

Le corps brut externe n'est pas archivé par ce mécanisme. Le hash du contenu intégral permet de détecter une différence si une copie de référence est conservée séparément ; il ne permet pas de reconstruire le contenu absent.

### Chaîne de hash et racine de Merkle

Le JSON est sérialisé de façon déterministe (clés triées, séparateurs stables, UTF-8, valeurs non finies interdites), puis empreinté en SHA-256.

Les enregistrements sont chaînés par `CollectionRun` : chaque enregistrement référence le hash de l'enregistrement précédent. La racine de Merkle est calculée sur les hashes des enregistrements, avec séparation de domaines :

- feuille : `SHA256(0x00 || record_hash_bytes)` ;
- nœud interne : `SHA256(0x01 || left || right)` ;
- niveau impair : le dernier nœud est dupliqué ;
- registre vide : racine calculée vide (`""`) et statut de vérification `empty`.

La racine courante est enregistrée dans `CollectionRun.evidence_root_hash`. La vérification recalcule les hash de payload, références, séquences, chaîne et racine.

### API

Les routes sont montées sous le préfixe `/api/v1/` :

| Méthode | Route | Description |
|---|---|---|
| GET | `/api/v1/intelligence-evidence/` | Liste des preuves visibles |
| GET | `/api/v1/intelligence-evidence/?run=<uuid>` | Filtrage par collecte |
| GET | `/api/v1/collection-runs/<uuid>/verify-evidence/` | Vérification de la chaîne d'une collecte |
| GET | `/api/v1/collection-runs/<uuid>/export-stix/` | Export STIX de la collecte |

La consultation et la vérification du registre requièrent le rôle minimal `analyst`. Le queryset est limité à l'organisation de l'utilisateur et le filtrage TLP s'applique au niveau enregistré dans le payload de la preuve. Les rôles supérieurs héritent des autorisations prévues par le modèle RBAC. Un compte `viewer` ne peut ni consulter ni vérifier les preuves.

### Migration

La migration `0004_intelligence_evidence` :

- crée la table `IntelligenceEvidence` ;
- ajoute la relation Many-to-Many `CollectionRun.sources`, qui était déclarée dans le modèle mais absente de la migration initiale ;
- aligne la longueur de `IntelligenceObservation.source_url` sur le champ Django configuré à 2 000 caractères.

Il faut appliquer les migrations avec `make migrate` après mise à jour du code. Les migrations doivent être vérifiées sur une base vierge et une copie représentative d'une base existante avant un déploiement.

### Garanties et limites

Le terme « append-only » décrit les contrôles applicatifs : les méthodes du modèle et du QuerySet bloquent les modifications/suppressions ordinaires, l'admin ne permet pas l'ajout/la modification/la suppression et les clés étrangères utilisent `PROTECT`. Il ne s'agit pas d'une immutabilité au niveau du moteur de base de données. Un administrateur DB privilégié ou une écriture SQL directe peut contourner ces contrôles.

La racine de Merkle et les enregistrements sont conservés dans la même base. Pour une assurance supérieure, il faut ajouter une signature gérée hors base et un ancrage indépendant (KMS/HSM, service d'horodatage ou stockage immuable séparé), puis documenter les contrôles de clés, sauvegardes, restauration et vérification hors ligne.

Une empreinte valide signifie que les données conservées correspondent au hash vérifié ; elle ne prouve pas que la source initiale disait vrai, que le collecteur était digne de confiance ou que le contenu est complet. Les collectes historiques antérieures à la migration ne sont pas rétroactivement inscrites : leur vérification renvoie `empty`.

## Dashboard et agrégats cartographiques

L'endpoint de carte renvoie les IOC africains agrégés par `country_code`, avec les comptes total et par sévérité. Les coordonnées individuelles ne sont pas incluses dans la réponse cartographique. Le frontend utilise des repères/centroïdes nationaux : ils servent à afficher un agrégat par pays et ne doivent jamais être présentés comme la position d'un incident ou d'un IOC particulier.

Le dashboard charge aussi les statistiques, alertes, IOC et événements OSINT à partir de l'API. Les erreurs de ressources doivent être présentées comme indisponibilités, pas comme des résultats vides ; les dernières données valides peuvent être conservées en indiquant clairement leur fraîcheur.

## Vérifications opérationnelles avant déploiement

1. contrôler les autorisations TLP avec plusieurs organisations et chacun des rôles ;
2. tester la migration sur une base vierge et une base existante ;
3. vérifier la cohérence de la racine après plusieurs acquisitions et après restauration ;
4. tester les accès directs par UUID, les filtres et la pagination ;
5. définir la rétention et l'archivage des preuves ;
6. déployer une ancre externe avant toute revendication de chaîne de conservation renforcée.
