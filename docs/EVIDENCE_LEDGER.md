# Evidence Ledger — première fondation technique

## Objectif

Le Evidence Ledger conserve une trace vérifiable des acquisitions du Intelligence Center. Il sépare trois objets :

- **Observation analytique** : enregistrement dédupliqué utilisé par les fonctions de recherche et de corrélation.
- **EvidenceRecord** : instantané append-only d'une acquisition donnée, rattaché au run, au fournisseur réellement utilisé et à l'observation correspondante.
- **EvidenceManifest** : engagement cryptographique versionné sur les preuves d'un run.

Une nouvelle collecte peut retrouver une observation déjà connue. Elle ne crée pas une deuxième observation analytique, mais elle crée tout de même une nouvelle preuve d'acquisition rattachée au nouveau run. Une répétition de collecte ne doit pas être comptée comme une confirmation indépendante.

## Empreintes et manifestes

Le contenu JSON d'une preuve est sérialisé canoniquement (clés triées, séparateurs stables, UTF-8, valeurs non finies interdites), puis haché en SHA-256.

Le manifeste référence les identifiants et empreintes des preuves. Sa racine Merkle utilise la version suivante :

- feuille : SHA256(0x00 || digest_bytes) ;
- nœud : SHA256(0x01 || left || right) ;
- si un niveau contient un nombre impair de nœuds, le dernier nœud est dupliqué ;
- un manifeste vide utilise SHA256(empty).

Les manifestes sont versionnés par run et ne sont pas écrasés. La vérification recalcule les empreintes de chaque payload, vérifie l'appartenance des entrées et recalcule la racine Merkle.

Une signature Ed25519 peut être fournie au service de construction du manifeste. Aucune clé privée n'est embarquée dans le dépôt et aucune signature n'est produite par défaut. Lorsqu'un manifeste indique une signature, la vérification complète échoue si la clé publique correspondante n'est pas fournie.

## Provenance et corrélation

Les observations produites directement par les collecteurs internes (RDAP, DNS, Certificate Transparency, GDELT et enrichissements passifs) ne sont plus attribuées artificiellement à la première source configurée du run. Elles portent le libellé du fournisseur/collecteur et une référence URL lorsqu'elle existe. Les sources RSS, API publiques et modèles de pages conservent la référence de la source configurée qui a réellement fourni les données.

Le compteur corroboration_count ne progresse plus sur une simple relecture. Il représente, pour les relations explicites de type shared_ioc, le nombre d'origines d'acquisition distinctes présentes sur les observations reliées, après exclusion des origines déjà attachées à l'observation courante. Les origines sont dérivées des EvidenceRecord lorsqu'ils existent, ce qui permet de représenter plusieurs fournisseurs derrière une observation analytique dédupliquée. Une origine configurée distincte ne prouve toutefois pas l'indépendance éditoriale ou opérationnelle de deux fournisseurs. Le partage d'un IOC indique un lien observable ; il ne prouve pas à lui seul une campagne commune, une causalité ou l'identité d'un acteur.

Les relations automatiques ne sont créées que lorsqu'un IOC est effectivement partagé. La langue identique de deux textes n'est pas considérée comme une preuve de relation.

## API

Les endpoints suivants sont en lecture seule et limités à l'organisation de la session :

- GET /api/v1/evidence-records/ : preuves enregistrées ;
- GET /api/v1/evidence-manifests/ : manifestes et racines Merkle.

L'accès requiert une authentification et le rôle minimal analyste. La création des preuves et manifestes se fait par le pipeline interne de collecte.

## Limites connues — ne pas surinterpréter

Cette tranche fournit une intégrité vérifiable au niveau applicatif, pas encore une chaîne de conservation certifiée juridiquement ou forensiquement.

Les gardes Django et l'interface d'administration empêchent les modifications ordinaires, mais un administrateur direct de la base de données peut contourner les méthodes du modèle. Une prochaine étape doit ajouter un stockage indépendant des manifestes signés (ou un ancrage externe horodaté), des contrôles de sauvegarde/restauration et une procédure documentée de vérification hors ligne.

La signature n'est pas active sans configuration et gestion externe de clés. La vérification d'un manifeste non signé confirme les payloads et la racine Merkle, pas l'identité de son producteur.

Enfin, l'empreinte d'une preuve ne garantit pas que la source initiale était véridique. Elle permet de détecter une modification du snapshot conservé, pas d'établir la véracité de l'information collectée.
