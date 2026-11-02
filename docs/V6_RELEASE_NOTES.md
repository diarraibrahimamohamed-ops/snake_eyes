# AfricaWatch V6 — notes de capacités

Ce document résume les capacités présentes dans la génération V6 du dépôt. Il ne constitue pas une déclaration de disponibilité de production. Les détails et limites actuels sont décrits dans le README et les documents spécialisés.

## Intelligence Center

- Collecte passive via sources configurées : DNS, RDAP, Certificate Transparency, GDELT, RSS, APIs publiques et sources Onion allowlistées.
- Cibles et observables publics liés à des actifs organisationnels enregistrés, selon les profils implémentés.
- Corrélation d'IOC, classification multilingue FR/EN/AR/HA/FF/BM, provenance, confiance, pertinence et TLP.
- Radar de signaux sur sept jours et tendances heuristiques ; pas de prédiction probabiliste calibrée.
- Export STIX de collecte.
- Evidence Ledger v1 : événement par acquisition, empreintes SHA-256, chaînage par collecte, racine de Merkle et endpoint de vérification.
- Les preuves sont limitées par tenant et clearance TLP ; l'accès exige le rôle minimal analyste.
- Les racines ne sont pas ancrées hors de la base ; l'immutabilité n'est pas garantie contre un administrateur DB privilégié.

## Dashboard

- Statistiques, alertes, IOC et événements OSINT chargés depuis l'API.
- Carte alimentée par les agrégats IOC par pays et sévérité.
- Les marqueurs nationaux sont des repères d'agrégation et ne représentent pas la position exacte d'un IOC.

## Ingestion de rapports de vulnérabilité

- Nmap XML, Nuclei JSON/JSONL, Nessus XML et Shodan JSON/CSV.
- Upload borné, SHA-256, parsing asynchrone, rejet des déclarations DTD/entités Nessus.
- Liaison exacte aux actifs existants du tenant ; pas de création automatique d'actifs à partir d'un rapport.
- Le pipeline importe des résultats existants et ne lance pas les scanners.

## Malware & Code Lab

- Quarantaine par organisation, empreinte SHA-256, limites de taille et d'archives.
- ClamAV, YARA et règles statiques selon les binaires/règles disponibles.
- Le Compose propose un scanner sans réseau, mais le worker possède encore un fallback direct ; voir les limites d'isolation dans `MALWARE_CODE_LAB.md`.

## Security Lab

- Contrôles Web/API, posture PostgreSQL, SAST/SCA et recherche de secrets.
- Audit de format de hash uniquement : aucune tentative de cassage ou de vérification de mot de passe.
- Hydra et sqlmap en préparation non exécutante ; ZAP baseline en plan.

## Offensive Lab

- Code de reconnaissance et d'assessment avec engagement, scope, approbation, fenêtre, kill-switch et vérification par le worker.
- Les évaluations actives sont désactivées par défaut ; les binaires ne sont pas garantis dans les images standard.
- Les fonctionnalités de code ne doivent pas être interprétées comme une autorisation ou une garantie de disponibilité.

## IA et ressources

- Approche règles-first/déterministe ; Ollama local optionnel.
- Heavy NLP et traduction externe désactivés par défaut dans l'exemple de configuration.
- Les ressources optionnelles (Elastic/Kafka, Tor, scanner malware, Ollama) augmentent les besoins CPU/RAM/disque.
