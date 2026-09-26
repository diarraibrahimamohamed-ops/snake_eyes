# AfricaWatch V6 — Intelligence & Analysis Release

## Intelligence institutionnelle
- Collecte passive domain/IP/URL/organisation et cibles publiques liées aux actifs: email, téléphone institutionnel, profil social, identifiant public, Onion.
- DNS, RDAP, Certificate Transparency, GDELT, RSS, APIs publiques, Web/Social publics et sources Onion allowlistées.
- Corrélation IOC, signaux multilingues FR/EN/AR/HA/FF/BM, score d'actionnabilité, confiance, provenance, TLP et empreinte SHA-256.
- Radar de signaux/campagnes défensif sur 7 jours et forecasting heuristique basé sur cadence, diversité IOC et exposition vulnérable.
- Export STIX des observations/IOC.
- Enrichissement passif optionnel via Shodan/VirusTotal lorsque les clés organisationnelles existent.

## Analyse des fichiers
- Quarantaine par organisation, hash SHA-256, limites taille/archives, détection de traversal/symlinks, MIME/magic, entropie, profils PE/ELF.
- ClamAV + YARA + Semgrep + analyse statique multi-langages.
- Aucun fichier soumis n'est exécuté, importé, compilé ou autorisé à faire du réseau dans le scanner.

## Security Lab
- OWASP Web 2025, OWASP API 2023, ASVS 5.0.0, contrôle DB PostgreSQL, SAST/SCA/secrets, ZAP baseline plan, audit John offline, Hydra/sqlmap readiness.
- Nmap/Nuclei restent bornés par engagement autorisé, scope et kill-switch.

## Vie privée et traçabilité
- Tor est réservé à la collecte passive sur des hôtes Onion explicitement allowlistés.
- AfricaWatch ne tente pas de rendre les scans actifs invisibles et ne contourne pas les journaux/IDS/contrôles d'une cible.
- Les recherches de contacts/téléphones sociaux sont limitées aux informations publiques liées à des actifs organisationnels enregistrés; pas d'accès à des comptes privés.

## IA 8 Go
- Le cœur analytique reste déterministe/règles-first. L'IA locale est optionnelle, modèle léger, contexte et sortie bornés.
- Heavy NLP et traduction externe sont désactivés par défaut.
