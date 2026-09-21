# Offensive Lab — architecture d’assessment autorisé

## Mission

Le Lab permet de conduire des évaluations actives sur des actifs préenregistrés, avec autorisation humaine, fenêtre de temps et périmètre immuable entre approbation et exécution.

## Capacités

- DNS : A, AAAA, MX, NS, TXT, CNAME.
- Web : statut, en-têtes de sécurité, bannière, titre, indices technologiques.
- TLS : protocole négocié, chiffrement, certificat, expiration.
- Réseau : Nmap en connect scan, top 100 ports, identification de service légère.
- Exposure audit : corrélation des observations et règles de surface d’exposition.
- Nuclei Safe : adaptateur optionnel limité aux sévérités info/low/medium et à une liste de tags non intrusifs.
- Batch : exécution sur plusieurs cibles déjà approuvées.
- Report : findings normalisés + intégrité de la chaîne d’événements.

## Interdictions intégrées

Pas d’exécution shell arbitraire, de scripts NSE, d’évasion, de payload delivery, d’exploitation, de brute-force, de récupération de secrets, de persistance ou de mouvement latéral. Les arguments des scanners sont construits côté serveur à partir de profils fixes.

## Chaîne de confiance

1. Asset actif et scan_enabled.
2. Engagement avec référence d’autorisation.
3. Cibles enregistrées dans la même organisation.
4. Approbation d’un org_admin ou supérieur.
5. Hash SHA-256 du scope.
6. Job créé avec le hash du scope au lancement.
7. Revalidation du scope et de la fenêtre par le worker.
8. Résultat hashé et findings persistés.
9. Événements en chaîne SHA-256 vérifiable.

## LAB réseau privé

Une cible privée ou locale reste interdite par défaut. Pour un environnement d’apprentissage isolé, `LAB_MODE=True` doit être défini au niveau serveur et la mission doit aussi activer `lab_mode=True`.

## Kill switch

`SECURITY_ASSESSMENT_KILL_SWITCH=True` empêche toute nouvelle création de job d’assessment. Les jobs déjà terminés restent consultables.

## Mode « threat-informed red team »

Le Lab ajoute une couche d'analyse inspirée d'un attaquant réel sans automatiser
l'exploitation :

- `dns_posture` : SPF, DMARC et CAA observés.
- `web_posture` : CORS, méthodes annoncées, cookies d'authentification, HSTS et chemins fixes `robots.txt`, `sitemap.xml`, `.well-known/security.txt`.
- `adversary_recon` : fusion DNS + Web + TLS + ports + posture et estimation de la surface d'attaque.
- `exposure_chain` : construction de chemins d'exposition à partir des observations déjà collectées.
- comparaison avec le job précédent : nouveaux/anciens services et findings apparus/résolus.
- `preflight` avant batch : validation de l'autorisation, de la fenêtre, du hash de scope, du kill-switch, des cibles et du quota horaire.
- `integrity` : vérification du SHA-256 du résultat et de la chaîne d'événements.
- `adversary_plan` : séquençage de mission et questions d'analyste, sans procédure d'exploitation.

La surface de secret potentielle est détectée sous forme de motif uniquement :
les valeurs correspondantes ne sont jamais écrites dans les findings.

## Perspective « black-hat » simulée

Le raisonnement est volontairement centré sur les questions suivantes :

1. Quelle entrée observable est la plus exposée ?
2. Quelle faiblesse peut être confirmée sans exploitation ?
3. Quelle preuve permettrait de passer d'un signal à un finding confirmé ?
4. Quelle télémétrie devrait être visible côté SOC/IDS/WAF ?
5. Comment l'exposition a-t-elle changé depuis le précédent assessment ?

Cette couche sert donc à rapprocher le Lab d'une démarche de pentest/red-team,
mais ne fournit pas de mécanisme d'intrusion, de vol d'identifiants, de persistance,
d'évasion ou de mouvement latéral.
