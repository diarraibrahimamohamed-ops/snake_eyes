# Threat-Informed Offensive Lab

Cette couche vise à reproduire le raisonnement d'un pentester/red-team au niveau de la **surface d'attaque**, pas à automatiser une compromission.

## Boucle d'assessment

`pré-engagement -> préflight -> reconnaissance -> posture -> exposition -> corrélation -> drift -> visibilité SOC -> remédiation -> re-test`

### Vue attaquant

Le moteur cherche notamment :

- points d'entrée réseau observables ;
- services qui méritent une validation prioritaire ;
- mauvaises configurations Web, TLS et DNS ;
- indices d'exposition de secrets sans persister leur contenu ;
- changements de surface entre deux assessments ;
- chaînes d'exposition plausibles ;
- preuves nécessaires avant de qualifier un risque.

### Vue défenseur

Chaque profil retourne également une estimation de la télémétrie attendue : DNS, reverse proxy, HTTP, TLS, firewall, WAF/IDS, EDR/SIEM.

Le but est de pouvoir exécuter une mission du type :

1. vérifier ce que l'équipe offensive peut observer ;
2. vérifier ce que le SOC devrait voir ;
3. mesurer les écarts de détection ;
4. corriger ;
5. refaire exactement le même assessment ;
6. comparer le résultat au job précédent.

## Profils

| Profil | But |
|---|---|
| `dns_recon` | Surface DNS technique |
| `dns_posture` | SPF/DMARC/CAA observés |
| `web_recon` | Réponse HTTP et hardening |
| `web_posture` | CORS, cookies, méthodes annoncées, HSTS, fichiers canoniques |
| `tls_audit` | TLS/certificat |
| `port_recon` | Découverte TCP + service légère |
| `exposure_audit` | Corrélation surface |
| `adversary_recon` | Reconnaissance composite orientée menace |
| `exposure_chain` | Chaînes d'exposition hypothétiques |
| `nuclei_safe` | Contrôles Nuclei non intrusifs autorisés |
| `combined_recon` | Alias composite de reconnaissance |

## Limites

Le moteur n'automatise pas :

- exploitation de vulnérabilités ;
- brute-force ou credential stuffing ;
- payload delivery ;
- persistance ;
- mouvement latéral ;
- évasion/anti-détection ;
- exécution de commandes arbitraires.

Pour un laboratoire isolé, `LAB_MODE=True` est requis côté serveur et `lab_mode=True` côté engagement pour autoriser les cibles privées.
