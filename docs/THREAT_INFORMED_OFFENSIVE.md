# Threat-Informed Assessment

Cette couche structure une évaluation défensive autour de la surface d'exposition et de la visibilité SOC. Elle vise à améliorer la qualité des observations et des preuves, pas à automatiser une compromission.

## Statut d'exécution

Le dépôt contient des profils de reconnaissance et d'analyse de posture. Les évaluations actives sont désactivées par défaut par `ACTIVE_ASSESSMENTS_ENABLED=False`, à la fois à l'API et dans le worker Celery. Ce document décrit les capacités du code et leurs garde-fous, pas une autorisation d'exécuter une mission.

## Boucle d'analyse

```text
pré-engagement -> préflight -> observations autorisées -> posture
 -> corrélation -> comparaison temporelle -> visibilité SOC
 -> remédiation -> revalidation
```

### Vue exposition

Les analyses présentes dans le code peuvent examiner, selon le profil :

- résolution DNS et posture SPF/DMARC/CAA ;
- réponses HTTP, en-têtes et cookies ;
- certificat et protocole TLS ;
- ports TCP/services lorsque le runner et les binaires sont activés ;
- changements entre deux évaluations ;
- chaînes d'exposition hypothétiques ;
- motifs ressemblant à des secrets, sans conserver la valeur détectée.

### Vue défenseur

Les résultats peuvent inclure les sources de télémétrie qu'une équipe devrait examiner : DNS, reverse proxy, HTTP, TLS, firewall, WAF/IDS, EDR et SIEM. Il s'agit d'attentes analytiques, pas de la preuve que ces systèmes ont effectivement observé l'événement.

## Profils recensés dans le code

| Profil | Objectif |
|---|---|
| `dns_recon` | Résolution DNS |
| `dns_posture` | Observations SPF/DMARC/CAA |
| `web_recon` | Réponse HTTP et posture |
| `web_posture` | CORS, cookies, méthodes annoncées, HSTS et chemins fixes |
| `tls_audit` | Protocole et certificat TLS |
| `port_recon` | Reconnaissance TCP légère |
| `exposure_audit` | Corrélation de surface |
| `adversary_recon` | Vue composite de reconnaissance |
| `exposure_chain` | Relations d'exposition hypothétiques |
| `nuclei_safe` | Contrôles restreints via Nuclei si configuré |
| `combined_recon` | Profil composite |

La disponibilité effective dépend de la configuration, des dépendances et de la politique d'exécution. La CI ne valide pas le fonctionnement d'un scanner réseau sur une cible réelle.

## Limites d'interprétation

Une exposition détectée n'est pas nécessairement exploitable. Un motif de secret n'est pas une preuve qu'un secret est valide. Une chaîne d'exposition est une hypothèse à confirmer. Une attente de télémétrie n'est pas un événement SIEM observé. Les résultats doivent être corroborés avant d'être qualifiés de finding confirmé.

## Conditions d'un pilote isolé

Avant d'activer les évaluations dans un laboratoire :

- autorisation écrite et scope vérifiable ;
- actifs de test appartenant à l'organisation ;
- fenêtre de test, quotas et arrêt opérateur ;
- politique serveur activée uniquement dans l'environnement isolé ;
- `LAB_MODE=True` côté serveur si des cibles privées sont utilisées ;
- worker et réseau sortant isolés, observables et limités ;
- preuves et journaux conservés avec horodatage et rétention définis.
