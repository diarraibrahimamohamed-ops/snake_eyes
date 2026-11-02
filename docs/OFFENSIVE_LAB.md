# Offensive Lab — assessment autorisé, désactivé par défaut

## Mission et statut

L'Offensive Lab contient des modèles d'engagement, des cibles, des jobs, des findings et des runners de reconnaissance. Il est conçu pour des assessments explicitement autorisés, bornés à des actifs enregistrés et soumis à une approbation.

**La politique serveur désactive les évaluations actives par défaut** avec `ACTIVE_ASSESSMENTS_ENABLED=False`. L'API vérifie cette politique et le worker Celery la vérifie à nouveau avant l'exécution. Le code présent ne signifie donc pas que les scans actifs sont disponibles dans une installation standard.

Ne réactivez pas cette fonction sur une installation exposée ou de production sans revue de sécurité, environnement isolé, autorisation écrite et procédure d'arrêt.

## Contrôles de reconnaissance présents dans le code

Selon le profil et les binaires/configurations présents, les runners contiennent des contrôles limités de :

- DNS et posture DNS ;
- réponses HTTP et en-têtes de sécurité ;
- TLS et certificats ;
- ports TCP et identification légère de services ;
- corrélation d'exposition et comparaison de jobs ;
- contrôles Nuclei restreints dans le code.

Les outils externes ne sont pas garantis installés. Nmap a été retiré de l'image Docker standard de l'API. La CI n'atteste pas que les binaires d'assessment sont présents ou opérationnels.

## Préconditions et chaîne d'autorisation

Le modèle d'exécution prévoit :

1. actif existant et activé dans l'organisation ;
2. engagement avec référence d'autorisation et fenêtre temporelle ;
3. cibles attachées à la même organisation ;
4. approbation par un rôle habilité ;
5. calcul du hash du périmètre ;
6. vérification du scope et de la politique au préflight ;
7. contrôle de la politique serveur et du kill-switch ;
8. nouvelle vérification par le worker avant exécution ;
9. conservation du résultat, de son SHA-256 et d'événements d'audit.

La politique d'exécution active reste prioritaire : avec `ACTIVE_ASSESSMENTS_ENABLED=False`, un job est bloqué par le worker même s'il a été mis en file auparavant.

## Mode laboratoire privé

Les cibles privées ou locales ne sont pas autorisées par défaut. Leur validation nécessite à la fois `LAB_MODE=True` dans la configuration serveur et un engagement explicitement marqué `lab_mode=True`. Cette configuration est réservée à un laboratoire isolé et contrôlé.

## Kill switch

`SECURITY_ASSESSMENT_KILL_SWITCH=True` bloque le lancement de nouveaux jobs. Les opérateurs doivent aussi prévoir la révocation/annulation des jobs en cours et vérifier l'état réel des workers.

## Interdictions et limites

Les runners documentés ne sont pas destinés à fournir de l'exploitation de vulnérabilités, du brute-force, du vol de secrets, de la persistance, du mouvement latéral, de l'évasion ou de l'exécution shell arbitraire. Les arguments d'outils externes sont construits côté serveur.

Le périmètre réseau sortant, la résolution DNS, les redirections, la protection SSRF, l'isolation du worker et les limites de ressources doivent être testés dans l'environnement de déploiement avant toute activation.
