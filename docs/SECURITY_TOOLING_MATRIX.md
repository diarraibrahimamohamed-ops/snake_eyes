# Security Tooling Matrix

| Outil | Domaine | Intégration | Exécution | Limite |
|---|---|---|---|---|
| Nmap | Réseau | Offensive Lab | Active contrôlée | TCP connect/service detection |
| Nuclei | Web/exposition | Offensive Lab | Restricted | info/low/medium; familles intrusives exclues |
| OWASP ZAP | DAST | Security Lab | Baseline plan | pas d'active scan depuis l'API |
| Semgrep | SAST | Security Lab | Local | arbre de code du tenant |
| Trivy | SCA/misconfig | Security Lab | Local | fichiers/artefacts du tenant |
| Gitleaks | Secrets | Security Lab | Local | sortie redacted |
| PostgreSQL audit | DB | Security Lab | Read-only | DSN tenant-scoped |
| John the Ripper | Credential audit | Security Lab | Offline, opt-in | fichier de hash local du tenant |
| Hashcat | Credential audit | Catalogue | Station dédiée | non lancé par l'API |
| Hydra | Auth testing | Readiness | Plan only | aucun essai réseau d'identifiants |
| sqlmap | Injection | Readiness | Plan only | aucune exploitation automatisée |

Le catalogue est conçu pour une machine de développement limitée en RAM : les outils lourds ne sont ni démarrés ni chargés en permanence.
