# AfricaWatch — Security / Architecture Audit v2

## What was changed

- **Tenant isolation:** user/profile writes cannot change role, organisation or activation state; asset/user creation is constrained to the authenticated tenant; WebSocket rooms are organisation-scoped where appropriate.
- **SSRF controls:** outbound HTTP used by OSINT/feed paths now validates HTTP(S), blocks private/loopback/link-local/reserved addresses by default, disables proxy environment inheritance, limits redirects and response size.
- **Authorized Offensive Lab:** engagements have an authorization reference, explicit validity window, approval state, target list, and scope hash. Active recon can only target registered assets attached to an active approved engagement.
- **No arbitrary shell input:** assessment commands are selected from a fixed server-side profile set. User input never becomes a shell command line.
- **Recon profiles:** DNS, HTTP/TLS headers, TLS audit, Nmap connect-scan service/version discovery, exposure audit, optional safe Nuclei adapter, and a combined profile. No brute force, exploitation, persistence, payload delivery or destructive actions are implemented.
- **Assessment governance:** per-engagement target ceilings, hourly job ceilings, concurrency ceilings, allowed-profile policy, batch launch, scope snapshot invalidation, kill-switch and job cancellation.
- **Evidence integrity:** structured findings, per-job result SHA-256, execution nonce, and a chained event ledger with independent integrity verification in the report endpoint.
- **Worker isolation:** scan worker has CPU/memory/PID ceilings, `no-new-privileges`, all Linux capabilities dropped, read-only filesystem and a bounded temporary filesystem in Docker.
- **Lab boundary:** private/reserved assessment targets remain blocked unless `LAB_MODE=True` is deliberately enabled for an isolated environment.
- **AI safety:** AI is opt-in, has strict input/output limits, uses a small local Ollama model by default, treats incident data as untrusted evidence, and falls back to deterministic summaries when AI is unavailable/disabled.
- **Prediction wording:** the existing threat “prediction” endpoint now identifies its result as a heuristic indicator rather than validated machine learning.
- **8 GB mode:** heavy Elasticsearch/Kafka/Kibana/Prometheus/Grafana services are moved behind the `lab` profile; Ollama is behind the `ai` profile with one model / one parallel worker and a 2 GB container limit.
- **Network exposure:** development service ports are bound to loopback where practical.
- **Credential hygiene:** demo credentials are removed from the sample environment and README guidance.

## Commands

```bash
make up
make lab
make ai
```

For the lightweight local AI, after starting the `ai` profile:

```bash
docker compose --profile ai exec ollama ollama pull qwen2.5:1.5b-instruct-q3_K_S
```

Then set `AI_ENABLED=True` in `.env`.

## Offensive Lab workflow

1. Create an engagement and record the authorization reference.
2. Attach only the organisation's registered assets.
3. Approve the engagement with an organisation administrator account.
4. Launch one of the fixed reconnaissance profiles during the approved time window.
5. Review the resulting evidence and SHA-256 digest.
6. Close the engagement when the assessment ends.

## Remaining limitations

The full Django test suite and Docker integration tests could not be executed in the current build environment because Docker is not installed here and the Python environment does not contain Django/dependencies. Python source compilation was checked successfully. The ZIP should therefore be treated as an audited source build requiring normal dependency/container validation on the target machine before production deployment.

## Threat-informed offensive assessment — v4

La version renforcée ajoute une logique d'analyse adversariale contrôlée :
`preflight`, quotas de batch, respect de la concurrence au niveau worker,
reconnaissance DNS/Web/TLS/réseau enrichie, détection de mauvaises configurations,
comparaison temporelle, chaîne d'attaque hypothétique et contrôle d'intégrité du
résultat. Le scanner ne reçoit toujours aucune commande utilisateur arbitraire.

Les contenus web potentiellement sensibles sont réduits à des motifs catégorisés ;
les secrets eux-mêmes ne sont pas persistés. Les contrôles CORS et cookies utilisent
une origine de test non enregistrée et n'exécutent aucune charge utile.

Le mode privé reste conditionné à `LAB_MODE=True` côté serveur et `lab_mode=True`
dans l'engagement. Le kill-switch bloque les nouveaux jobs.
