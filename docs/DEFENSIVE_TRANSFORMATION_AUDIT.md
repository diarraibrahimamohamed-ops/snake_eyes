# Defensive transformation audit — snake_eyes / AfricaWatch

Date: 2026-10-28
Branch: `defensive-institutional-pivot`
Baseline: `main` at `5ccdc41c4ccdfa51da1b4c16c3e25bae6119b501`

## Executive decision

The repository is not an offensive toolkit overall: it already contains threat intelligence, OSINT, SOC, vulnerability management, malware/code analysis, organizational RBAC and an AI helper. The institution-grade pivot should preserve those useful defensive capabilities while removing the product's dependence on active scanning and credential-attack tooling.

This document distinguishes **present in the repository**, **documented/claimed**, and **not yet demonstrated as production-ready**. A file or UI screen alone is not proof that an end-to-end feature works.

## Repository map (241 tracked blobs on the baseline)

- **Root and operations**: `.env.example`, `docker-compose.yml`, `Makefile`, `BUILD_MANIFEST.sha256`, `LICENSE`, `README.md`, `SECURITY_AUDIT.md`, CI workflow.
- **Django API**: `apps/api/africanwatch/` — settings split into base/dev/prod/test, root URL routing, health endpoints and shared security helpers.
- **Identity and tenancy**: `apps/organizations/` — Organization, User, Asset, audit models, serializers, views, auth/API routes and seed/management commands.
- **Threat intelligence**: `apps/threat_intel/` — IOC/feed/campaign-related API, models, serializers and Celery tasks.
- **OSINT**: `apps/osint/` — source/event ingestion, tenant scope, API and tasks.
- **SOC**: `apps/soc/` — alert, incident, detection-rule models and APIs/tasks. MITRE fields exist on alerts, but a dedicated analyst hunting workbench and tested query language are not established by the inspected structure.
- **Vulnerability management**: `apps/vulns/` — vulnerability/scan models, APIs and tasks. Current active scanning dependency should be replaced by normalized third-party report ingestion for the institutional default.
- **AI engine**: `apps/ai_engine/` — views, URLs and tasks. Existing summarization/IOC extraction and heuristic forecast must not be described as validated predictive ML without benchmark evidence.
- **Intelligence Center**: `apps/intelligence/` — classifiers, collectors, source models, services, tasks, tests and STIX export. STIX export code exists; a complete partner-facing TAXII server/export governance flow is not demonstrated.
- **Malware & Code Lab**: `apps/malware_lab/` — upload/API, queue tasks, safe scanner, tests. The scanner contains size/archive checks and static analysis paths; production isolation still requires container-level validation and adversarial tests.
- **Security Lab**: `apps/security_lab/` — OWASP checks, database posture, local SAST/secrets/container scans, tool definitions and UI. `local_tools.py` still includes an opt-in John-the-Ripper execution path and Hydra/sqlmap readiness plans; this conflicts with the desired clean institutional posture.
- **Offensive Lab**: `apps/offensive_lab/` — engagement/target/job/finding/event models, runner, task queue, approval/preflight/kill-switch/scope hashing, API, tests and UI. Guardrails exist, but the server can still initiate active reconnaissance; this is the highest-priority product pivot.
- **Frontend**: `apps/web/src/app/` — dashboard, intelligence, OSINT, SOC alerts/incidents, IOC, vulnerability, malware, security and offensive lab screens; shared components, API client, middleware and types.
- **Infrastructure**: `infra/docker/`, Docker Compose, local security-lab directories and optional heavy profiles.

## Feature status and evidence confidence

| Capability | Evidence in repository | Assessment |
|---|---|---|
| Tenant-scoped organizations/users/assets | Models, serializers, views and permission helpers | Implemented in code; must be regression-tested across every API, task and WebSocket path |
| SOC alerts/incidents/detection rules | Models, routes, views, tasks and UI screens | Core CRUD/workflow exists; full SOAR orchestration and tested containment connectors are not evidenced |
| Threat intelligence / IOC collection | Models, collectors, services, tasks, tests, STIX export | Substantial code exists; production source reliability, sharing governance and TAXII serving remain to validate/build |
| OSINT collection | App, models, views, tasks and UI | Code exists; each connector needs source-specific tests, legal review, rate limits and provenance checks |
| Malware/code analysis | Scanner, tasks, models, views, tests, UI | Static analysis paths exist; never execute uploaded samples; verify scanner is truly network-isolated in deployment |
| Vulnerability management | Models, views, tasks, UI and active assessment integration | CRUD/scan concepts exist; normalized ingestion for Nmap XML, Nuclei JSON, Nessus and Shodan export is not evidenced as a complete workflow |
| Security Lab | OWASP, DB posture, SAST, Gitleaks, Trivy helpers, John path, Hydra/sqlmap plans | Mixed defensive and dual-use semantics; remove password-cracking execution from the product path and replace plans with policy/configuration checks |
| Offensive Lab | Active runner, approved engagements, scan tasks and frontend | Guardrails exist but active scan initiation remains implemented; default-disabled now, later replace with report ingestion |
| SOAR | SOC entities and asynchronous task infrastructure | No complete playbook model/approval/execution/audit lifecycle evidenced |
| Threat sharing across CERTs | STIX bundle export helper | Export helper exists; production TAXII server, partner auth, TLP enforcement, revocation and sharing agreements not evidenced |
| Deception/canary tokens | No dedicated app/model/route found in tracked paths | Not implemented; proposed future module |
| Threat hunting workbench | MITRE tactic/technique fields and alert search foundations | Data fields exist; dedicated temporal hunting/query UX and validated ATT&CK mapping are not demonstrated |
| Hash policy auditing | Credential-related local tooling, but JtR path exists | Defensive policy auditor as described is not implemented |
| Lockout/MFA policy validation | Authentication stack and readiness plan | Dedicated safe policy validator is not demonstrated |
| CI / reproducible quality gates | `.github/workflows/ci-cd.yml`, tests and Makefile | CI exists; historical review noted a missing migration, lint debt and failing workflow checks; rerun and fix on this branch |

## Institutional risks to resolve before deployment

1. **Active scan ambiguity**: an institutional product should not initiate external scans by default. Import scanner reports and correlate their findings instead.
2. **Credential attack tool presence**: remove John/Hashcat/Hydra/sqlmap execution or operational workflows from the production application. Keep SAST/SCA, secret detection and authentication-policy checks.
3. **Multi-tenant boundaries**: test object-level access, unassigned organization records, task ownership, WebSocket groups, report downloads and admin exceptions.
4. **Untrusted uploads**: cap bytes, archive expansion, member count, path traversal, MIME mismatch and processing time; isolate the worker with no network, non-root, read-only root filesystem, resource limits and no Linux capabilities.
5. **Outbound requests**: centralize SSRF-safe URL/IP validation, DNS rebinding protections, redirect revalidation, response caps and outbound allowlisting.
6. **Audit integrity**: a hash chain detects tampering only if the chain's head is anchored/protected independently. Document retention, access control, time synchronization and export verification.
7. **AI claims**: label summaries as assistance and forecast scores as heuristics until a documented benchmark validates precision, recall, calibration and drift.
8. **Institutional governance**: add data classification/TLP enforcement, retention/deletion policy, case evidence chain, approvals for response actions, incident runbooks, backup/restore drills and operational SLAs.
9. **Supply chain**: reconcile the README AGPL badge with the actual LICENSE contents; generate an SBOM and dependency vulnerability report before releases.
10. **Deployment posture**: Compose includes development defaults and a development Django settings target. Production must use production settings, strong secrets, TLS, restricted service networking and managed credentials.

## Work completed in the first implementation slice

- Added `ACTIVE_ASSESSMENTS_ENABLED=False` as the default server policy and documented it in `.env.example`.
- The active-assessment API preflight reports the policy state, and the API launch policy rejects jobs while the feature is disabled.
- The Celery worker independently blocks queued jobs when the feature flag is off, preventing previously queued work from bypassing the API gate.
- Added a regression test for the disabled default and updated the existing launch test to opt in explicitly for its isolated test scenario.
- Replaced the John-the-Ripper execution path with a bounded hash-format policy audit. It reports format counts and legacy-format warnings only; it does not crack passwords, verify credentials, or return hash values. Removed offensive tools from the Security Lab's availability inventory.
- Updated Security Lab UI language to reflect format-only auditing and updated the legacy assessment screen to disclose the disabled-by-default institutional policy.
- Updated README positioning and added this audit/roadmap.

**Validation status:** source changes are committed on this branch, but the full Django/pytest suite, frontend build, and Docker integration tests have not yet been executed in this environment. These changes must be treated as an implementation in progress, not a production certification. The next step is to run CI and fix all regressions before extending the report-ingestion workflow.

## Implementation plan

### Phase 0 — safety boundary and inventory (started on this branch)
- Add an explicit server-side feature flag that disables active offensive assessments by default.
- Enforce the flag at API preflight/launch and again in the Celery worker so a queued job cannot bypass the policy.
- Add regression tests for the disabled-by-default boundary.
- Keep the existing main branch unchanged; all changes go through this branch.

### Phase 1 — report ingestion hub
- Add bounded, authenticated uploads for Nmap XML, Nuclei JSON/JSONL, Nessus XML and Shodan JSON/CSV.
- Parse in an isolated worker; reject malformed/oversized input and never execute uploaded content.
- Normalize findings into one schema: source, external asset, timestamp, CVE/CWE, severity, evidence, scanner reference, confidence and remediation.
- Resolve imported targets only against the tenant's registered assets; unmatched targets remain untrusted/unlinked pending review.
- Deduplicate, preserve original report hash, and correlate findings with IOC/threat intelligence.

### Phase 2 — clean defensive Security Lab
- Remove JtR execution path and any Hashcat invocation from API workers.
- Implement hash-policy audit based on metadata/prefixes/known hash formats only; never crack or verify user passwords.
- Replace Hydra readiness with a local configuration validator for MFA, rate limits, lockout, throttling and alerting.
- Fold SQL injection checks into static SAST/SCA and OpenAPI review, not remote exploitation.
- Make UI labels reflect exactly what runs, what is plan-only and what is unavailable.

### Phase 3 — operational SOC
- Implement SOAR playbooks as versioned, reviewed workflows with dry-run, approval gates, idempotency, allowlisted connectors, rollback/compensation and immutable action records.
- Add hunting workbench with bounded time windows, searchable normalized events, ATT&CK mappings with source confidence, and saved queries.
- Add canary tokens only with tenant-controlled generation, scoped callbacks and alerting; do not use tokens to track people outside authorized assets.

### Phase 4 — trusted inter-CERT sharing
- Add partner identities, mutual authentication, explicit sharing agreements, TLP handling, redaction and revocation.
- Provide STIX/TAXII export/import with pagination, filtering, rate limits, signing/verification and audit.
- Never share TLP:RED data outside the explicitly authorized recipients.

### Phase 5 — institution-grade assurance
- Restore green CI; migrations, Ruff/lint, tests, dependency scanning, container scanning and SBOM.
- Add tenant-isolation tests for all API objects, Celery tasks and channels.
- Add threat-model, incident response runbooks, backup/restore proof, audit-chain verification and performance benchmarks.
- Conduct a controlled pilot with synthetic incidents and authorized telemetry before production claims.

## Acceptance criteria for this branch

- Active assessment is denied unless explicitly enabled by an operator in a non-production isolated environment.
- The Celery worker independently enforces the same policy.
- Tests cover both the denied default and explicitly enabled test configuration.
- No claim of full production readiness is made until integration tests and deployment isolation are executed.
