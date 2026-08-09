# Security governance, risk and operations

## 1. Asset inventory and owners

| Asset | Location | Classification | Access boundary |
|---|---|---|---|
| Password hashes, MFA recovery hashes | PostgreSQL/SQLite | Restricted | App runtime only; Argon2id, RBAC |
| Chat and agent document plaintext | Encrypted DB rows | Confidential | Owner-only API query, AES-256-GCM with AAD |
| API/crypto/audit secrets | Environment in local lab; KMS/Vault target in production | Secret | Runtime process; never Git/logs |
| Source, CI definitions, manifests | Git repository | Internal | Protected branch/review + secret scan |
| Audit events/SIEM stream | DB + stdout JSON | Restricted evidence | Moderator/admin API; remote immutable sink required in production |
| Agent workspace and tool output | Per-user workspace | Confidential | Capability broker, quotas and owner boundary |

## 2. Risk register and STRIDE model

Risk is scored as **Threat likelihood (1–5) × exposure/vulnerability (1–5) × impact (1–5)**. Reassess every release and after an incident.

| Scenario / STRIDE | Risk | Existing control | Residual / action |
|---|---:|---|---|
| Credential stuffing (Spoofing) | 4×3×4=48 | Argon2id, generic errors, IP/account limits, lockout, TOTP | Enforce MFA for privileged accounts in production operations |
| IDOR / cross-tenant retrieval (Tampering/Info disclosure) | 3×2×5=30 | Owner-filtered queries, agent document tests, 404 anti-enumeration | Keep ACL filter before future vector ranking |
| DB theft (Info disclosure) | 3×3×5=45 | AES-256-GCM, AAD, separate key version | Move keys to KMS/HSM; test restore drills |
| Prompt injection / excessive agency (Elevation) | 4×3×4=48 | Untrusted agent plan, scoped broker, no shell/network | Remote sandbox and plugin registry are release blockers |
| SSRF / private network scan (Info disclosure) | 3×2×4=24 | HTTPS allowlist and private-IP/DNS checks; no HTTP client in broker | Enforce again in egress proxy at connect/redirect |
| Audit alteration (Repudiation) | 3×3×5=45 | HMAC chain and SIEM JSON | Export to WORM/immutable remote sink |
| Resource exhaustion (DoS) | 3×3×4=36 | body/tool/session quotas, Docker limits, Redis production limiter | load-test and tune quotas |

## 3. Architecture acceptance criteria

- **Zero Trust:** authenticate every API call; authorize each object/tool action; no trust in forwarded client headers.
- **Defense in depth:** Caddy/TLS → container/network segmentation → FastAPI headers/rate-limit/IDS → RBAC/capabilities → AES-GCM/audit.
- **Least privilege:** `scap_app` lacks schema ownership; agent tools are explicit allowlist; sandbox is deny-by-default.
- **Cryptography:** AES-256-GCM at rest; Caddy production policy requires TLS 1.3 in transit.

## 4. Incident response plan (six steps)

1. **Prepare:** keep contacts, runbook, current asset/risk register and offsite backups.
2. **Detect:** triage SIEM/audit alerts; preserve request IDs and immutable evidence.
3. **Contain:** revoke user sessions, disable account/API key, block source, disable an agent/plugin/egress rule.
4. **Eradicate:** patch root cause, rotate affected keys, remove malicious artifacts and rebuild verified image.
5. **Recover:** restore clean data, verify audit chain, monitor heightened alerts and notify affected stakeholders.
6. **Lessons learned:** within five business days record timeline, impact, root cause, control gap and regression test.

## 5. Backup and disaster recovery (3-2-1)

Maintain three copies: production PostgreSQL backup, encrypted backup on separate storage, and encrypted offsite/object-storage copy. Test restore at least quarterly into an isolated environment; verify schema, a sample AES-GCM decrypt with KMS access, and audit-chain integrity. Backup encryption keys are never stored alongside the backup. Record RPO/RTO per deployment before go-live.

## 6. Compliance and assurance matrix

| Control area | Current evidence | Remaining operational requirement |
|---|---|---|
| OWASP Top 10 | RBAC/IDOR tests, parameterized ORM, CSP, DLP, error handling | Authenticated DAST report per release |
| NIST CSF | Identify: assets/risk above; Protect: IAM/crypto; Detect: audit/IDS; Respond/Recover: runbook/DR | Assign owners and exercise incident/restore drills |
| ISO 27001-style ISMS | Policies, security CI, disclosure endpoint, audit records | Formal scope, risk-owner approval, supplier review, evidence retention |
| DevSecOps | pytest, Ruff, Bandit, pip-audit, Gitleaks, Semgrep, Trivy/SBOM, ZAP script | Branch protection and required CI checks in Git hosting |

## 7. External dependencies that cannot be claimed as implemented

SSO/OIDC (e.g. Keycloak), centralized SIEM (ELK/Splunk/Wazuh), KMS/HSM, immutable/WORM storage and independent pentest/Red Team require deployed services and organizational authority. They are production exit criteria, not features this repository can honestly simulate. Conduct security-awareness/phishing training and an independent code review/pentest at least annually and after material agent/sandbox changes.
