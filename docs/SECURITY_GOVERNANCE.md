# Security governance, risk and operations

## 1. Asset inventory and owners

| Asset | Location | Classification | Access boundary |
|---|---|---|---|
| Password hashes, MFA recovery hashes | PostgreSQL/SQLite | Restricted | App runtime only; Argon2id, RBAC |
| Chat plaintext | Envelope-encrypted DB rows; absent in E2EE mode | Confidential/Restricted | Owner API; per-session DEK + message-bound AAD |
| API/crypto/audit secrets | Environment only for local legacy; Vault/KMS adapter in high profile | Secret | Workload identity/token file; never Git/logs |
| Source, CI definitions, manifests | Git repository | Internal | Protected branch/review + secret scan |
| Audit events/SIEM stream | DB + stdout JSON | Restricted evidence | Moderator/admin API; remote immutable sink required in production |

## 2. Risk register and STRIDE model

Risk is scored as **Threat likelihood (1–5) × exposure/vulnerability (1–5) × impact (1–5)**. Reassess every release and after an incident.

| Scenario / STRIDE | Risk | Existing control | Residual / action |
|---|---:|---|---|
| Credential stuffing (Spoofing) | 4×3×4=48 | Argon2id, generic errors, IP/account limits, lockout, TOTP | Enforce MFA for privileged accounts in production operations |
| IDOR / cross-tenant chat access (Tampering/Info disclosure) | 3×2×5=30 | Owner-filtered queries, 404 anti-enumeration tests | Keep ownership filter on every new resource |
| DB theft (Info disclosure) | 3×2×5=30 | Per-session DEK, message-bound AAD, Vault/KMS adapters | Deploy KMS IAM/HSM; test restore drills |
| Audit alteration (Repudiation) | 3×2×5=30 | HMAC chain, signed external checkpoints, SIEM JSON | Provision retention-locked WORM + SOC alerts |
| E2EE device compromise (Disclosure/Spoofing) | 3×3×5=45 | Possession/approval proofs, fingerprints, revoke + epoch | Audited client, secure hardware storage, recovery drill |
| Resource exhaustion (DoS) | 3×3×4=36 | body/message/session quotas, Docker limits, Redis production limiter | load-test and tune quotas |

## 3. Architecture acceptance criteria

- **Zero Trust:** authenticate every API call; authorize each object action; no trust in forwarded client headers.
- **Defense in depth:** Caddy/TLS → container/network segmentation → FastAPI headers/rate-limit/IDS → RBAC → AES-GCM/audit.
- **Least privilege:** `scap_app` lacks schema ownership; administrative actions require their own role checks.
- **Cryptography:** per-session AES-256-GCM DEK wrapped by Vault/KMS; ciphertext-only E2EE boundary; Caddy production policy requires TLS 1.3 in transit.

## 4. Incident response plan (six steps)

1. **Prepare:** keep contacts, runbook, current asset/risk register and offsite backups.
2. **Detect:** triage SIEM/audit alerts; preserve request IDs and immutable evidence.
3. **Contain:** revoke user sessions, disable account/API key and block source.
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

## 7. External assurance boundary

Repository đã có adapter/guard cho OIDC proxy, Vault/managed KMS, SIEM JSON và
HTTPS audit checkpoint/WORM. Tuy nhiên IdP, IAM/HSM, retention lock, SIEM rule,
data residency/DPA và credential thật phải do môi trường triển khai cung cấp.
Double Ratchet/MLS cũng phải chạy trong client dùng thư viện đã kiểm toán; server
chỉ relay ciphertext. Những bằng chứng này cùng pentest/Red Team độc lập là cổng
production, không thể được mô phỏng rồi tuyên bố đạt chỉ bằng unit test.
