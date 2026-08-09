# Secure AI Agent Platform — security architecture

SCAP now contains a **secure agent foundation**.  The important design choice is
that an LLM is an *untrusted planner*, never an execution principal.  A model may
propose a tool call, but it receives neither a shell, filesystem handle, network
client nor database session.

```text
Browser / API client
        │ JWT, MFA, rate limit
        ▼
FastAPI API gateway
        │ explicit user-approved scopes
        ▼
Agent orchestrator (untrusted plan)
        │ internal short-lived capability JWT
        ▼
Tool Broker ── policy checks ── audit/SIEM
   ├── per-user workspace
   ├── allowlisted source search
   ├── egress inspection (no HTTP client)
   └── external sandbox gateway (deny-by-default)
```

## What is implemented now

### Capability and tool boundary

`POST /api/agent/runs` accepts a proposed plan and an explicit list of scopes
approved by the authenticated user.  The server mints an internal capability JWT
with a dedicated HMAC-derived key, a 5-minute expiry, an audience, subject and
only those scopes.  It is never returned to a browser or LLM.

The broker only dispatches six version-pinned built-in manifests.  `GET
/api/agent/tools` returns their signed manifest; there is no dynamic plugin
loader, arbitrary import, shell, `subprocess`, `requests` or `httpx` escape
hatch in the agent process.

| Tool | Required scope | Boundary |
|---|---|---|
| `workspace.list`, `workspace.read` | `workspace:read` | User-specific root, blocks absolute paths, traversal, hidden paths and symlink escape. |
| `workspace.write` | `workspace:write` | Separate consent, UTF-8 only, 32 KiB cap, atomic write; no symlink writes. |
| `repo.search` | `repo:read` | Read-only allowlist: `src`, `tests`, `scripts`, `README.md`, `pyproject.toml`; excludes `.env` and Git metadata. |
| `egress.inspect` | `egress:inspect` | HTTPS only, domain allowlist, private/special-IP and DNS validation. It makes **no request**. |
| `sandbox.execute` | `sandbox:execute` | Always denied until a remote sandbox runner is configured. It never falls back to local execution. |

Each run is limited by `AGENT_MAX_TOOL_CALLS` (default 8).  Audit records include
only tool names, scope names and counts — never arguments, file contents, model
output or capability tokens.

### Tenant document retrieval foundation

`POST /api/agent/documents` ingests bounded **plain text** into an encrypted
`agent_documents` row owned by the authenticated user.  `POST
/api/agent/retrieval/search` performs bounded lexical retrieval only after
filtering `owner_id = current_user`.  It returns a short snippet and never
searches another user's documents.  Document ID and purpose are AES-GCM AAD, so
copying a ciphertext to another row cannot decrypt successfully.

This is intentionally not called a Vector DB or semantic RAG system.  It creates
the tenant/ACL and encrypted-ingestion boundary first; embeddings and a vector
store belong in the isolated retrieval phase below.

## Local security demonstration

Obtain the normal user JWT via `/api/auth/login`, then call `/api/agent/runs` in
Swagger (`/docs`) or a local client.

```json
{
  "approved_scopes": ["workspace:write"],
  "tool_calls": [
    {
      "tool": "workspace.write",
      "arguments": {"path": "notes.txt", "content": "Agent-created note"}
    }
  ]
}
```

Then use these negative cases as evidence of policy enforcement:

```json
{"approved_scopes":["workspace:read"],"tool_calls":[{"tool":"workspace.write","arguments":{"path":"x.txt","content":"blocked"}}]}
```

```json
{"approved_scopes":["workspace:read"],"tool_calls":[{"tool":"workspace.read","arguments":{"path":"../../.env"}}]}
```

```json
{"approved_scopes":["egress:inspect"],"tool_calls":[{"tool":"egress.inspect","arguments":{"url":"https://127.0.0.1/private"}}]}
```

All three return a completed run with a denied tool result, while the request is
recorded as `agent.run` in audit.  Do not use real secrets in demonstration tool
arguments.

## Production boundaries not yet present

The local implementation is deliberately conservative; it must not be labelled
a container sandbox, RAG system, or KMS when it is not one.  These are the next
deployment phases:

1. **Remote sandbox runner.** Replace `SandboxGateway` with a separate service
   backed by rootless containers first, then gVisor/Kata/Firecracker as required.
   Use a per-run ephemeral filesystem, no host mounts, no network by default,
   seccomp, dropped capabilities, read-only rootfs, CPU/RAM/PID/time quotas and
   a signed capability verified by the runner.
2. **Egress gateway.** Put all runner and tool HTTP traffic behind a proxy that
   repeats DNS/private-IP checks on connect and every redirect, applies the
   domain allowlist, normalizes URLs, logs metadata only and enforces request and
   byte quotas.  `egress.inspect` is intentionally only a safe preflight.
3. **MCP/plugin registry.** Store manifests in a registry with publisher
   signature verification, dependency/version pinning, per-plugin allowlists,
   timeout/quotas and revocation.  Never load a plugin merely because an LLM
   named it.
4. **Vector RAG isolation.** Move parsing/embedding to a separate worker and add
   a vector-store namespace per tenant/document ACL.  Retrieval must filter
   authorization *before* similarity ranking and label retrieved text as untrusted to reduce
   indirect prompt injection and cross-tenant retrieval.
5. **Untrusted file processing.** Put ZIP/PDF/image/repository parsing into the
   sandbox worker; reject traversal and symlinks, cap expansion ratio/size/count,
   disable network and treat metadata as untrusted.
6. **KMS/Vault and immutable audit.** Move the master encryption key and audit
   signing material out of the app process.  Stream signed audit events to a
   separate WORM/immutable destination so compromising SCAP does not also grant
   audit rewrite authority.
7. **Security release engineering.** Add property/state-machine tests for the
   broker, parser fuzzing, adversarial-agent corpora, authenticated DAST and
   concurrency tests.  Release a pinned image digest, SBOM, provenance, threat
   model and attack-surface map with every version.

## Configuration

| Variable | Safe default | Meaning |
|---|---|---|
| `AGENT_WORKSPACE_ROOT` | `./agent_workspaces` | Dedicated per-user workspace root. Mount a dedicated volume in production. |
| `AGENT_CAPABILITY_SECONDS` | `300` | Lifetime of an internal scope-specific capability JWT. |
| `AGENT_MAX_TOOL_CALLS` | `8` | Per-run broker quota. |
| `AGENT_EGRESS_ALLOWED_HOSTS` | empty | Comma-separated domains for the future egress gateway; empty denies all. |

Run the regression and security boundary tests with:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```
