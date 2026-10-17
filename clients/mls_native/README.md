# Native MLS client

This helper implements group operations through [OpenMLS 0.9.1](https://github.com/openmls/openmls/tree/v0.9.1), an RFC 9420 library. SCAP does not implement its own group cipher, key schedule or ratchet. `Cargo.lock` freezes the Rust dependency graph; OpenMLS's `content-debug`, `crypto-debug` and development features are disabled.

Build from the repository root:

```powershell
docker build -t scap-mls-client:local clients/mls_native
uv sync --frozen --extra e2ee-client
uv run --frozen --extra e2ee-client python -m scripts.demo_mls --check
uv run --frozen --extra e2ee-client python -m clients.mls_chat --username alice
```

The automated rehearsal starts three clients and a separate disposable loopback server. It verifies Add/Commit/Welcome, group messages, account removal, opaque server export and failure to decrypt the new epoch with a removed member's complete previous private state. Existing `.env`, databases and cloud services are not used.

For an interactive group, each participant registers their device, compares the full `fingerprint` over a separate trusted channel, runs `pin <username>`, and exchanges `offer`/`accept-offer` public JSON with every other participant. The owner runs `new`, then `add <session-id> <device-id>`. The joining participant runs `receive <session-id> <owner-device-id>`; existing participants receive the membership commit before sending. `send`, `receive`, `remove` and `retry` manage the group afterwards. Run `refresh-offer` before joining another group because MLS KeyPackages are single-use. Additional devices require existing-device approval using the `device-offer`, `approve` and `register-approved` commands.

The current application policy is owner-managed groups with one device per account. Multiple devices for the same account, arbitrary nonowner commits and external MLS clients are not yet supported. An unexpected server membership epoch or device revocation stops sending and preserves recovery state; it never silently recreates group secrets. Do not restore an old client vault over a newer ratchet state.

The helper is a local client component. Its stdin/stdout pipes contain private state and must not be logged or redirected into ordinary files. `NativeMls` runs the locally built image with image pulls disabled, no network or mounts, a read-only filesystem, dropped capabilities, a memory limit and container logging disabled. The existing encrypted vault is the only durable storage; a persistence failure requires reopening it. The local OS, Docker daemon and client binaries remain part of the trusted client environment.

Run the actual native integration tests explicitly:

```powershell
$env:SCAP_TEST_MLS_NATIVE = '1'
uv run --frozen --extra e2ee-client pytest tests/test_mls_client.py tests/test_mls_cli.py -q
```

The OpenMLS maintainers published an [independent library audit notice](https://blog.phnx.im/openmls-independent-security-audit/). This does not constitute an independent audit of SCAP's bridge, client, delivery service or deployment. Interoperability with a different MLS implementation and a security review of the complete integration remain release requirements before a production security claim.
