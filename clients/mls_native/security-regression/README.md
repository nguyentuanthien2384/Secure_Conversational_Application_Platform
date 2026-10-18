# Optional HPKE provider security regressions

This standalone test crate compiles SCAP's manifest-only
[`hpke-rs-libcrux` backport](../vendor/hpke-rs-libcrux/BACKPORT.md), even though
the production OpenMLS helper continues to use RustCrypto. It does not add a
provider, cipher suite, or post-quantum mode to the running SCAP client.

The seven tests check both hybrid KEM algorithms named in
[RUSTSEC-2026-0330](https://rustsec.org/advisories/RUSTSEC-2026-0330.html) and
[RUSTSEC-2026-0331](https://rustsec.org/advisories/RUSTSEC-2026-0331.html): all
truncated key lengths, all short encapsulation seed lengths, valid KEM
roundtrips, and malformed keys through the patched HPKE provider. They also
exchange HPKE ciphertext in both directions between libcrux and RustCrypto
using X25519/AES-128-GCM and P-256/ChaCha20-Poly1305, including rejection of
modified ciphertext and associated data. Keys and seeds are synthetic test
inputs. A panic fails the ordinary Rust test; it is never suppressed.

The optional provider's fixed dependency pulls `libcrux-platform 0.0.4`, whose
x86 CPUID calls require Rust 1.95 or later. This test requirement is separate
from the unchanged production helper's Rust 1.91 build.

From the repository root with Rust 1.95 or later:

```sh
cargo test --locked --manifest-path clients/mls_native/security-regression/Cargo.toml
cargo install --locked cargo-audit --version 0.22.2
cargo audit --file clients/mls_native/Cargo.lock
cargo audit --file clients/mls_native/security-regression/Cargo.lock
```

The native MLS CI job runs these tests in the digest-pinned Rust 1.95 image,
audits both lockfiles with the official cargo-audit 0.22.2 Linux release after
verifying its pinned SHA-256, and saves the test log and both audit JSON files.
No advisory exclusions are used.
The test crate has its own checked-in lockfile and stays outside the production
image build context. These regressions provide compatibility and bug-fix
evidence; they do not replace an independent cryptographic audit.
