# HPKE 0.7 KEM compatibility backport

The published OpenMLS RustCrypto provider 0.6.0 requires HPKE 0.7.0. Its
optional libcrux provider pins `libcrux-kem =0.0.9`, so an ordinary lockfile
update cannot select the patched 0.0.10. The current native SCAP release
uses the RustCrypto provider; this patch also removes the vulnerable optional
resolution from its source lockfile.

This directory contains the published `hpke-rs-libcrux 0.7.0` registry source,
verified against the registry archive checksum recorded in `provenance.json`.
The Rust source is unchanged. The normalized `Cargo.toml` changes only the
`libcrux-kem` version requirement to `=0.0.10`. `Cargo.toml.orig` preserves the
original manifest. The original nested Cargo.lock and registry receipt are
omitted; the native helper's root lockfile controls this build. The provider
is licensed under MPL-2.0; the complete license is included here.

The fixed dependency addresses
[RUSTSEC-2026-0330](https://rustsec.org/advisories/RUSTSEC-2026-0330.html) and
[RUSTSEC-2026-0331](https://rustsec.org/advisories/RUSTSEC-2026-0331.html).
No advisory is suppressed. HPKE 0.8 changes interfaces and requires a separate
OpenMLS compatibility review. The same manifest-only backport is documented
by the [Marmot Development Kit](https://github.com/marmot-protocol/mdk/tree/master/vendor/hpke-rs-libcrux).

Remove this patch when a published OpenMLS-compatible HPKE provider selects
the fixed KEM, or after a separately tested OpenMLS/HPKE upgrade. Refresh the
lockfile, run the provider compatibility tests, rebuild the native image, run
the SCAP group tests/demo and rerun cargo audit before removing it.

The separate [`security-regression` test crate](../../security-regression/README.md)
compiles this optional provider and tests the two RustSec input-validation
surfaces plus bidirectional compatibility with the unchanged RustCrypto
provider. The optional provider test requires Rust 1.95 for the fixed KEM's
`libcrux-platform 0.0.4` CPUID calls; production still builds with Rust 1.91.
From the repository root with Rust 1.95 or later:

```sh
cargo test --locked --manifest-path clients/mls_native/security-regression/Cargo.toml
cargo install --locked cargo-audit --version 0.22.2
cargo audit --file clients/mls_native/Cargo.lock
cargo audit --file clients/mls_native/security-regression/Cargo.lock
```

Both Cargo lockfiles are scanned in CI with no advisory exclusions. An
informational upstream maintenance warning, if reported by Cargo audit, remains
visible in the saved audit JSON; it is not an ignored vulnerability.
