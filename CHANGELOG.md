# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-02

### Changed

- Renamed the unpublished crate and Rust library target from `secure-envelope-lite` / `secure_envelope_lite` to `gmcrypto-envelope-lite` / `gmcrypto_envelope_lite` before recording the 0.1.0 RC baseline.
- Aligned the license to the ecosystem-standard dual `MIT OR Apache-2.0` (charter §3): the manifest `license` field is now dual, the Apache text moved to `LICENSE-APACHE`, an in-crate `LICENSE-MIT` was added so both texts ship inside the published archive, and the contribution terms in CONTRIBUTING.md are inbound-equals-outbound under both licenses.
- Updated the manifest `repository` URL to `https://github.com/frankxue831/gmcrypto-envelope-lite`, matching the public repository's rename to the official crate name.
- Enabled publication and relaxed the `gmcrypto-core` requirement from the unpublished exact pin to the caret requirement `1.11`, per the ecosystem charter's first-publication rule; the lockfile continues to resolve 1.11.0.
- Bumped the exact `gmcrypto-core` pin from 1.9.0 to 1.11.0 in the crate manifest and the fuzz workspace after running compatibility gate #1 (full test, formatting, Clippy, boundary, and dependency-policy checks) and re-reviewing the cryptographic dependency inventory; the compiled source delta is limited to the SM4 CBC path, the feature-gated AEAD modules remain disabled, and the backend license metadata is now `MIT OR Apache-2.0`.

### Fixed

- Refreshed the root lockfile from yanked `spin` 0.10.0 to 0.10.1, which contains the upstream `Once` move-out double-drop fix; this records the dependency fix without claiming that the SDK exercised the affected consuming APIs.
- The boundary-scanner self-test now probes whether the environment can create symlink and FIFO fixtures (Windows Git Bash copies `ln -s` sources by default) and skips only those checks where the fixture cannot exist; Windows CI sets `MSYS=winsymlinks:nativestrict` to keep full assertion coverage with real native symlinks.
- The denylist literal-path self-test no longer embeds a backslash in a single path component, which Windows path handling treats as a directory separator; backslash literalness is covered by a dedicated check that runs where such names round-trip.

### Added

- Versioned security claims/non-claims, API-stability policy, engineering evidence map, and cryptographic dependency inventory.
- Pinned public-API snapshot, bounded fuzz harnesses, and a blank external-gate template for external promotion review.
- Initial import of `secure-envelope-lite`: a synchronous, HTTP-neutral library for SM2/SM3 signatures and SM4 secure envelopes.
- `SecureClient` with immutable `ClientConfig`, four role-specific keys (`KeyMaterial`), and pluggable `ProtocolAdapter`.
- `AuthenticationMode::ContextBound` with a length-prefixed signed transcript, and `AuthenticationMode::LegacyPlaintext` for legacy wire compatibility.
- `HeaderProtocolAdapter` and `HeaderSchema` builder for header-mapped legacy protocols.
- Transport-neutral `RequestParts` / `ResponseParts` with case-insensitive header validation and injection rejection.
- Zeroization of SDK-owned session-key and plaintext buffers.
- Release-boundary tooling: `ci/check-open-source-boundary.sh` scanner (worktree, export, and package modes), scanner self-tests, and CI enforcement across Linux/macOS/Windows plus a 1.85 MSRV job.
- Disposable public-only test fixtures and `tools/generate-public-test-fixtures.sh`.
