# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Renamed the unpublished crate and Rust library target from `secure-envelope-lite` / `secure_envelope_lite` to `gmcrypto-envelope-lite` / `gmcrypto_envelope_lite` before recording the 0.1.0 RC baseline.

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
