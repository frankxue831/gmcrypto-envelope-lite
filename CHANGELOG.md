# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- The boundary-scanner self-test now probes whether the environment can create symlink and FIFO fixtures (Windows Git Bash copies `ln -s` sources by default) and skips only those checks where the fixture cannot exist; Windows CI sets `MSYS=winsymlinks:nativestrict` to keep full assertion coverage with real native symlinks.

### Added

- Initial import of `secure-envelope-lite`: a synchronous, HTTP-neutral library for SM2/SM3 signatures and SM4 secure envelopes.
- `SecureClient` with immutable `ClientConfig`, four role-specific keys (`KeyMaterial`), and pluggable `ProtocolAdapter`.
- `AuthenticationMode::ContextBound` with a length-prefixed signed transcript, and `AuthenticationMode::LegacyPlaintext` for legacy wire compatibility.
- `HeaderProtocolAdapter` and `HeaderSchema` builder for header-mapped legacy protocols.
- Transport-neutral `RequestParts` / `ResponseParts` with case-insensitive header validation and injection rejection.
- Zeroization of SDK-owned session-key and plaintext buffers.
- Release-boundary tooling: `ci/check-open-source-boundary.sh` scanner (worktree, export, and package modes), scanner self-tests, and CI enforcement across Linux/macOS/Windows plus a 1.85 MSRV job.
- Disposable public-only test fixtures and `tools/generate-public-test-fixtures.sh`.
