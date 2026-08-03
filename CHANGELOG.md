# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Opt-in `aead` feature: an SM4-GCM authenticated-encryption envelope mode (`EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm)`) pinned by `ClientConfig`, framed inside the existing `cipher` field (version, algorithm id, 12-byte random nonce, ciphertext, 16-byte tag) so `SecureEnvelope`, `ProtocolAdapter`, `HeaderSchema`, and `KeyMaterial` are unchanged. The AAD binds the frame header, domain separator, and protocol context; the SM2 signature remains mandatory. There is no mode negotiation: an AEAD client rejects CBC envelopes outright and vice versa. Enabling the feature compiles `gmcrypto-simd` and, on x86_64 and aarch64, its target-gated `cpufeatures` detection dependency; both are locked and recorded in a second, feature-scoped cryptographic-inventory tier.
- SM4-GCM known-answer test pinned to RFC 8998 Appendix A.1, an `aead_envelope` fuzz target with a curated corpus, and CI coverage (`cargo test/clippy/doc --features aead`) on all platforms plus MSRV.
- Plaintext length-sweep round-trip coverage in both envelope modes and both authentication modes, over the lengths where these constructions actually change behaviour: PKCS#7 appends a whole extra block at an exact multiple of the SM4 block, the AEAD frame wraps a variable-length ciphertext in fixed overhead, and Base64 pads differently for each length mod 3. Fault injection measured the gap it closes — before this, the CBC unit suite exercised 4 of 17 boundary lengths (missing 16, the full-pad-block case) and the AEAD suite 2 of 9; both now cover all of them. Added without a new dependency, deliberately: a property-testing crate would change `Cargo.lock` and so invalidate the reviewed lockfile hash and the cryptographic-dependency inventory.
- 38 fuzz corpus seeds for the `transport_parts` and `typed_headers` targets, covering the `Generic` arm — the branch that builds header sets from the seed itself (name class per slot, ordering permutation, duplicate injection) and which no tracked seed reached at all. They sit on the decisions the header types actually make: RFC token bytes for names, and the value rule that rejects everything below U+0020 except tab plus U+007F, so tab/space and U+001F/U+007F/NUL/CRLF are pinned on both sides of the boundary. Measured with libFuzzer over the tracked corpus: `transport_parts` coverage 164 → 291 and `typed_headers` 193 → 366; 29 of the 38 add coverage, the rest pin decisions that compile to already-covered edges. Each seed declares its expected adapter outcome in `fuzz/tests/scenarios.rs`, which the pre-existing corpus contract requires — seeds are never opaque blobs.
- `.gitattributes` marks `fuzz/corpus/**` as non-text. Git's end-of-line normalization had rewritten CRLF to LF while committing the two CRLF-injection seeds, which left them exercising a lone LF under a name that says otherwise and left their length prefixes describing one more byte than the value held. Nothing would have reported it: LF is rejected exactly like CRLF, so the seeds kept their declared outcomes. A contract test now asserts both seeds still carry a carriage return within the declared field length.
- `ci/check-compatibility-gate.sh` executes the ecosystem charter's section 8 compatibility gate #1: it exports this crate and a candidate `gmcrypto-core` side by side, runs both charter phases in both feature configurations, and emits the evidence table the core release record requires. The `aead` configuration matters here — it compiles `gmcrypto-core/sm4-aead`, which pulls `gmcrypto-simd` (and, on x86_64 and aarch64, its target-gated `cpufeatures` detection dependency) into the graph, so a default-features-only gate cannot see that path. The candidate override is relative by construction, because an absolute path writes a developer home directory into the manifest and the boundary scanner rejects it. Driven by the manually triggered `compatibility-gate` workflow and covered by the `tests/compatibility_gate.sh` self-test. Validated end to end against a real `gmcrypto-core` checkout rather than only against the self-test's fake cargo: the run reproduces the hand-run PASS recorded for the 1.11.0 candidate on every pre-existing target, and extends it with the `aead` tier that hand run could not have covered.

### Fixed

- Restored the release-document suite's CRLF-normalization regression test, dropped when the 0.1.0 release-candidate export was imported. The normalization itself survived the import, but nothing pinned it any more: with it removed, 12 of the 13 assertions still pass on macOS and Linux, so the loss would have surfaced only on Windows CI — and the 0.1.0 changelog already claims the behaviour as a fix. The read path is now a named `read_normalized`, exercised against a CRLF fixture and against a lone carriage return, which it must leave intact. Found by comparing the compatibility gate's per-target counts against the counts recorded for the hand-run 1.11.0 gate.

### Changed

- Version identity moved to 0.2.0; the public API surface under default features is content-identical to the 0.1.0 snapshot. Security model, engineering evidence, API-stability policy, and cryptographic inventory documents advanced to version 2.

## [0.1.0] - 2026-08-02

### Changed

- Renamed the unpublished crate and Rust library target from `secure-envelope-lite` / `secure_envelope_lite` to `gmcrypto-envelope-lite` / `gmcrypto_envelope_lite` before recording the 0.1.0 RC baseline.
- Aligned the license to the ecosystem-standard dual `MIT OR Apache-2.0` (charter §3): the manifest `license` field is now dual, the Apache text moved to `LICENSE-APACHE`, an in-crate `LICENSE-MIT` was added so both texts ship inside the published archive, and the contribution terms in CONTRIBUTING.md are inbound-equals-outbound under both licenses.
- Updated the manifest `repository` URL to `https://github.com/frankxue831/gmcrypto-envelope-lite`, matching the public repository's rename to the official crate name.
- Enabled publication and relaxed the `gmcrypto-core` requirement from the unpublished exact pin to the caret requirement `1.11`, per the ecosystem charter's first-publication rule; the lockfile continues to resolve 1.11.0.
- Bumped the exact `gmcrypto-core` pin from 1.9.0 to 1.11.0 in the crate manifest and the fuzz workspace after running compatibility gate #1 (full test, formatting, Clippy, boundary, and dependency-policy checks) and re-reviewing the cryptographic dependency inventory; the compiled source delta is limited to the SM4 CBC path, the feature-gated AEAD modules remain disabled, and the backend license metadata is now `MIT OR Apache-2.0`.

### Fixed

- Release-document contract tests now normalize CRLF line endings when reading repository files, so multi-line lockfile assertions hold on Windows checkouts that apply autocrlf conversion.
- Refreshed the pinned CI tooling for current runner images: `cargo-fuzz` 0.13.1 to 0.13.2 (0.13.1 no longer compiles under the runners' updated stable Rust), and the actionlint version check now accepts the `v`-prefixed version string emitted by `go install` builds while still failing closed on any other version.
- Self-test fixtures now track the reviewed state: the inventory-checker mutations target the current 1.11.0 backend checksum and lockfile hash, and the fuzz-runner self-test's fake tool reports the pinned cargo-fuzz version.
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
