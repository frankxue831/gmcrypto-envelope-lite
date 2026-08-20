# AGENTS

## Cursor Cloud specific instructions

`gmcrypto-envelope-lite` is a single synchronous Rust library crate (SM2/SM3 signatures and
SM4 secure envelopes). There is no long-running service to start: development is entirely
`cargo` build/lint/test plus two example binaries. See `README.md` and `CONTRIBUTING.md` for
the authoritative command list; the notes below only capture non-obvious gotchas.

### Toolchain

- The crate is edition 2024 with an MSRV of `1.85` (`Cargo.toml`). The base image's default
  `rustc` may be older than 1.85 and cannot compile the crate; the update script installs a
  current `stable` toolchain (with `clippy`/`rustfmt`) plus the `1.85.0` MSRV toolchain and sets
  `stable` as the rustup default. Use `cargo +1.85.0 ...` to reproduce MSRV CI checks.

### Everyday commands (from `CONTRIBUTING.md` / `.github/workflows/ci.yml`)

- Build: `cargo build --all-targets --locked` (add `--features aead` for the AEAD path).
- Lint: `cargo fmt --all -- --check` and `cargo clippy --all-targets --locked -- -D warnings`
  (also run the `--features aead` clippy variant).
- Test: `cargo test --all-targets --locked` and the `--features aead` variant, plus
  `cargo test --doc --locked`.
- The `aead` feature is opt-in and off by default; the two example binaries (`build_request`,
  `open_response`) are gated on it via `required-features`, so they only build/run with
  `--features aead`.

### Running the example binaries (non-obvious)

- `examples/build_request.rs` and `examples/open_response.rs` require four on-disk SM2 key
  files plus the `SECURE_ENVELOPE_KEY_PASSWORD` env var. The private-key files must be
  **encrypted PKCS#8 using this ecosystem's PBES2 profile: PBKDF2-HMAC-SM3 + SM4-CBC**
  (see `gmcrypto-core`'s `pkcs8` module). OpenSSL's default PKCS#8 encryption
  (PBKDF2-HMAC-SHA256 + AES) is **not** accepted and fails with `KeyMaterial { kind: LocalPrivate }`.
- Both PEM and raw DER are accepted (`PrivateKey::from_encrypted_file` /
  `PublicKey::from_file` sniff the container), so compatible DER key files can be generated
  with a tiny throwaway program that depends on `gmcrypto-core` and calls `pkcs8::encrypt`
  (+`spki::encode` for the public keys). `tools/generate-public-test-fixtures.sh` only emits
  *public* fixtures via OpenSSL and does not produce loadable encrypted private keys for the
  examples.
- `open_response` needs a fully-formed, signed+encrypted response envelope (JSON with
  `headers` + `body`) produced by the remote side; the full request/response round trip is
  exercised by the integration tests (e.g. `tests/aead_envelope.rs`, `tests/secure_client.rs`)
  rather than by manually hand-authoring a response.

### Release / policy gates (optional, heavy)

The `quality` and `fuzz-smoke` CI jobs use extra pinned tooling that the update script does
**not** install because it is slow and only needed for release-readiness work:
`nightly-2026-05-23`, `cargo-deny 0.20.2`, `cargo-public-api 0.52.0`, `cargo-fuzz 0.13.2`, and
`actionlint v1.7.12` (installed via `go install`). Versions are pinned in `ci/tool-versions.sh`.
Install these on demand when running the boundary/API/fuzz/release scripts under `ci/` and
`tests/`.
