# Contributing

Thank you for considering a contribution. This crate is small and deliberately conservative: synchronous, HTTP-neutral, and explicit about its trust boundaries. Changes that widen scope (async runtimes, HTTP clients, new cryptographic constructions) need discussion in an issue before a pull request.

## Requirements

- Rust 1.85 or newer (edition 2024). CI also builds on the 1.85 MSRV toolchain.
- A change must keep the public API's documented invariants: no plaintext, keys, or secrets in `Debug` output, errors, or logs.

## Before opening a pull request

Run the same checks CI enforces:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --doc --locked
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
sh tests/open_source_boundary.sh
./ci/check-open-source-boundary.sh --worktree .
```

## Release-boundary rules

This repository must stay free of private or partner-specific material. CI enforces a boundary scanner over the working tree, the repository export, and the crate package.

- Never commit private keys, certificates from real deployments, production identifiers, or real remote wire mappings — not even in tests, fixtures, comments, or commit messages.
- Test key material may only be generated with `tools/generate-public-test-fixtures.sh`, which produces disposable public-only fixtures.
- Protocol adapters for real deployments belong in separately access-controlled repositories, as described in README.md.

## Security issues

Do not report suspected vulnerabilities in issues or pull requests. Follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), the same license that covers the project (inbound = outbound).
