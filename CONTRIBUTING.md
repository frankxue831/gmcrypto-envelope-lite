# Contributing

Thank you for considering a contribution. This crate is small and deliberately conservative: synchronous, HTTP-neutral, and explicit about its trust boundaries. Changes that widen scope (async runtimes, HTTP clients, new cryptographic constructions) need discussion in an issue before a pull request.

## Requirements

- Rust 1.85 or newer (edition 2024). CI also builds on the 1.85 MSRV toolchain.
- Python 3 available as `python3` is required by `tests/release_candidate.sh` to parse and validate release-candidate manifest JSON.
- Go is required to install actionlint 1.7.12, which must be available on `PATH` when `tests/workflows.sh` validates workflow syntax and contracts.
- A change must keep the public API's documented invariants: no plaintext, keys, or secrets in `Debug` output, errors, or logs.

## Before opening a pull request

Run the same checks CI enforces:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --doc --locked
RUSTDOCFLAGS="-D missing-docs -D warnings" cargo doc --locked --no-deps
sh tests/workflows.sh
cargo deny check
sh tests/open_source_boundary.sh
./ci/check-open-source-boundary.sh --worktree .
package_parent=$(mktemp -d "${TMPDIR:-/tmp}/secure-envelope-package-check.XXXXXX")
trap 'rm -rf "$package_parent"' 0 HUP INT TERM
./ci/check-cargo-package.sh "$PWD" "$package_parent/package"
```

The package helper requires a clean worktree. Its `mktemp` parent keeps the package output outside the repository and is removed when the shell exits.

## Release-readiness checks

The release gates use Rust stable, Rust 1.85.0, and nightly-2026-05-23. Their auxiliary tools are pinned to cargo-deny 0.20.2, cargo-public-api 0.52.0, cargo-fuzz 0.13.1, and actionlint 1.7.12. Install each Cargo tool with its exact `--version` and `--locked`; install the workflow checker with `go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12`.

Exercise each fail-closed checker and then its repository gate:

```sh
sh tests/workflows.sh
sh tests/public_api.sh
./ci/check-public-api.sh
sh tests/crypto_inventory.sh
./ci/check-crypto-inventory.sh
sh tests/fuzz_smoke.sh
sh ci/fuzz-smoke.sh smoke
sh tests/release_candidate.sh
```

To construct the complete release-candidate artifact set, first ensure `git status --short` prints nothing and that `HEAD` is the intended immutable candidate. The output path must be absolute, outside this repository, and absent before the command starts:

```sh
git status --short
./ci/check-release-candidate.sh HEAD /absolute/path/outside-this-repository/gmcrypto-envelope-lite-rc
```

A successful repository construction reaches only `rc-built`. Private exact-wire compatibility, organization policy acceptance, independent security review, legal approval, and release authorization remain external gates recorded in the blank [release checklist](RELEASE_CHECKLIST.md). No command in this repository publishes a crate, creates or pushes a tag, or grants publication approval.

## Release-boundary rules

This repository must stay free of private or partner-specific material. CI enforces a boundary scanner over the working tree, the repository export, and the crate package.

- Never commit private keys, certificates from real deployments, production identifiers, or real remote wire mappings — not even in tests, fixtures, comments, or commit messages.
- Test key material may only be generated with `tools/generate-public-test-fixtures.sh`, which produces disposable public-only fixtures.
- Protocol adapters for real deployments belong in separately access-controlled repositories, as described in README.md.

## Security issues

Do not report suspected vulnerabilities in issues or pull requests. Follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are dual-licensed under the [Apache License 2.0](LICENSE-APACHE) and the [MIT license](LICENSE-MIT), the same licenses that cover the project (inbound = outbound), without any additional terms or conditions.
