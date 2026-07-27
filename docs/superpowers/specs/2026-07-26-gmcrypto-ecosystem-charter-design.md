# gmcrypto Ecosystem Charter Design

**Status:** Approved on 2026-07-26

**Date:** 2026-07-26

**Target repositories:** `gm-crypto-rs` (charter home) and this repository (crate rename and README link-back)

## 1. Purpose

Establish a minimal, written ecosystem charter for the gmcrypto-core-centered Rust cryptography ecosystem before the envelope crate records its 0.1.0 release-candidate baseline. The charter turns properties that currently hold by discipline — layering, encapsulation, the public/private boundary, MSRV alignment — into short, authoritative policy, and it names the envelope crate's 0.1.0 RC suite as the ecosystem's first downstream compatibility gate.

This phase produces documentation and one crate rename. It does not start partner integrations, does not create new public crates, and does not publish anything.

## 2. Current baseline

Facts verified at design time:

- `gmcrypto-core` 1.9.0 is published on crates.io and developed in the `gm-crypto-rs` workspace alongside `gmcrypto-c` (C ABI shim) and `gmcrypto-simd` (opt-in SIMD backend); a cargo-fuzz workspace is kept out of the published dependency graph.
- The core workspace family shares one workspace version (1.9.0) with exact intra-workspace pins (`=1.9.0`) between members, and releases in lockstep.
- `gmcrypto-core` 1.9.0 includes an optional TLCP cryptographic toolkit behind the `tlcp` feature (key schedule, record protection, certificate-pair verification) in addition to SM2/SM3/SM4 primitives and X.509 support.
- The `gm-crypto-rs` repository carries one repository-level `SECURITY.md`; its member crates do not duplicate it.
- The envelope crate in this repository is named `secure-envelope-lite`, version 0.1.0, `publish = false`, with an approved 0.1.0 RC-readiness design and 112 passing tests.
- The envelope crate consumes `gmcrypto-core` with an exact pin (`=1.9.0`) in exactly three modules (`src/keys.rs`, `src/envelope_crypto.rs`, `src/client.rs`) and does not re-export core types in its public API.
- Both the core workspace and the envelope crate declare `rust-version = "1.85"`.
- The envelope repository carries a release-boundary scanner, an external denylist mechanism, and a private-fixture policy.
- GitHub already hosts the private `secure-envelope-lite` repository; the current `partner-sdk-rust-lite` checkout is a development source tree with no configured remote, not a reason to create a second envelope remote.
- The public `gm-crypto-rs-demo` repository is an external-consumer example and published-version smoke test. Its package remains unpublished, so it is a supporting repository rather than an official crate in the charter list.
- Earlier pure-Java projects are independent historical projects. They neither depend on `gmcrypto-core` nor belong to this Rust ecosystem.

## 3. Goals

- Publish one authoritative charter document in the core repository, one to two pages, with the eight sections specified in section 6.
- Record the naming decision: the `gmcrypto-*` prefix is reserved for officially maintained, charter-governed crates at all layers, and the envelope crate is renamed `gmcrypto-envelope-lite` before its 0.1.0 RC baseline.
- Make every charter rule either checkable today (it names the command, file, or test that verifies it) or explicitly marked policy-only.
- Keep the charter free of contradictions with the envelope crate's README and the RC-readiness design's non-goals.

## 4. Non-goals

- No partner-integration crates, no new public crates, and no meta/governance repository.
- No RFC process, maintainer hierarchy, or other governance structure beyond the charter text.
- No code or API changes in either repository beyond the mechanical crate rename.
- No publishing, no release tags, and no change to `publish = false`.
- No cross-repository CI automation in this phase; the compatibility gate is operated manually as specified in section 6.8.

## 5. Deliverables

1. `docs/ECOSYSTEM.md` in the `gm-crypto-rs` repository containing the charter (section 6).
2. One link line to the charter from the `gm-crypto-rs` README.
3. A short "Position in the ecosystem" section in this repository's README linking to the charter.
4. The crate rename specified in section 8, completed before the RC baseline is recorded.

## 6. Charter content specification

The charter is normative but minimal: eight sections, each one short paragraph or list. The language below is the intended substance; exact wording may be edited during implementation.

### 6.1 Mission and scope

A layered Rust ecosystem for GM/SM cryptography (SM2, SM3, SM4) centered on `gmcrypto-core`. The core provides cryptographic primitives and standards-level cryptographic building blocks — including encoding, X.509 support, and the optional TLCP toolkit (key schedule, record protection, certificate-pair verification). The core's boundary excludes transport I/O, connection and session orchestration, application envelope formats, endpoint policy, and partner-specific mappings; those belong to higher layers.

### 6.2 Layering and encapsulation rule

Three layers: core (primitives and standards-level building blocks), public protocol crates (for example the secure-envelope layer), and private deployment adapters. A public ecosystem crate other than the core must not expose core types, traits, or macros in its public API and must not `pub use` them. Checkable today in the envelope crate: `grep -rn "pub use gmcrypto" src/` returns nothing, and the root-API integration test (`tests/public_api.rs`) exercises the public surface without core types.

### 6.3 Naming policy

The `gmcrypto-*` crate-name prefix is reserved for officially maintained, charter-governed ecosystem crates at all layers — not only core-family crates. Third-party or community crates use their own neutral names. This reservation is a charter policy, not an enforceable crates.io namespace: crates.io does not restrict who may publish names with this prefix. For an unpublished crate, official status is established by the charter's authoritative crate list together with verified source-repository and maintainer identity. Once an official crate is published, its crates.io publisher metadata must also match that identity. A prefix or crate name alone never establishes official status. The initial list is `gmcrypto-core`, `gmcrypto-c`, `gmcrypto-simd`, and `gmcrypto-envelope-lite`. A crate joins the list only through the admission criteria in 6.7.

### 6.4 Version coupling and MSRV

Two coupling regimes exist. The core workspace family (`gmcrypto-core`, `gmcrypto-c`, `gmcrypto-simd`) shares one workspace version, keeps exact intra-workspace pins, and releases in lockstep; this regime is permanent. Independently versioned downstream crates such as `gmcrypto-envelope-lite` follow their own release cadence: while unpublished they pin the exact core version (as the envelope crate pins `=1.9.0`), and at first publication the pin relaxes to a caret requirement. Before a downstream crate bumps its core pin, its full test suite and boundary checks must pass against the new core version. The ecosystem MSRV equals the core's published `rust-version` (1.85 today); an official crate must not require a newer toolchain than the core without a charter update, and MSRV increases are recorded in changelogs.

### 6.5 Public/private boundary

Partner-specific mappings, identities, fixtures, denylist entries, and exact-wire compatibility suites live only in private repositories. A public repository must pass a release-boundary scan before any publication step; the envelope repository's scanner (`tests/open_source_boundary.sh` plus its external-denylist mechanism) is the reference implementation. Untracked files in a public checkout are not a secrecy boundary. Publishing a previously private tree uses a fresh, reviewed export or repository — or, alternatively, a separately approved history rewrite followed by fresh-clone verification and a boundary scan of the rewritten history, matching the envelope README and the RC-readiness design.

### 6.6 Per-crate security baseline

The security baseline applies at repository level: a security policy file, RUSTSEC advisory monitoring (`cargo-deny` configuration or equivalent in CI), and fuzz coverage where untrusted structured input is parsed. A repository hosting multiple official crates (as `gm-crypto-rs` hosts the core family) satisfies the baseline once for all its members rather than duplicating files per crate. Every official crate, regardless of repository, carries an explicit statement that no independent audit has occurred until one has, and must not claim audit status, universal constant-time behavior, or protection from a compromised process.

### 6.7 Admission criteria for new official crates

A new official public crate requires, from day one: a concrete consumer that needs it, a named owner, and the full security baseline of 6.6. Shared release tooling and evidence-map templates are extracted into a meta-repository only when at least three independently released official public repositories exist and duplicated tooling or policy maintenance has become concrete. Supporting repositories such as an unpublished demo do not count toward this threshold. This criterion exists to keep the ecosystem small and well-maintained rather than broad and thin.

### 6.8 Compatibility gates

The charter keeps a registry of downstream compatibility gates that core releases must respect. Gate #1 is the `gmcrypto-envelope-lite` 0.1.0 RC suite: the crate's full test, formatting, Clippy, and boundary checks. The gate runs at two points. First, before every `gmcrypto-core` release, the release candidate is tested against the gate through a temporary `path` dependency or `[patch]` override of the envelope crate's core dependency — a downstream pin bump is not a sufficient trigger, because once the dependency is a caret requirement a compatible core release reaches consumers without any downstream change. Second, on the downstream side: while the envelope crate pins an exact core version, the gate also runs on every pin bump; after the crate publishes with a caret requirement, its own runs cover both the minimum supported and the newest compatible core version. A core release that would break the gate requires a documented migration note before it ships. The gate is operated manually in this phase; cross-repository CI is deliberately deferred (policy-only until then).

## 7. Repository topology and creation triggers

This phase creates no repository. It assigns authoritative roles to the repositories that already exist:

1. `gm-crypto-rs` remains the public core repository and charter authority. It continues to host `gmcrypto-core`, `gmcrypto-c`, and `gmcrypto-simd`; those workspace members are not split into separate repositories.
2. The existing private `secure-envelope-lite` GitHub repository is the target repository identity for the envelope SDK; when the maintainer separately authorizes the hosted-repository rename, it is renamed in place to `gmcrypto-envelope-lite`. The current `partner-sdk-rust-lite` checkout is a development source tree, not a third envelope repository. Before any push, the implementation plan must reconcile the two Git histories and choose a reviewed transfer path; it must not assume that a force-push or history replacement is authorized.
3. `gm-crypto-rs-demo` remains a public supporting repository for examples and smoke-testing the published `gmcrypto-core` release. It is not an official published crate, does not enter the authoritative crate list, and does not by itself trigger a governance repository.

Future repositories are created only when their trigger is present:

- A private partner-adapter repository requires a real partner, a real wire mapping, and a named owner.
- A public ecosystem workspace is created together with its first admitted, concrete crate that has a real consumer and does not belong in the core workspace or envelope repository; an empty placeholder workspace is prohibited.
- A language-binding repository requires a real language consumer whose needs cannot be met by `gmcrypto-c`.
- A governance/meta repository requires at least three independently released official public repositories plus demonstrated duplication of release tooling or policy maintenance.
- A shared test-vector repository requires the same vector corpus to be independently maintained in at least two official repositories with demonstrated duplication or drift.

Until a trigger is met, governance, documentation, release templates, test vectors, and examples remain with the repository that owns and verifies them. No standalone governance, documentation/site, test-vector, or empty ecosystem repository is created in this phase. The earlier Java repositories remain outside the charter and are not renamed or migrated.

## 8. Rename specification

The envelope crate is renamed `secure-envelope-lite` → `gmcrypto-envelope-lite` (library target `secure_envelope_lite` → `gmcrypto_envelope_lite`) before the 0.1.0 RC baseline is recorded, while `publish = false` still holds. The rename covers:

- `Cargo.toml` package name and lib name, and the regenerated `Cargo.lock` entry;
- every `use secure_envelope_lite::…` and doc reference across `src/`, `tests/`, `examples/`, `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, and the RC-phase documents that name the crate;
- crates.io metadata fields that embed the name (description stays accurate; keywords unchanged).

The Cargo `repository` field currently points at the `secure-envelope-lite` GitHub repository. Renaming the hosted repository is owned by the maintainer outside this phase; the field is updated when that happens, and confirming the final URL is added to the RC checklist as a pre-publication item. A stale URL is acceptable only while `publish = false`.

Prior design and plan documents under `docs/superpowers/` are historical records and are not retro-edited; only living documents (README, security model, RC checklist, CHANGELOG) are updated.

## 9. Sequencing

1. Land the charter (`docs/ECOSYSTEM.md` and README link) in `gm-crypto-rs`.
2. Land the rename and the "Position in the ecosystem" README section in this repository.
3. Resume the already-approved 0.1.0 RC-readiness phase under the charter, with the crate under its final name.

Partner integrations and additional public crates remain out of scope until after the RC phase.

## 10. Verification

- Charter self-consistency: every rule in section 6 either names its checking command, file, or test, or carries an explicit policy-only marker. Cross-read the charter against the envelope README and the RC design's non-goals; zero contradictions is the acceptance bar.
- Rename correctness in this repository: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, the boundary-scanner self-test, and a repository-wide search proving no stale `secure_envelope_lite`/`secure-envelope-lite` references remain outside historical `docs/superpowers/` documents and the CHANGELOG entry that records the rename.
- Core repository check: the charter document builds no code, so verification there is review plus link validity.
- Repository-topology check: the implementation plan creates no remote repository; it identifies the existing envelope remote as the rename target, preserves `gm-crypto-rs-demo` as a supporting repository, and treats any Git-history replacement or force-push as a separately authorized operation.

## 11. Risks and accepted trade-offs

- Renaming during a freeze-oriented phase adds churn; it is accepted because the rename is mechanical, happens before the API baseline is recorded, and becomes strictly more expensive after first publication.
- The compatibility gate is manual until cross-repository CI exists; this is stated in the charter rather than implied away.
- Running gate #1 against every core release candidate adds a step to the core release process; accepted because it is the only point where an incompatible core release can still be stopped once downstream uses a caret requirement.
- The charter lives in the core repository, so downstream-only policy edits require core-repo commits; accepted as the cost of a single source of truth.
- Reusing the existing private envelope remote avoids repository proliferation, but the development checkout and remote currently have different histories; reconciling them is a planned, reviewed migration step rather than an implicit push operation.
