# gmcrypto Ecosystem Charter and Envelope Rename Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the normative `gmcrypto-core`-centered Rust ecosystem charter, rename the envelope crate to `gmcrypto-envelope-lite` before its 0.1.0 RC baseline, and prove the renamed RC suite works as compatibility gate #1.

**Architecture:** Keep governance in the existing public `gm-crypto-rs` repository and keep the envelope implementation in its existing private repository identity. Land the charter first, then layer a mechanical package/library/tooling/documentation rename onto the already-built RC-readiness branch. Preserve the current exact `gmcrypto-core = "=1.9.0"` dependency and all runtime behavior; validate the downstream gate against the local core checkout through a temporary Cargo patch. Do not create a repository, publish a crate, rename or push a hosted repository, rewrite history, or force-push in this phase.

**Tech Stack:** Rust 2024, Cargo, rustfmt, Clippy, cargo-public-api 0.52.0 on nightly-2026-05-23, cargo-deny 0.20.2, cargo-fuzz 0.13.1, POSIX shell, Git, Markdown.

---

## Repository map and fixed boundaries

- Core source: `"$GMCRYPTO_CORE_SOURCE"`
- Core implementation worktree: `"$GMCRYPTO_CORE_WORKTREE"`
- Envelope planning source: `"$GMCRYPTO_ENVELOPE_SOURCE"`
- Existing envelope RC worktree: `"$GMCRYPTO_ENVELOPE_RC"`
- Existing private hosted-repository clone: `"$GMCRYPTO_TARGET_CLONE"`
- Core implementation branch: `codex/gmcrypto-ecosystem-charter`, created from the then-current `origin/main` in an isolated worktree
- Envelope implementation branch: existing `codex/0.1.0-rc-readiness`

### Runtime path discovery

Run this block from the envelope RC worktree before any task or command shell that uses the task-specific path variables:

```sh
set -eu

GMCRYPTO_ENVELOPE_RC=$(git rev-parse --show-toplevel)
GMCRYPTO_COMMON_GIT=$(git rev-parse --path-format=absolute --git-common-dir)
GMCRYPTO_ENVELOPE_SOURCE=$(dirname "$GMCRYPTO_COMMON_GIT")
GMCRYPTO_WORKSPACE_ROOT=$(dirname "$GMCRYPTO_ENVELOPE_SOURCE")
GMCRYPTO_CORE_SOURCE="$GMCRYPTO_WORKSPACE_ROOT/gm-crypto-rs"
GMCRYPTO_TARGET_CLONE="$GMCRYPTO_WORKSPACE_ROOT/secure-envelope-lite"
GMCRYPTO_CORE_WORKTREE=$(
    git -C "$GMCRYPTO_CORE_SOURCE" worktree list --porcelain |
        awk -v expected_branch='refs/heads/codex/gmcrypto-ecosystem-charter' '
            /^worktree / { worktree_path = substr($0, 10) }
            $0 == "branch " expected_branch {
                selected_path = worktree_path
                match_count += 1
            }
            END {
                if (match_count != 1) {
                    print "error: expected exactly one gmcrypto ecosystem charter worktree" >"/dev/stderr"
                    exit 1
                }
                print selected_path
            }
        '
) || exit 1

for GMCRYPTO_REQUIRED_DIRECTORY in \
    "$GMCRYPTO_COMMON_GIT" \
    "$GMCRYPTO_ENVELOPE_SOURCE" \
    "$GMCRYPTO_ENVELOPE_RC" \
    "$GMCRYPTO_WORKSPACE_ROOT" \
    "$GMCRYPTO_CORE_SOURCE" \
    "$GMCRYPTO_CORE_WORKTREE" \
    "$GMCRYPTO_TARGET_CLONE"
do
    test -d "$GMCRYPTO_REQUIRED_DIRECTORY" || {
        echo "error: required gmcrypto directory is missing" >&2
        exit 1
    }
done

test "$(git -C "$GMCRYPTO_ENVELOPE_SOURCE" branch --show-current)" = main
test "$(git -C "$GMCRYPTO_ENVELOPE_RC" branch --show-current)" = codex/0.1.0-rc-readiness
test "$(git -C "$GMCRYPTO_CORE_SOURCE" branch --show-current)" = main
test "$(git -C "$GMCRYPTO_CORE_WORKTREE" branch --show-current)" = codex/gmcrypto-ecosystem-charter
test "$(git -C "$GMCRYPTO_TARGET_CLONE" branch --show-current)" = main
```

Each task or command shell using these variables must execute this discovery block first, or receive all seven variables through its runner environment. Shell variables do not persist across independent command invocations; rediscovery prevents cross-shell state defects.

The development source and private hosted-repository clone have different Git histories. This plan produces reviewed commits in the development source and a read-only transfer assessment. It does not choose or execute a hosted transfer, push, repository rename, history replacement, or force-push. Those operations require a separate maintainer authorization after the implementation is reviewed.

## Task 1: Establish clean implementation worktrees and integrate the approved design

**Files:**

- Verify: `"$GMCRYPTO_CORE_SOURCE/.git"`
- Verify: `"$GMCRYPTO_CORE_WORKTREE/.git"`
- Verify: `"$GMCRYPTO_ENVELOPE_SOURCE/.git"`
- Verify: `"$GMCRYPTO_ENVELOPE_RC/.git"`
- Merge into: `"$GMCRYPTO_ENVELOPE_RC"`

- [ ] **Step 1: Re-read the approved design and confirm the non-goals**

Run from `"$GMCRYPTO_ENVELOPE_SOURCE"`:

```sh
sed -n '1,260p' docs/superpowers/specs/2026-07-26-gmcrypto-ecosystem-charter-design.md
```

Expected: the document specifies zero new repositories, no publication, no partner adapter, no cross-repository CI, no hosted rename, and no unauthorized history rewrite.

- [ ] **Step 2: Verify every source tree is clean before branching or merging**

```sh
git -C "$GMCRYPTO_CORE_SOURCE" status --short --branch
git -C "$GMCRYPTO_CORE_WORKTREE" status --short --branch
git -C "$GMCRYPTO_ENVELOPE_SOURCE" status --short --branch
git -C "$GMCRYPTO_ENVELOPE_RC" status --short --branch
git -C "$GMCRYPTO_TARGET_CLONE" status --short --branch
```

Expected: no modified or untracked paths. Stop and ask the maintainer before touching any tree that is not clean.

- [ ] **Step 3: Verify the already-created isolated core implementation worktree**

The core implementation worktree already exists in the global Superpowers worktree directory. The `gm-crypto-rs` repository does not ignore a repo-local `.worktrees` directory, so using the global directory avoids an unrelated `.gitignore` change. Do not fetch or recreate the worktree in this task.

```sh
git -C "$GMCRYPTO_CORE_WORKTREE" status --short --branch
test "$(git -C "$GMCRYPTO_CORE_WORKTREE" branch --show-current)" = codex/gmcrypto-ecosystem-charter
test "$(git -C "$GMCRYPTO_CORE_WORKTREE" rev-parse HEAD)" = 6b89e30616ccb1ff05448c50ee72e9b522396577
```

Expected: the existing worktree is clean on `codex/gmcrypto-ecosystem-charter` at the fetched `origin/main` commit `6b89e30616ccb1ff05448c50ee72e9b522396577`. Do not fetch, recreate the worktree, reset, or overwrite the existing local `main`, which was one commit behind `origin/main` during planning.

- [ ] **Step 4: Merge the newly committed design and plan into the existing RC branch**

Run from `"$GMCRYPTO_ENVELOPE_RC"`:

```sh
git rev-parse HEAD
git merge --no-ff main -m "merge: bring ecosystem design into rc branch"
git diff --name-only 93e3aafebf2c4bb0f5f52286e1b4be439ac7b4d1..HEAD
```

Expected: the pre-merge head is `93e3aafebf2c4bb0f5f52286e1b4be439ac7b4d1`, the merge succeeds without conflict, and the diff introduced by the merge contains only the approved ecosystem spec and this implementation plan under `docs/superpowers/`. If the branch has advanced legitimately, record its clean head and review the actual merge diff instead of resetting it.

- [ ] **Step 5: Confirm the existing RC work remains present**

```sh
test -f SECURITY_MODEL.md
test -f RELEASE_CHECKLIST.md
test -f api/secure-envelope-lite-0.1.0.txt
test -x ci/check-release-candidate.sh
test -f fuzz/tests/scenarios.rs
git status --short
```

Expected: every check succeeds and the worktree is clean. This plan extends the existing RC work; it does not reimplement it.

## Task 2: Land the authoritative charter in `gm-crypto-rs`

**Files:**

- Create: `"$GMCRYPTO_CORE_WORKTREE/docs/ECOSYSTEM.md"`
- Modify: `"$GMCRYPTO_CORE_WORKTREE/README.md"`

- [ ] **Step 1: Prove the charter and README link are absent**

Run from `"$GMCRYPTO_CORE_WORKTREE"`:

```sh
test ! -e docs/ECOSYSTEM.md
! rg -F '[gmcrypto Rust ecosystem charter](docs/ECOSYSTEM.md)' README.md
```

Expected: both commands succeed, proving the deliverables do not already exist. If either fails because upstream added an equivalent document, stop and reconcile it with the approved design instead of overwriting it.

- [ ] **Step 2: Create the eight-section charter**

Create `docs/ECOSYSTEM.md` with this complete content:

````markdown
# gmcrypto Rust Ecosystem Charter

**Status:** Normative

This charter is the authoritative definition of the official `gmcrypto-core`-centered Rust ecosystem. It records scope, layering, names, release coupling, security expectations, admission rules, and downstream compatibility gates.

## 1. Mission and scope

The ecosystem provides layered Rust support for GM/SM cryptography centered on `gmcrypto-core`. The core supplies SM2, SM3, and SM4 primitives plus standards-level cryptographic building blocks such as encoding, X.509 support, and the optional TLCP key-schedule, record-protection, and certificate-pair toolkit. Transport I/O, connection or session orchestration, application envelope formats, endpoint policy, and partner-specific mappings are outside the core boundary and belong to higher layers.

**Verification:** the core workspace manifests and feature documentation identify the standards-level building blocks present today. The placement of future functionality at the correct layer is a policy-only architecture review until an automated architecture check exists.

## 2. Layering and encapsulation

The ecosystem has three layers: the core family, independently versioned public protocol crates, and private deployment adapters. A public ecosystem crate outside the core family must not expose `gmcrypto-core` types, traits, or macros in its public API and must not re-export them. The envelope crate is the first reference implementation of this boundary.

**Verification in `gmcrypto-envelope-lite`:** `grep -RIn "pub use gmcrypto" src/` must produce no matches, `cargo test --test public_api` must pass, and `./ci/check-public-api.sh` must show no unreviewed core types in the public API snapshot. Applying the same encapsulation rule to a future crate is policy-only until that crate adds an equivalent gate.

## 3. Official names and identity

The `gmcrypto-*` crate-name prefix is reserved by project policy for officially maintained, charter-governed crates at every layer. It is not an enforceable crates.io namespace. For an unpublished crate, official identity requires an entry in this charter together with verified source-repository and maintainer identity. Once an official crate is published, its crates.io publisher metadata must also match that identity. A prefix or crate name alone never establishes official status. The initial official list is `gmcrypto-core`, `gmcrypto-c`, `gmcrypto-simd`, and `gmcrypto-envelope-lite`.

The unpublished `gm-crypto-rs-demo` project is a supporting example and published-version smoke test, not an official published crate. Historical Java projects are independent and are not members of this Rust ecosystem.

**Verification:** compare the authoritative list above with workspace and downstream manifests plus verified source-repository and maintainer identity; for each published crate, also compare its crates.io publisher record and linked source repository. Prefix reservation and third-party naming remain policy-only because crates.io cannot enforce this charter.

## 4. Version coupling and MSRV

The core workspace family (`gmcrypto-core`, `gmcrypto-c`, and `gmcrypto-simd`) shares one workspace version, uses exact intra-workspace pins, and releases in lockstep. Independently versioned downstream crates use their own release cadence. While unpublished, `gmcrypto-envelope-lite` pins the exact core version; at first publication its core requirement changes to a caret requirement. Every downstream core-version change requires the full downstream test and boundary suite before it lands.

The ecosystem MSRV equals the published `rust-version` of `gmcrypto-core`, currently Rust 1.85. An official crate must not require a newer toolchain without a charter update, and every MSRV increase must be recorded in the affected changelogs.

**Verification:** inspect the core workspace version and exact member requirements, inspect each official downstream `Cargo.toml`, and run its MSRV CI job. Lockstep release behavior and the publication-time caret transition are policy-only release checks.

## 5. Public and private boundary

Partner-specific mappings, identities, fixtures, denylist entries, and exact-wire compatibility suites belong only in access-controlled private repositories or systems. Untracked files in a public checkout are not a secrecy boundary. Before any publication step, the public source export and Cargo package must pass a release-boundary scan. Publishing a previously private tree uses a fresh reviewed export or repository, unless a history rewrite and subsequent fresh-clone history scan receive separate approval.

**Verification in `gmcrypto-envelope-lite`:** run `sh tests/open_source_boundary.sh`, `./ci/check-open-source-boundary.sh --worktree .`, and the package scan performed by `./ci/check-cargo-package.sh`. Approval of a fresh export, repository migration, or history rewrite is a policy-only human gate.

## 6. Per-repository security baseline

Every repository containing an official crate must provide a security policy, RustSec advisory monitoring through `cargo-deny` or an equivalent CI gate, and fuzz coverage wherever it parses untrusted structured input. One repository-level baseline covers all official crates in a workspace; member crates do not duplicate it. Every official crate must say that no independent audit has occurred until one has, and must not claim audit status, universal constant-time behavior, or protection from a compromised process.

**Verification:** check the repository-level `SECURITY.md`, advisory workflow or deny configuration, parser fuzz targets, and explicit non-claims in living security documentation. Whether new parsing code needs additional fuzz targets is policy-only security review until a coverage contract is added.

## 7. Admission and repository creation

A new official public crate requires a concrete consumer, a named owner, and the complete security baseline from section 6 on its first day. Empty placeholder crates and workspaces are prohibited. A public ecosystem workspace is created only with its first admitted crate that does not belong in an existing repository. A language-binding repository requires a real consumer that `gmcrypto-c` cannot serve. A shared test-vector repository requires demonstrated duplication or drift of the same corpus across at least two official repositories.

A governance or tooling meta-repository is created only after at least three independently released official public repositories exist and duplicated release tooling or policy maintenance is concrete. Supporting repositories such as the unpublished demo do not count toward that threshold.

**Policy-only:** admission, ownership, repository-creation triggers, and the meta-repository threshold are maintainer decisions recorded by updating this charter; no repository is created automatically.

## 8. Compatibility gates

The charter maintains a registry of downstream gates that a core release must respect. Gate #1 is the `gmcrypto-envelope-lite` 0.1.0 RC suite. From a clean envelope checkout, its local gate is:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --doc --locked
sh tests/open_source_boundary.sh
./ci/check-open-source-boundary.sh --worktree .
```

Before every `gmcrypto-core` release, run this gate in a temporary envelope export with the core release candidate injected through a temporary path dependency or Cargo `[patch]` override. If the candidate version no longer satisfies the downstream exact pin, change that pin only in the temporary gate copy. A breaking result requires a documented migration note before the core release ships.

On the downstream side, the same gate runs for every exact core-pin bump while the crate is unpublished. After first publication with a caret requirement, downstream CI must cover both the minimum supported and newest compatible core versions.

**Verification:** preserve the command output and tested core/envelope commits as release evidence. Operation is manual and policy-only in this phase; cross-repository CI is deferred until repeated maintenance justifies it.
````

- [ ] **Step 3: Link the core README to the charter**

Immediately after the existing personal-project notice in `README.md`, add exactly:

```markdown
Official ecosystem membership, layering, versioning, and compatibility gates are defined in the [gmcrypto Rust ecosystem charter](docs/ECOSYSTEM.md).
```

- [ ] **Step 4: Verify structure, wording, and local link validity**

```sh
test -f docs/ECOSYSTEM.md
test "$(rg -c '^## [1-8]\.' docs/ECOSYSTEM.md)" -eq 8
rg -n '^## [1-8]\.|\*\*Verification|\*\*Policy-only' docs/ECOSYSTEM.md
rg -nF '[gmcrypto Rust ecosystem charter](docs/ECOSYSTEM.md)' README.md
test -f "$(sed -n 's/.*](\(docs\/ECOSYSTEM.md\)).*/\1/p' README.md)"
git diff --check
```

Expected: exactly eight numbered sections; every section contains a verification or policy-only statement; the README link resolves to a real local file; `git diff --check` is silent.

- [ ] **Step 5: Review the charter against the approved design**

Cross-check these facts explicitly: core includes TLCP cryptographic building blocks but excludes protocol/session orchestration; the core family remains lockstep with exact internal pins; independently versioned downstream crates do not; the prefix is policy rather than a crates.io namespace; security is repository-level; Java projects and the demo are not official crates; gate #1 runs before every core release; no new repository is created.

Expected: zero contradictions and no unresolved drafting markers.

- [ ] **Step 6: Commit the core charter**

```sh
git add docs/ECOSYSTEM.md README.md
git diff --cached --check
git commit -m "docs: add gmcrypto ecosystem charter"
```

Expected: one documentation-only commit on `codex/gmcrypto-ecosystem-charter`. Do not push it in this phase.

## Task 3: Add a failing contract test for the envelope's final package identity

**Files:**

- Modify: `"$GMCRYPTO_ENVELOPE_RC/tests/release_documents.rs"`

- [ ] **Step 1: Add the package-identity contract test**

Add after `completed_approval_marker`:

```rust
#[test]
fn crate_manifest_uses_final_identity() {
    assert_eq!(env!("CARGO_PKG_NAME"), "gmcrypto-envelope-lite");

    let manifest = repository_file("Cargo.toml");
    assert_markers(
        &manifest,
        &[
            "name = \"gmcrypto-envelope-lite\"",
            "name = \"gmcrypto_envelope_lite\"",
            "publish = false",
        ],
    );
}
```

- [ ] **Step 2: Run the test and observe the intended failure**

```sh
cargo test --test release_documents crate_manifest_uses_final_identity -- --exact
```

Expected: the test fails because the package is still `secure-envelope-lite`. Do not change the assertion to match the old state.

- [ ] **Step 3: Keep the failing test uncommitted while implementing Task 4**

Expected: `git status --short` shows only `tests/release_documents.rs` at this point.

## Task 4: Mechanically rename the Rust package, library target, and code imports

**Files:**

- Modify: `"$GMCRYPTO_ENVELOPE_RC/Cargo.toml"`
- Regenerate: `"$GMCRYPTO_ENVELOPE_RC/Cargo.lock"`
- Modify: `"$GMCRYPTO_ENVELOPE_RC/fuzz/Cargo.toml"`
- Regenerate: `"$GMCRYPTO_ENVELOPE_RC/fuzz/Cargo.lock"`
- Modify Rust references (imports plus the temporary-directory prefix in `tests/key_roles.rs`): `examples/build_request.rs`, `examples/open_response.rs`, `fuzz/fuzz_targets/encoded_envelope.rs`, `fuzz/fuzz_targets/support.rs`, `fuzz/fuzz_targets/transport_parts.rs`, `fuzz/tests/scenarios.rs`, `tests/auth_and_config.rs`, `tests/client_convenience.rs`, `tests/key_roles.rs`, `tests/protocol_adapter.rs`, `tests/public_api.rs`, `tests/redacted_debug.rs`, `tests/secure_client.rs`, `tests/support/mod.rs`, and `tests/transport_types.rs`

- [ ] **Step 1: Record the exact mechanical mapping and current occurrence inventory**

```sh
rg -n 'secure-envelope-lite|secure_envelope_lite' Cargo.toml Cargo.lock examples fuzz tests --glob '*.rs' --glob '*.toml' --glob 'Cargo.lock'
```

Apply only these identity mappings in this task:

| Context | Old | New |
|---|---|---|
| Cargo package | `secure-envelope-lite` | `gmcrypto-envelope-lite` |
| Rust library/import | `secure_envelope_lite` | `gmcrypto_envelope_lite` |
| Fuzz package | `secure-envelope-lite-fuzz` | `gmcrypto-envelope-lite-fuzz` |
| Fuzz dependency key | `secure-envelope-lite` | `gmcrypto-envelope-lite` |
| Key-role test temporary-directory prefix | `secure-envelope-lite-key-roles-` | `gmcrypto-envelope-lite-key-roles-` |

- [ ] **Step 2: Update the root manifest without changing publication or dependency policy**

The relevant manifest entries must become:

```toml
[package]
name = "gmcrypto-envelope-lite"
version = "0.1.0"
publish = false

[lib]
name = "gmcrypto_envelope_lite"
path = "src/lib.rs"

[dependencies]
gmcrypto-core = { version = "=1.9.0", features = ["x509"] }
```

Keep this line unchanged until the hosted repository rename is separately authorized:

```toml
repository = "https://github.com/frankxue831/secure-envelope-lite"
```

Do not change the version, MSRV, features, public API, cryptographic behavior, or `publish = false`.

- [ ] **Step 3: Update the fuzz manifest, every Rust import, and the key-role test prefix**

The fuzz identity must become:

```toml
[package]
name = "gmcrypto-envelope-lite-fuzz"

[dependencies.gmcrypto-envelope-lite]
path = ".."
```

Replace every Rust path beginning with `secure_envelope_lite` by the equivalent `gmcrypto_envelope_lite` path in the inventoried examples, fuzz targets, fuzz scenario tests, and integration tests. In `tests/key_roles.rs`, also rename the temporary-directory prefix `secure-envelope-lite-key-roles-` to `gmcrypto-envelope-lite-key-roles-`. Do not rename public Rust types or functions.

- [ ] **Step 4: Let Cargo regenerate only the local package identities in both lockfiles**

```sh
cargo check --offline
cargo check --manifest-path fuzz/Cargo.toml --offline
git diff -- Cargo.lock fuzz/Cargo.lock
```

Expected: the root package entry becomes `gmcrypto-envelope-lite`; the fuzz root becomes `gmcrypto-envelope-lite-fuzz` and depends on `gmcrypto-envelope-lite`; dependency versions and registry checksums do not change. Stop if Cargo resolves unrelated versions.

- [ ] **Step 5: Make the package-identity test pass**

```sh
cargo fmt --all
cargo test --test release_documents crate_manifest_uses_final_identity -- --exact
cargo test --test public_api --locked
cargo test --manifest-path fuzz/Cargo.toml --test scenarios --locked
```

Expected: all commands pass.

- [ ] **Step 6: Verify this commit contains only the code-facing rename and the new contract test**

```sh
git diff --check
git diff --stat
git diff -- Cargo.toml Cargo.lock fuzz/Cargo.toml fuzz/Cargo.lock examples fuzz tests
```

Expected: no behavior change, no new dependency, and no failing committed test. `tests/release_documents.rs` contains the passing package-identity contract.

- [ ] **Step 7: Commit the mechanical Rust rename**

```sh
git add Cargo.toml Cargo.lock fuzz/Cargo.toml fuzz/Cargo.lock examples fuzz tests
git diff --cached --check
git commit -m "refactor: rename crate to gmcrypto-envelope-lite"
```

## Task 5: Rename RC tooling, workflow artifacts, and the public API baseline

**Files:**

- Move: `api/secure-envelope-lite-0.1.0.txt` → `api/gmcrypto-envelope-lite-0.1.0.txt`
- Modify: `ci/check-cargo-package.sh`
- Modify: `ci/check-public-api.sh`
- Modify: `ci/check-release-candidate.sh`
- Modify: `tests/public_api.sh`
- Modify: `tests/release_candidate.sh`
- Modify: `tests/workflows.sh`
- Modify: `.github/workflows/release-candidate.yml`
- Modify: `docs/api-stability.md`
- Modify: `tests/release_documents.rs`

- [ ] **Step 1: Rename the snapshot and its library paths**

Use `apply_patch` to move the snapshot to `api/gmcrypto-envelope-lite-0.1.0.txt` and mechanically replace `secure_envelope_lite` with `gmcrypto_envelope_lite` inside it. Update the baseline marker in `tests/release_documents.rs` to:

```rust
"api/gmcrypto-envelope-lite-0.1.0.txt",
```

Expected: no public item is added, removed, or otherwise renamed beyond the crate path.

- [ ] **Step 2: Rename the public-API checker contract and its fail-closed fixtures**

In `ci/check-public-api.sh`, set:

```sh
snapshot="$repo_root/api/gmcrypto-envelope-lite-0.1.0.txt"
```

In `tests/public_api.sh`, update every copied, removed, restored, and compared snapshot path to `api/gmcrypto-envelope-lite-0.1.0.txt`. Retain all negative cases for missing snapshots, generator failure, version mismatch, toolchain mismatch, and dirty temporary state.

- [ ] **Step 3: Rename package and release-artifact expectations**

Update `ci/check-cargo-package.sh` so its exact package-name assertion is:

```sh
test "$package_name" = gmcrypto-envelope-lite || fail "unexpected Cargo package name"
```

Update old full package names in `ci/check-release-candidate.sh` and `tests/release_candidate.sh`, including fixture manifests, expected `.crate` names, source-directory names, archive names, manifest fields, and output assertions. Preserve all validation, reservation, clean-tree, checksum, and fail-closed behavior.

- [ ] **Step 4: Rename the release workflow output and artifact contract**

In `.github/workflows/release-candidate.yml`, use:

```yaml
      - name: Build release-candidate artifacts
        run: ./ci/check-release-candidate.sh "$GITHUB_SHA" "$RUNNER_TEMP/gmcrypto-envelope-lite-rc"
      - name: Upload release-candidate artifacts
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
        with:
          name: gmcrypto-envelope-lite-0.1.0-rc-built-${{ github.sha }}
          path: ${{ runner.temp }}/gmcrypto-envelope-lite-rc/
          if-no-files-found: error
          retention-days: 14
```

Update the three exact-string assertions in `tests/workflows.sh` to match those values. Do not change triggers, permissions, pinned actions, tool versions, or retention.

- [ ] **Step 5: Update the API stability document**

Change its baseline sentence to:

```markdown
The canonical 0.1.0 snapshot is `api/gmcrypto-envelope-lite-0.1.0.txt`, generated by the pinned `cargo-public-api` version in `ci/tool-versions.sh` with simplified level two and color disabled.
```

Keep all existing open/closed-boundary policy intact.

- [ ] **Step 6: Prove the API baseline is generated by the pinned tool**

```sh
sh tests/public_api.sh
./ci/check-public-api.sh
```

Expected: both pass with cargo-public-api 0.52.0 on nightly-2026-05-23. If the checker reports more than the crate-path rename, stop and review the unexpected public API change instead of accepting a new baseline.

- [ ] **Step 7: Run the package, release, and workflow contract suites**

```sh
sh tests/release_candidate.sh
sh tests/workflows.sh
GMCRYPTO_PACKAGE_PARENT=$(mktemp -d /tmp/gmcrypto-envelope-package-check.XXXXXX)
./ci/check-cargo-package.sh "$PWD" "$GMCRYPTO_PACKAGE_PARENT/package"
```

Expected: all contract and negative-path tests pass; the package helper creates exactly `gmcrypto-envelope-lite-0.1.0.crate` under the explicit temporary output directory.

- [ ] **Step 8: Commit the RC tooling rename**

```sh
git add .github/workflows/release-candidate.yml api ci tests docs/api-stability.md
git diff --cached --check
git commit -m "ci: align release tooling with gmcrypto envelope name"
```

## Task 6: Update living documentation and add ecosystem/hosted-rename gates

**Files:**

- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `CONTRIBUTING.md`
- Modify: `SECURITY.md`
- Modify: `SECURITY_MODEL.md`
- Modify: `RELEASE_CHECKLIST.md`
- Verify: `Cargo.toml`
- Modify: `tests/release_documents.rs`

- [ ] **Step 1: Add the failing ecosystem-position and hosted-rename gate contract**

Add after `crate_manifest_uses_final_identity` in `tests/release_documents.rs`:

```rust
#[test]
fn ecosystem_position_and_remote_rename_gate_are_documented() {
    let readme = repository_file("README.md");
    assert_markers(
        &readme,
        &[
            "# gmcrypto-envelope-lite",
            "## Position in the ecosystem",
            "[gmcrypto Rust ecosystem charter](https://github.com/frankxue831/gm-crypto-rs/blob/main/docs/ECOSYSTEM.md)",
        ],
    );

    let checklist = repository_file("RELEASE_CHECKLIST.md");
    assert_markers(
        &checklist,
        &[
            "Hosted GitHub repository is named `gmcrypto-envelope-lite`",
            "Cargo `repository` metadata resolves to the authorized hosted repository before publication",
        ],
    );
}
```

Run:

```sh
cargo test --test release_documents ecosystem_position_and_remote_rename_gate_are_documented -- --exact
```

Expected: it fails because the final title, ecosystem section, and hosted-rename checklist gates do not exist.

- [ ] **Step 2: Rename the crate in all living prose and examples**

Apply these living-document changes:

- `README.md`: title and crate name become `gmcrypto-envelope-lite`; all Rust imports and doctest paths become `gmcrypto_envelope_lite`.
- `SECURITY.md` and `SECURITY_MODEL.md`: the named crate becomes `gmcrypto-envelope-lite` without weakening any claim, non-claim, or reporting instruction.
- `CONTRIBUTING.md`: the release-candidate output example ends in `gmcrypto-envelope-lite-rc`.
- `CHANGELOG.md`: add a `### Changed` section under `[Unreleased]` containing `- Renamed the unpublished crate and Rust library target from \`secure-envelope-lite\` / \`secure_envelope_lite\` to \`gmcrypto-envelope-lite\` / \`gmcrypto_envelope_lite\` before recording the 0.1.0 RC baseline.` Keep the historical initial-import entry unchanged as the rename record's context.

- [ ] **Step 3: Add the README's ecosystem position**

Immediately after the opening paragraphs and the existing Security Model link, add:

```markdown
## Position in the ecosystem

`gmcrypto-envelope-lite` is the independently versioned public protocol layer above `gmcrypto-core`; it consumes core cryptography without exposing core types in its public API. Partner-specific wire mappings, identities, and exact-wire fixtures remain in private downstream adapters.

Official membership, layering, versioning, admission rules, and compatibility gates are defined by the [gmcrypto Rust ecosystem charter](https://github.com/frankxue831/gm-crypto-rs/blob/main/docs/ECOSYSTEM.md). This crate's 0.1.0 RC suite is compatibility gate #1 for candidate `gmcrypto-core` releases.
```

- [ ] **Step 4: Add two blank hosted-repository gates to the RC checklist**

In `RELEASE_CHECKLIST.md`, immediately before the existing authorized-release-owner confirmation, add:

```markdown
- [ ] Hosted GitHub repository is named `gmcrypto-envelope-lite`; record the final repository URL.
- [ ] Cargo `repository` metadata resolves to the authorized hosted repository before publication.
```

These remain unchecked. They document work that is explicitly outside this phase and prevent publication while the old URL remains in `Cargo.toml`.

- [ ] **Step 5: Make the ecosystem documentation contract pass**

```sh
cargo test --test release_documents ecosystem_position_and_remote_rename_gate_are_documented -- --exact
cargo test --test release_documents --locked
cargo test --doc --locked
```

Expected: all pass, including README doctests with the new library path. The checklist test still proves no approval marker is completed.

- [ ] **Step 6: Prove only the explicitly allowed old-name records remain**

```sh
! rg -n 'secure-envelope-lite|secure_envelope_lite' --glob '!docs/superpowers/**' --glob '!CHANGELOG.md' --glob '!Cargo.toml' .
rg -n 'secure-envelope-lite|secure_envelope_lite' CHANGELOG.md
rg -nF 'repository = "https://github.com/frankxue831/secure-envelope-lite"' Cargo.toml
test "$(rg -c 'secure-envelope-lite|secure_envelope_lite' Cargo.toml)" -eq 1
```

Expected: the first command has no output and exits 0 because the negated search found no unexpected live references; the CHANGELOG contains only historical/rename context; the only old-name occurrence in `Cargo.toml` is the temporarily stale hosted URL. `docs/superpowers/**` remains untouched as historical design evidence.

- [ ] **Step 7: Cross-read for policy consistency**

Compare `README.md`, `SECURITY_MODEL.md`, `RELEASE_CHECKLIST.md`, `docs/api-stability.md`, and the core `docs/ECOSYSTEM.md`. Confirm all of the following:

- the envelope crate remains synchronous and HTTP-neutral;
- new protocols are still directed to reviewed AEAD rather than the legacy envelope construction;
- private partner mappings remain downstream;
- the core types are not re-exported;
- `publish = false` and the exact core pin remain unchanged;
- the current repository URL is described only as a blocked pre-publication follow-up;
- no document implies that `rc-built` means approval or publication authorization.

- [ ] **Step 8: Commit living documentation**

```sh
git add README.md CHANGELOG.md CONTRIBUTING.md SECURITY.md SECURITY_MODEL.md RELEASE_CHECKLIST.md tests/release_documents.rs
git diff --cached --check
git commit -m "docs: position envelope in gmcrypto ecosystem"
```

## Task 7: Run the full renamed RC suite and compatibility gate #1

**Files:**

- Verify only: all tracked files in the envelope RC worktree
- Read only: `"$GMCRYPTO_CORE_WORKTREE/crates/gmcrypto-core"`
- Temporary export: a new directory under `/tmp/gmcrypto-envelope-gate.*`
- Temporary RC artifacts: a new directory under `/tmp/gmcrypto-envelope-rc.*`

- [ ] **Step 1: Verify the branch is clean and the identity invariants hold**

```sh
git status --short
test "$(cargo metadata --no-deps --format-version 1 | tr -d '\n' | rg -o '"name":"gmcrypto-envelope-lite"' | wc -l | tr -d ' ')" -eq 1
rg -nF 'gmcrypto-core = { version = "=1.9.0", features = ["x509"] }' Cargo.toml
! grep -RIn "pub use gmcrypto" src/
```

Expected: the worktree is clean; exactly one package has the final name; the exact core pin is unchanged; the negated grep has no output and exits 0.

- [ ] **Step 2: Run formatting, linting, test, documentation, advisory, API, inventory, fuzz, and boundary gates**

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --doc --locked
RUSTDOCFLAGS="-D missing-docs -D warnings" cargo doc --locked --no-deps
cargo +1.85.0 test --all-targets --locked
cargo deny check
sh tests/workflows.sh
sh tests/public_api.sh
./ci/check-public-api.sh
sh tests/crypto_inventory.sh
./ci/check-crypto-inventory.sh
sh tests/fuzz_smoke.sh
sh ci/fuzz-smoke.sh smoke
sh tests/release_candidate.sh
sh tests/open_source_boundary.sh
./ci/check-open-source-boundary.sh --worktree .
```

Expected: every command exits 0. The test count may exceed the design-time count of 112 because Tasks 3 and 6 add two tests; record the actual final count instead of hard-coding it.

- [ ] **Step 3: Construct the immutable local `rc-built` artifact set**

```sh
GMCRYPTO_RC_PARENT=$(mktemp -d /tmp/gmcrypto-envelope-rc.XXXXXX)
./ci/check-release-candidate.sh "$(git rev-parse HEAD)" "$GMCRYPTO_RC_PARENT/artifacts"
find "$GMCRYPTO_RC_PARENT/artifacts" -maxdepth 1 -type f -print | sort
```

Expected: the full command passes from a clean tree and produces the renamed source archive, Cargo package, manifest, and checksums. This proves only `rc-built`; it does not satisfy any external gate in `RELEASE_CHECKLIST.md`.

- [ ] **Step 4: Create a clean temporary envelope export and run compatibility gate #1 in the same shell**

```sh
GMCRYPTO_GATE_PARENT=$(mktemp -d /tmp/gmcrypto-envelope-gate.XXXXXX)
GMCRYPTO_CORE_PATCH_CONFIG="patch.crates-io.gmcrypto-core.path=\"$GMCRYPTO_CORE_WORKTREE/crates/gmcrypto-core\""
mkdir "$GMCRYPTO_GATE_PARENT/source"
git archive --format=tar HEAD | tar -xf - -C "$GMCRYPTO_GATE_PARENT/source"
test -f "$GMCRYPTO_GATE_PARENT/source/Cargo.toml"
test ! -e "$GMCRYPTO_GATE_PARENT/source/.git"
test -f "$GMCRYPTO_CORE_WORKTREE/crates/gmcrypto-core/Cargo.toml"
rg -n '^version = "1.9.0"|version.workspace = true' "$GMCRYPTO_CORE_WORKTREE/Cargo.toml" "$GMCRYPTO_CORE_WORKTREE/crates/gmcrypto-core/Cargo.toml"
cargo test --manifest-path "$GMCRYPTO_GATE_PARENT/source/Cargo.toml" --offline --locked --test release_documents
"$GMCRYPTO_GATE_PARENT/source/ci/check-crypto-inventory.sh"
cargo fmt --manifest-path "$GMCRYPTO_GATE_PARENT/source/Cargo.toml" --all -- --check
cargo --config "$GMCRYPTO_CORE_PATCH_CONFIG" clippy --manifest-path "$GMCRYPTO_GATE_PARENT/source/Cargo.toml" --offline --all-targets -- -D warnings
cargo --config "$GMCRYPTO_CORE_PATCH_CONFIG" test --manifest-path "$GMCRYPTO_GATE_PARENT/source/Cargo.toml" --offline --lib
cargo --config "$GMCRYPTO_CORE_PATCH_CONFIG" test --manifest-path "$GMCRYPTO_GATE_PARENT/source/Cargo.toml" --offline --examples

test -f "$GMCRYPTO_GATE_PARENT/source/tests/release_documents.rs"
GMCRYPTO_BEHAVIORAL_INTEGRATION_COUNT=0
GMCRYPTO_EXCLUDED_METADATA_COUNT=0
for GMCRYPTO_INTEGRATION_FILE in "$GMCRYPTO_GATE_PARENT/source/tests/"*.rs
do
    test -f "$GMCRYPTO_INTEGRATION_FILE" || continue
    GMCRYPTO_INTEGRATION_TARGET=${GMCRYPTO_INTEGRATION_FILE##*/}
    GMCRYPTO_INTEGRATION_TARGET=${GMCRYPTO_INTEGRATION_TARGET%.rs}
    if test "$GMCRYPTO_INTEGRATION_TARGET" = release_documents; then
        GMCRYPTO_EXCLUDED_METADATA_COUNT=$((GMCRYPTO_EXCLUDED_METADATA_COUNT + 1))
        continue
    fi
    GMCRYPTO_BEHAVIORAL_INTEGRATION_COUNT=$((GMCRYPTO_BEHAVIORAL_INTEGRATION_COUNT + 1))
    cargo --config "$GMCRYPTO_CORE_PATCH_CONFIG" test \
        --manifest-path "$GMCRYPTO_GATE_PARENT/source/Cargo.toml" \
        --offline --test "$GMCRYPTO_INTEGRATION_TARGET"
done
test "$GMCRYPTO_EXCLUDED_METADATA_COUNT" -eq 1
test "$GMCRYPTO_BEHAVIORAL_INTEGRATION_COUNT" -ge 1
printf 'behavioral integration targets: %s; excluded metadata targets: %s\n' \
    "$GMCRYPTO_BEHAVIORAL_INTEGRATION_COUNT" "$GMCRYPTO_EXCLUDED_METADATA_COUNT"

cargo --config "$GMCRYPTO_CORE_PATCH_CONFIG" test --manifest-path "$GMCRYPTO_GATE_PARENT/source/Cargo.toml" --offline --doc
sh "$GMCRYPTO_GATE_PARENT/source/tests/open_source_boundary.sh"
"$GMCRYPTO_GATE_PARENT/source/ci/check-open-source-boundary.sh" --worktree "$GMCRYPTO_GATE_PARENT/source"
printf 'envelope gate commit: %s\n' "$(git rev-parse HEAD)"
printf 'core gate commit: %s\n' "$(git -C "$GMCRYPTO_CORE_WORKTREE" rev-parse HEAD)"
```

Expected: both phases pass, and the output records the exact core and envelope commit IDs. Before applying the local core patch, the strict `release_documents` test and cryptographic inventory checker validate repository metadata against the pristine committed registry lock. After that phase, the disposable unlocked lock supports the local-core behavioral gate: formatting, linting, library tests, examples, every dynamically discovered behavioral integration target, documentation tests, and both boundary checks all pass. The guards prove that `release_documents.rs` exists, exactly one metadata target is excluded after patching, and at least one behavioral integration target ran.

`release_documents` is not a behavioral compatibility test. It remains strict and already ran against the pristine registry lock; it is the sole deliberate exclusion after patching because Cargo path packages have no registry checksum. Every behavioral integration target remains included, while the committed downstream lockfile and metadata test stay unchanged. If a future candidate has another version, update the pin only inside the temporary export before running the gate; do not modify the reviewed envelope branch merely to test a candidate. Omit `--locked` only from the patched phase because applying the local `[patch]` legitimately rewrites the disposable lockfile. Do not substitute Cargo's `paths` override for this patch.

- [ ] **Step 5: Confirm verification did not modify either reviewed worktree**

```sh
git status --short
git -C "$GMCRYPTO_CORE_WORKTREE" status --short
```

Expected: both outputs are empty. Do not claim completion if either verification tree is dirty.

## Task 8: Prepare a read-only handoff for the existing private remote

**Files:**

- Read only: `"$GMCRYPTO_ENVELOPE_RC"`
- Read only: `"$GMCRYPTO_TARGET_CLONE"`
- Temporary export: a new directory under `/tmp/gmcrypto-envelope-transfer.*`

- [ ] **Step 1: Reconfirm repository identities and divergent histories**

```sh
git -C "$GMCRYPTO_ENVELOPE_SOURCE" remote -v
git -C "$GMCRYPTO_TARGET_CLONE" remote -v
git -C "$GMCRYPTO_ENVELOPE_RC" log --oneline --decorate --max-count=12
git -C "$GMCRYPTO_TARGET_CLONE" log --oneline --decorate --max-count=12
```

Expected: the development source still has no remote; the target clone still points to the existing private `secure-envelope-lite` GitHub repository; histories remain distinct. No command in this step mutates either repository.

- [ ] **Step 2: Compare a clean reviewed export with the target clone**

```sh
GMCRYPTO_TRANSFER_PARENT=$(mktemp -d /tmp/gmcrypto-envelope-transfer.XXXXXX)
mkdir "$GMCRYPTO_TRANSFER_PARENT/reviewed" "$GMCRYPTO_TRANSFER_PARENT/target"
git -C "$GMCRYPTO_ENVELOPE_RC" archive --format=tar HEAD | tar -xf - -C "$GMCRYPTO_TRANSFER_PARENT/reviewed"
git -C "$GMCRYPTO_TARGET_CLONE" archive --format=tar HEAD | tar -xf - -C "$GMCRYPTO_TRANSFER_PARENT/target"
git diff --no-index --stat "$GMCRYPTO_TRANSFER_PARENT/target" "$GMCRYPTO_TRANSFER_PARENT/reviewed" || test "$?" -eq 1
```

Expected: `git diff --no-index` exits 1 because the reviewed RC export contains intentional changes absent from the three-commit target clone. Review the stat; do not copy files, merge unrelated histories, reset the target, or push.

- [ ] **Step 3: Report the separately authorized follow-up choices**

The handoff report must state:

1. The existing private GitHub repository is the rename target; no new repository is needed.
2. The reviewed implementation exists as commits on the local RC branch.
3. The local development and hosted-target histories differ, so transfer needs an explicit choice: a reviewed patch/clean export applied onto the target history, or a separately approved history migration.
4. Hosted repository rename, Cargo `repository` URL update, push, tag, publication, and any history replacement remain unperformed.
5. Force-push is not authorized by this plan.

- [ ] **Step 4: Final plan acceptance check**

Before handing implementation back, verify:

```sh
git -C "$GMCRYPTO_CORE_WORKTREE" log -1 --oneline
git -C "$GMCRYPTO_ENVELOPE_RC" log --first-parent --oneline 93e3aafebf2c4bb0f5f52286e1b4be439ac7b4d1..HEAD
git -C "$GMCRYPTO_CORE_WORKTREE" status --short
git -C "$GMCRYPTO_ENVELOPE_RC" status --short
```

Expected: the core branch ends in `docs: add gmcrypto ecosystem charter`; the envelope branch includes the merge plus the three scoped rename commits; both worktrees are clean; all Task 7 evidence is recorded in the execution report.

## Completion criteria

- `gm-crypto-rs/docs/ECOSYSTEM.md` contains the approved eight-section normative charter and the core README links to it.
- The envelope package/library/tooling identity is consistently `gmcrypto-envelope-lite` / `gmcrypto_envelope_lite`.
- `publish = false`, version 0.1.0, Rust 1.85, exact `gmcrypto-core = "=1.9.0"`, runtime behavior, and public types remain unchanged.
- All renamed RC checks pass, including the pinned public API baseline and a clean `rc-built` artifact construction.
- Compatibility gate #1 passes against the local core checkout through a disposable patch override.
- Old identity strings remain only in historical `docs/superpowers/**`, the CHANGELOG rename/history context, and the temporarily stale Cargo repository URL protected by two unchecked pre-publication gates.
- No new repository, remote rename, push, tag, publication, force-push, or history rewrite occurs.
