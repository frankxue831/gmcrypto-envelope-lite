# 0.3.0 Release Candidate External Gate Checklist

**Template version:** 2

Only this blank template is committed. A completed copy lives in the release owner's records outside the repository, and is not committed unless a separate disclosure review approves a sanitized public record.

This template records the solo-owner release process this project actually runs. The repository's in-tree gates are unchanged; the gates below are the external layer.

## Promotion states

- `candidate-source`: a named commit selected for repository checks.
- `rc-built`: repository-owned gates passed for the exact candidate commit, and the complete immutable artifact set was produced and checksummed. External recording is not a prerequisite for this local state; external gates are **not evaluated in-tree**.
- `rc-approved`: the unchanged complete `rc-built` artifact set passed every required external gate below, recorded by the release owner.
- `release-authorized`: the release owner approved a separately considered publication action for the unchanged complete `rc-approved` artifact set.

The repository command can produce only `rc-built`. It cannot infer or record either later state.

Recording artifact identity externally is a handoff and evidence action after `rc-built`; it is not a predicate for the local state.

## Artifact identity recorded externally

- Candidate commit: record the exact commit from `rc-manifest.json`.
- RC manifest: record `rc-manifest.json` filename, byte length, SHA-256, and manifest schema version.
- Source export: record filename, byte length, and SHA-256.
- Cargo package: record filename, byte length, and SHA-256.
- Root Cargo.lock: record SHA-256.
- SHA256SUMS: record filename, byte length, and SHA-256 externally to avoid self-hash circularity; verify its entries match every other RC artifact.
- Evidence schemas: record security-model, API snapshot, engineering-evidence, dependency-inventory, and checklist versions.
- Toolchain: record the versions from `rc-manifest.json`.

Every later approval must identify the unchanged complete artifact set above.

## Required fields for every external gate evidence record

The release owner's record keeps the actual values for every gate. The committed template remains blank and contains no completed evidence record.

- Gate ID.
- Exact candidate commit.
- `rc-manifest.json` SHA-256.
- Source export SHA-256.
- Cargo package SHA-256.
- Result.
- Evidence ID, run URL, or reference.
- Reviewer or automated system.
- Completion UTC.
- Expiry UTC (or explicit non-expiring policy).
- Disposition or notes reference.

## Required external gates

Each following gate must identify the unchanged complete artifact set and include every required evidence record field above.

- [ ] Linux CI passed for the exact candidate commit; record the run ID and actual `rustc --version`.
- [ ] macOS CI passed for the exact candidate commit; record the run ID and actual `rustc --version`.
- [ ] Windows CI passed for the exact candidate commit; record the run ID and actual `rustc --version`.
- [ ] Rust 1.85 MSRV CI passed for the exact candidate commit; record the run ID and actual `rustc --version`.
- [ ] Self security review completed against the prepared review packet, with residual rulings and a signed disposition recorded.
- [ ] License and dependency hygiene: the committed license files match the manifest license expression, and a fresh `cargo deny check` ran green at the candidate commit on the review date.
- [ ] Repository history scanned for secrets, and the publication method — public history or fresh reviewed export — decided and recorded before the repository becomes public.
- [ ] Hosted GitHub repository is named `gmcrypto-envelope-lite`; record the final repository URL.
- [ ] Cargo `repository` metadata resolves to the authorized hosted repository before publication.
- [ ] Authorized release owner confirmed that the reviewed commit and checksums are unchanged.

## Decision rules

- Missing evidence is `pending`, never `passed`.
- A rejected or expired gate blocks promotion.
- Any source, dependency, metadata, documentation, package, evidence-version, or checksum change returns the candidate to `candidate-source`.
- No checklist entry authorizes a tag, push, crates.io publication, or production deployment by itself.
