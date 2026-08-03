# 0.2.0 Release Candidate External Gate Checklist

**Template version:** 1

Only this blank template is committed. A completed copy remains in the authorized external approval system unless a separate disclosure review approves a fully sanitized public record.

## Promotion states

- `candidate-source`: a named commit selected for repository checks.
- `rc-built`: repository-owned gates passed for the exact candidate commit, and the complete immutable artifact set was produced and checksummed. External recording is not a prerequisite for this local state; external gates are **not evaluated in-tree**.
- `rc-approved`: the unchanged complete `rc-built` artifact set passed every required private and human gate in authorized external systems.
- `release-authorized`: an authorized release owner approved a separately requested publication action for the unchanged complete `rc-approved` artifact set.

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

The authorized external approval system records the actual values for every gate. The committed template remains blank and contains no completed evidence record.

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
- [ ] Private policy scan passed against the identified source export and unpacked package.
- [ ] Exact-wire compatibility passed for outbound names, values, casing, body placement, and signatures.
- [ ] Exact-wire compatibility passed for approved inbound responses and failure behavior.
- [ ] Replacement-client rotation preserved the deployed wire contract.
- [ ] Independent security review completed with disposition recorded externally.
- [ ] Legal and open-source approval completed.
- [ ] Hosted GitHub repository is named `gmcrypto-envelope-lite`; record the final repository URL.
- [ ] Cargo `repository` metadata resolves to the authorized hosted repository before publication.
- [ ] Authorized release owner confirmed that the reviewed commit and checksums are unchanged.

## Decision rules

- Missing evidence is `pending`, never `passed`.
- A rejected or expired gate blocks promotion.
- Any source, dependency, metadata, documentation, package, evidence-version, or checksum change returns the candidate to `candidate-source`.
- No checklist entry authorizes a tag, push, crates.io publication, or production deployment by itself.
