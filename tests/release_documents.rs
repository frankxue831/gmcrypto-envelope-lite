#![forbid(unsafe_code)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_EXTERNAL_GATES_HEADING: &str = "## Required external gates";
const HOSTED_REPOSITORY_NAME_GATE: &str = "- [ ] Hosted GitHub repository is named `gmcrypto-envelope-lite`; record the final repository URL.";
const CARGO_REPOSITORY_METADATA_GATE: &str = "- [ ] Cargo `repository` metadata resolves to the authorized hosted repository before publication.";
const RELEASE_OWNER_AUTHORIZATION_GATE: &str = "- [ ] Authorized release owner confirmed that the reviewed commit and checksums are unchanged.";

fn read_normalized(full_path: &Path) -> String {
    fs::read_to_string(full_path)
        .unwrap_or_else(|error| panic!("unable to read {}: {error}", full_path.display()))
        .replace("\r\n", "\n")
}

fn repository_file(path: &str) -> String {
    read_normalized(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path))
}

fn assert_markers(document: &str, markers: &[&str]) {
    for marker in markers {
        assert!(
            document.contains(marker),
            "missing document marker: {marker}"
        );
    }
}

fn required_hosting_gates_are_ordered(document: &str) -> bool {
    let mut document_lines = document.lines();
    let Some(_) = document_lines.find(|line| *line == REQUIRED_EXTERNAL_GATES_HEADING) else {
        return false;
    };
    let section_lines: Vec<_> = document_lines
        .take_while(|line| !line.starts_with("## "))
        .collect();

    let unique_position = |expected: &str| {
        let mut matches = section_lines
            .iter()
            .enumerate()
            .filter(|(_, line)| **line == expected)
            .map(|(position, _)| position);
        let position = matches.next()?;
        matches.next().is_none().then_some(position)
    };

    let Some(hosted_position) = unique_position(HOSTED_REPOSITORY_NAME_GATE) else {
        return false;
    };
    let Some(metadata_position) = unique_position(CARGO_REPOSITORY_METADATA_GATE) else {
        return false;
    };
    let Some(owner_position) = unique_position(RELEASE_OWNER_AUTHORIZATION_GATE) else {
        return false;
    };

    hosted_position < metadata_position && metadata_position < owner_position
}

fn archive_source_files(repository_root: &Path) -> io::Result<Vec<PathBuf>> {
    fn visit(repository_root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
        let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());

        for entry in entries {
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "archive source contains a symlink: {}",
                        entry.path().display()
                    ),
                ));
            }
            if file_type.is_dir() {
                let name = entry.file_name();
                let is_generated_root_directory = directory == repository_root
                    && (name == ".git" || name == ".worktrees" || name == "target");
                if is_generated_root_directory {
                    continue;
                }
                visit(repository_root, &entry.path(), files)?;
            } else if file_type.is_file() {
                files.push(
                    entry
                        .path()
                        .strip_prefix(repository_root)
                        .expect("visited source files must remain under the repository root")
                        .to_path_buf(),
                );
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "archive source contains a non-regular entry: {}",
                        entry.path().display()
                    ),
                ));
            }
        }

        Ok(())
    }

    let mut files = Vec::new();
    visit(repository_root, repository_root, &mut files)?;
    files.sort();
    Ok(files)
}

fn repository_source_files(repository_root: &Path) -> Vec<PathBuf> {
    let git_output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(repository_root)
        .output();

    if let Ok(output) = git_output {
        if output.status.success() {
            return output
                .stdout
                .split(|byte| *byte == 0)
                .filter(|path| !path.is_empty())
                .map(|path| {
                    PathBuf::from(
                        std::str::from_utf8(path)
                            .expect("tracked repository paths must be valid UTF-8"),
                    )
                })
                .collect();
        }
    }

    archive_source_files(repository_root)
        .unwrap_or_else(|error| panic!("unable to enumerate archive source files: {error}"))
}

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "gmcrypto-envelope-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("unable to create temporary test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn completed_approval_marker(document: &str) -> Option<&'static str> {
    let lowercase = document.to_ascii_lowercase();
    [
        "[x]",
        "status: passed",
        "status: approved",
        "status: complete",
        "status: authorized",
        "decision: passed",
        "decision: approved",
        "decision: complete",
        "decision: authorized",
        "result: passed",
        "result: approved",
        "result: complete",
        "result: authorized",
    ]
    .into_iter()
    .find(|marker| lowercase.contains(marker))
}

#[test]
fn repository_reads_normalize_windows_line_endings() {
    let directory = TemporaryDirectory::new("line-endings");

    // Every marker in this file is authored with LF. A Windows checkout with
    // autocrlf conversion hands the same bytes back as CRLF, so without this
    // normalization each multi-line assertion below fails on Windows alone.
    let windows_checkout = directory.path().join("manifest.toml");
    fs::write(
        &windows_checkout,
        "name = \"gmcrypto-core\"\r\nversion = \"1.11.0\"\r\n",
    )
    .expect("unable to write the CRLF fixture");
    let normalized = read_normalized(&windows_checkout);
    assert_eq!(
        normalized,
        "name = \"gmcrypto-core\"\nversion = \"1.11.0\"\n"
    );
    assert_markers(
        &normalized,
        &["name = \"gmcrypto-core\"\nversion = \"1.11.0\""],
    );

    // Pairs only. Stripping every carriage return would silently rewrite file
    // content that legitimately contains one.
    let lone_carriage_return = directory.path().join("lone-cr.txt");
    fs::write(&lone_carriage_return, "before\rafter").expect("unable to write the lone-CR fixture");
    assert_eq!(read_normalized(&lone_carriage_return), "before\rafter");
}

#[test]
fn crate_manifest_uses_final_identity() {
    assert_eq!(env!("CARGO_PKG_NAME"), "gmcrypto-envelope-lite");

    let manifest = repository_file("Cargo.toml");
    assert_markers(
        &manifest,
        &[
            "name = \"gmcrypto-envelope-lite\"",
            "name = \"gmcrypto_envelope_lite\"",
        ],
    );
    assert!(
        !manifest.contains("publish = false"),
        "publication remains enabled; publish = false must stay removed"
    );
}

#[test]
fn ecosystem_position_and_remote_rename_gate_are_documented() {
    let readme = repository_file("README.md");
    assert_markers(
        &readme,
        &[
            "# gmcrypto-envelope-lite",
            "## Position in the ecosystem",
            "`gmcrypto-envelope-lite` is the independently versioned public protocol layer above `gmcrypto-core`",
            "without exposing core types in its public API",
            "Partner-specific wire mappings, identities, and exact-wire fixtures remain in private downstream adapters.",
            "[gmcrypto Rust ecosystem charter](https://github.com/frankxue831/gm-crypto-rs/blob/main/docs/ECOSYSTEM.md)",
            "This crate's gate suite is compatibility gate #1 for candidate `gmcrypto-core` releases",
            "`ci/check-compatibility-gate.sh` runs it against a candidate core in every feature configuration this crate ships",
        ],
    );

    let checklist = repository_file("RELEASE_CHECKLIST.md");
    assert!(
        required_hosting_gates_are_ordered(&checklist),
        "hosted rename gates must be exact, unchecked, and ordered before release-owner authorization"
    );
}

#[test]
fn hosted_rename_gate_contract_rejects_mutations() {
    let valid = format!(
        "{REQUIRED_EXTERNAL_GATES_HEADING}\n\n{HOSTED_REPOSITORY_NAME_GATE}\n{CARGO_REPOSITORY_METADATA_GATE}\n{RELEASE_OWNER_AUTHORIZATION_GATE}\n\n## Decision rules\n"
    );
    assert!(required_hosting_gates_are_ordered(&valid));

    let prose_variant = valid.replacen(
        HOSTED_REPOSITORY_NAME_GATE,
        HOSTED_REPOSITORY_NAME_GATE.trim_start_matches("- [ ] "),
        1,
    );
    assert!(
        !required_hosting_gates_are_ordered(&prose_variant),
        "prose must not satisfy an unchecked release gate"
    );

    let checked_variant = valid.replacen(
        CARGO_REPOSITORY_METADATA_GATE,
        &CARGO_REPOSITORY_METADATA_GATE.replacen("- [ ]", "- [x]", 1),
        1,
    );
    assert!(
        !required_hosting_gates_are_ordered(&checked_variant),
        "a checked release gate must be rejected"
    );

    let wrong_section = format!(
        "{REQUIRED_EXTERNAL_GATES_HEADING}\n\n{RELEASE_OWNER_AUTHORIZATION_GATE}\n\n## Notes\n\n{HOSTED_REPOSITORY_NAME_GATE}\n{CARGO_REPOSITORY_METADATA_GATE}\n"
    );
    assert!(
        !required_hosting_gates_are_ordered(&wrong_section),
        "gates outside the required external gates section must be rejected"
    );

    let wrong_order = format!(
        "{REQUIRED_EXTERNAL_GATES_HEADING}\n\n{CARGO_REPOSITORY_METADATA_GATE}\n{HOSTED_REPOSITORY_NAME_GATE}\n{RELEASE_OWNER_AUTHORIZATION_GATE}\n"
    );
    assert!(
        !required_hosting_gates_are_ordered(&wrong_order),
        "hosted rename gates must retain their required order"
    );
}

#[test]
fn tracked_files_contain_only_intended_pre_rename_identity_references() {
    let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let former_package = ["secure", "envelope", "lite"].join("-");
    let former_library = ["secure", "envelope", "lite"].join("_");
    let mut actual = Vec::new();
    let historical_directory = Path::new("docs").join("superpowers");

    for relative_path in repository_source_files(&repository_root) {
        let display_path = relative_path.to_string_lossy();
        let full_path = repository_root.join(&relative_path);
        let file_type = fs::symlink_metadata(&full_path)
            .unwrap_or_else(|error| panic!("unable to inspect {display_path}: {error}"))
            .file_type();
        assert!(
            file_type.is_file(),
            "enumerated source path is not a regular file: {display_path}"
        );
        let bytes = fs::read(&full_path)
            .unwrap_or_else(|error| panic!("unable to read {display_path}: {error}"));
        let contents = String::from_utf8_lossy(&bytes);

        for line in contents.lines() {
            if !line.contains(&former_package) && !line.contains(&former_library) {
                continue;
            }
            if relative_path.starts_with(&historical_directory) {
                continue;
            }
            actual.push((relative_path.clone(), line.to_owned()));
        }
    }

    let mut expected = vec![
        (
            PathBuf::from("CHANGELOG.md"),
            format!(
                "- Renamed the unpublished crate and Rust library target from `{former_package}` / `{former_library}` to `gmcrypto-envelope-lite` / `gmcrypto_envelope_lite` before recording the 0.1.0 RC baseline."
            ),
        ),
        (
            PathBuf::from("CHANGELOG.md"),
            format!(
                "- Initial import of `{former_package}`: a synchronous, HTTP-neutral library for SM2/SM3 signatures and SM4 secure envelopes."
            ),
        ),
    ];
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
}

#[test]
fn archive_source_file_fallback_skips_only_root_generated_and_vcs_directories() {
    let fixture = TemporaryDirectory::new("archive-enumeration");
    let export = fixture.path().join("export");
    fs::create_dir_all(export.join("src")).expect("unable to create source fixture directory");
    fs::create_dir_all(export.join("docs/target"))
        .expect("unable to create nested target fixture directory");
    fs::create_dir_all(export.join("docs/.worktrees"))
        .expect("unable to create nested worktrees fixture directory");
    fs::create_dir_all(export.join("docs/.git"))
        .expect("unable to create nested Git fixture directory");
    fs::create_dir_all(export.join("target/debug"))
        .expect("unable to create generated fixture directory");
    fs::create_dir_all(export.join(".git/objects"))
        .expect("unable to create VCS fixture directory");
    fs::create_dir_all(export.join(".worktrees/generated"))
        .expect("unable to create worktree fixture directory");
    fs::write(export.join("README.md"), "readme").expect("unable to write regular source fixture");
    fs::write(export.join("src/lib.rs"), "library").expect("unable to write nested source fixture");
    fs::write(export.join("docs/target/live.md"), "nested target")
        .expect("unable to write nested target fixture");
    fs::write(export.join("docs/.worktrees/live.md"), "nested worktree")
        .expect("unable to write nested worktree fixture");
    fs::write(export.join("docs/.git/live.md"), "nested Git")
        .expect("unable to write nested Git fixture");
    fs::write(export.join("target/debug/generated"), "generated")
        .expect("unable to write generated fixture");
    fs::write(export.join(".git/objects/internal"), "vcs").expect("unable to write VCS fixture");
    fs::write(export.join(".worktrees/generated/internal"), "worktree")
        .expect("unable to write worktree fixture");

    assert_eq!(
        archive_source_files(&export).expect("archive fallback must enumerate source files"),
        vec![
            PathBuf::from("README.md"),
            PathBuf::from("docs/.git/live.md"),
            PathBuf::from("docs/.worktrees/live.md"),
            PathBuf::from("docs/target/live.md"),
            PathBuf::from("src/lib.rs"),
        ]
    );
}

#[cfg(unix)]
#[test]
fn archive_source_file_fallback_rejects_symlinks() {
    let fixture = TemporaryDirectory::new("archive-symlink");
    let export = fixture.path().join("export");
    fs::create_dir_all(&export).expect("unable to create symlink fixture directory");
    fs::write(fixture.path().join("outside"), "outside")
        .expect("unable to write symlink target fixture");
    std::os::unix::fs::symlink(fixture.path().join("outside"), export.join("outside-link"))
        .expect("unable to create symlink fixture");

    let error = archive_source_files(&export).expect_err("archive fallback must reject symlinks");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn security_model_is_versioned_and_states_claims_and_non_claims() {
    let model = repository_file("SECURITY_MODEL.md");
    assert_markers(
        &model,
        &[
            "**Model version:** 2",
            "## Protected assets and attacker-controlled inputs",
            "## Trust boundaries",
            "## Security claims",
            "## Explicit non-claims",
            "fixed-IV SM4-CBC",
            "LegacyPlaintext",
            "ContextBound",
            "not independently audited",
            "Without the opt-in `aead` feature it provides no AEAD envelope profile",
        ],
    );

    let readme = repository_file("README.md");
    let policy = repository_file("SECURITY.md");
    assert!(readme.contains("[Security model](SECURITY_MODEL.md)"));
    assert!(policy.contains("[Security model](SECURITY_MODEL.md)"));
    assert_markers(
        &policy,
        &[
            "## Supported versions",
            "| 0.2.x | Yes |",
            "| 0.3.x | Yes |",
        ],
    );
    assert!(
        !policy.contains("| 0.3.x | Unreleased (`main`) |"),
        "0.3.x must not remain Unreleased after the freeze"
    );
    assert!(
        readme.contains("current tagged line (`v0.3.0`)"),
        "README release status must name the 0.3.0 tag"
    );
    assert!(
        !readme.contains("Version 0.3.0 is unreleased and in development on `main`."),
        "README must not still describe 0.3.0 as unreleased development"
    );
}

#[test]
fn api_stability_policy_records_open_and_closed_boundaries() {
    let policy = repository_file("docs/api-stability.md");
    assert_markers(
        &policy,
        &[
            "**Policy version:** 2",
            "Within 0.3.x",
            "AuthenticationMode",
            "AdapterErrorKind",
            "KeyKind",
            "PeerKeySource",
            "Error",
            "`AuthenticationMode`, `AdapterErrorKind`, `KeyKind`, `PeerKeySource`, `Error`, and the feature-gated `EnvelopeMode` and `AeadAlgorithm` are `#[non_exhaustive]`.",
            "CipherLocation",
            "`CipherLocation` is exhaustive",
            "ProtocolAdapter",
            "api/gmcrypto-envelope-lite-0.3.0.txt",
            "api/gmcrypto-envelope-lite-0.3.0-aead.txt",
        ],
    );
}

#[test]
fn engineering_evidence_is_versioned_and_disclaims_audit_status() {
    let evidence = repository_file("docs/security/engineering-evidence.md");
    assert_markers(
        &evidence,
        &[
            "**Evidence version:** 2",
            "not an independent audit, certification, warranty, or proof",
            "tests/standard_vectors.rs",
            "directional_roles_drive_two_party_cryptography",
            "context_bound_transcript_is_versioned_and_length_delimited",
            "cbc_padding_and_cipher_tampering_is_an_invalid_envelope",
            "signature_tampering_and_wrong_verification_key_are_indistinguishable",
            "open-source boundary",
            "External",
        ],
    );
}

#[test]
fn cryptographic_dependency_inventory_records_the_reviewed_root_lockfile() {
    let manifest = repository_file("Cargo.toml");
    let lockfile = repository_file("Cargo.lock");
    let inventory = repository_file("docs/security/cryptographic-dependencies.md");

    assert!(manifest.contains("gmcrypto-core = { version = \"1.11\", features = [\"x509\"] }"));
    assert!(lockfile.contains("name = \"gmcrypto-core\"\nversion = \"1.11.0\""));
    assert!(lockfile.contains(
        "checksum = \"4e81a6030cdbef95407ef7924aa2b60469d1263e094b667295cd3d787c2c3095\""
    ));
    assert_markers(
        &inventory,
        &[
            "**Inventory version:** 2",
            "`gmcrypto-core` | `1.11.0` | `x509`",
            "`cb0ee0fc8572307aeccea2a43815e461b52e626d9e077130f335232af0736feb`",
            "unsafe_code = \"forbid\"",
            "No universal constant-time claim",
        ],
    );
}

#[test]
fn root_lock_and_inventory_pin_the_reviewed_spin_patch() {
    let lockfile = repository_file("Cargo.lock");
    let snapshot = repository_file("ci/crypto-inventory.snapshot");
    let inventory = repository_file("docs/security/cryptographic-dependencies.md");
    let reviewed_checksum = "023a211cb3138dbc438680b32560ad89f699977624c9f8dbb95a47d5b4c07dd3";
    let reviewed_stanza = format!(
        "name = \"spin\"\nversion = \"0.10.1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{reviewed_checksum}\""
    );
    let reviewed_snapshot = format!("spin|0.10.1|once|{reviewed_checksum}|reviewed-unsafe-present");
    let reviewed_inventory = format!(
        "| `spin` | `0.10.1` | `once` | `{reviewed_checksum}` | reviewed: unsafe source present | Backend one-time initialization support |"
    );

    assert_eq!(lockfile.matches(&reviewed_stanza).count(), 1);
    assert_eq!(snapshot.matches(&reviewed_snapshot).count(), 1);
    assert_eq!(inventory.matches(&reviewed_inventory).count(), 1);
    assert!(!lockfile.contains("name = \"spin\"\nversion = \"0.10.0\""));
    assert!(!snapshot.contains("spin|0.10.0|"));
    assert!(!inventory.contains("| `spin` | `0.10.0` |"));
}

#[test]
fn release_checklist_separates_build_approval_and_authorization() {
    let checklist = repository_file("RELEASE_CHECKLIST.md");
    assert_markers(
        &checklist,
        &[
            "**Template version:** 2",
            "- `candidate-source`: a named commit selected for repository checks.",
            "- `rc-built`: repository-owned gates passed for the exact candidate commit, and the complete immutable artifact set was produced and checksummed. External recording is not a prerequisite for this local state; external gates are **not evaluated in-tree**.",
            "- `rc-approved`: the unchanged complete `rc-built` artifact set passed every required external gate below, recorded by the release owner.",
            "- `release-authorized`: the release owner approved a separately considered publication action for the unchanged complete `rc-approved` artifact set.",
            "The repository command can produce only `rc-built`. It cannot infer or record either later state.",
            "Recording artifact identity externally is a handoff and evidence action after `rc-built`; it is not a predicate for the local state.",
            "- RC manifest: record `rc-manifest.json` filename, byte length, SHA-256, and manifest schema version.",
            "- SHA256SUMS: record filename, byte length, and SHA-256 externally to avoid self-hash circularity; verify its entries match every other RC artifact.",
            "Every later approval must identify the unchanged complete artifact set above.",
            "- Gate ID.",
            "- Exact candidate commit.",
            "- `rc-manifest.json` SHA-256.",
            "- Source export SHA-256.",
            "- Cargo package SHA-256.",
            "- Result.",
            "- Evidence ID, run URL, or reference.",
            "- Reviewer or automated system.",
            "- Completion UTC.",
            "- Expiry UTC (or explicit non-expiring policy).",
            "- Disposition or notes reference.",
            "Linux CI passed for the exact candidate commit; record the run ID and actual `rustc --version`.",
            "macOS CI passed for the exact candidate commit; record the run ID and actual `rustc --version`.",
            "Windows CI passed for the exact candidate commit; record the run ID and actual `rustc --version`.",
            "Rust 1.85 MSRV CI passed for the exact candidate commit; record the run ID and actual `rustc --version`.",
            "Each following gate must identify the unchanged complete artifact set and include every required evidence record field above.",
            "Self security review completed against the prepared review packet",
            "License and dependency hygiene",
            "Repository history scanned for secrets",
            "A completed copy lives in the release owner's records outside the repository",
            "- Missing evidence is `pending`, never `passed`.",
            "- A rejected or expired gate blocks promotion.",
            "- Any source, dependency, metadata, documentation, package, evidence-version, or checksum change returns the candidate to `candidate-source`.",
            "- No checklist entry authorizes a tag, push, crates.io publication, or production deployment by itself.",
        ],
    );

    let rc_built_definition = checklist
        .lines()
        .find(|line| line.starts_with("- `rc-built`:"))
        .expect("release checklist must define rc-built");
    assert!(
        !rc_built_definition
            .to_ascii_lowercase()
            .contains("recorded externally"),
        "rc-built must not require external recording: {rc_built_definition}"
    );

    assert_eq!(completed_approval_marker(&checklist), None);
    for completed_variant in ["* [X] completed", "+ [x] completed"] {
        assert_eq!(completed_approval_marker(completed_variant), Some("[x]"));
    }
}

/// Extracts the first whitespace-delimited token that follows `install_prefix`
/// in a workflow file — the pinned version on a `cargo install <tool> --version
/// <v> --locked` line.
fn workflow_pinned_version(workflow: &str, install_prefix: &str) -> String {
    workflow
        .lines()
        .find_map(|line| line.split_once(install_prefix))
        .map(|(_, rest)| rest)
        .unwrap_or_else(|| panic!("workflow is missing an install line for {install_prefix:?}"))
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("no version token after {install_prefix:?}"))
        .to_owned()
}

#[test]
fn contributing_tooling_pins_match_the_release_workflows() {
    let contributing = repository_file("CONTRIBUTING.md");
    let ci = repository_file(".github/workflows/ci.yml");

    // cargo-fuzz drifted here once: CONTRIBUTING pinned 0.13.1 while every
    // executable source pinned 0.13.2. Derive the truth from the workflow
    // install line and require CONTRIBUTING to quote the same version, so the
    // guidance cannot silently fall behind the pin it documents again.
    let cargo_fuzz = workflow_pinned_version(&ci, "cargo install cargo-fuzz --version ");
    assert!(
        contributing.contains(&format!("cargo-fuzz {cargo_fuzz}")),
        "CONTRIBUTING must pin cargo-fuzz {cargo_fuzz} to match .github/workflows/ci.yml"
    );

    // The rest of the pinned tool set and toolchains, validated as markers so
    // the release-readiness section stays complete alongside the gates it
    // describes.
    assert_markers(
        &contributing,
        &[
            "cargo-deny 0.20.2",
            "cargo-public-api 0.52.0",
            "actionlint 1.7.12",
            "Rust 1.85.0",
            "nightly-2026-05-23",
        ],
    );
}
