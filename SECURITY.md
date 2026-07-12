# Security Policy

`secure-envelope-lite` is security-sensitive software and is **not independently audited**. The trust model, known limitations, and legacy-compatibility caveats (fixed-IV SM4-CBC, legacy plaintext signatures, timing considerations) are documented in [README.md](README.md). A report that restates a documented limitation is welcome as an issue or discussion, but it is not treated as a new vulnerability unless it demonstrates impact beyond what is documented.

## Reporting a vulnerability

Do not open a public issue or pull request for a suspected vulnerability.

Report it privately through GitHub: **Security → Report a vulnerability** on this repository (GitHub private vulnerability reporting). Include the affected version or commit, a description of the issue, and a minimal reproduction if you have one.

You should receive an acknowledgement within 7 days. Please allow a reasonable embargo period for a fix before public disclosure; we will coordinate timing with you in the advisory thread.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x (unreleased) | Yes — latest commit on `main` only |

Until a stable release exists, fixes land on `main` and are not backported.

## Scope notes

- The crate does not perform HTTP, TLS, retries, replay defense, or request/response correlation; issues in those layers belong to the embedding application.
- Zeroization guarantees and their limits are described in README.md ("Rotation and memory handling").
- There is no bug bounty program.
