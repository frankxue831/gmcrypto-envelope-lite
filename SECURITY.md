# Security Policy

`gmcrypto-envelope-lite` is security-sensitive software and is **not independently audited**. The versioned [Security model](SECURITY_MODEL.md) defines its claims, non-claims, trust boundaries, and required caller controls. Legacy-compatibility caveats include fixed-IV SM4-CBC, plaintext-only legacy signatures, and timing considerations. A report that restates a documented limitation is welcome as an issue or discussion, but it is not treated as a new vulnerability unless it demonstrates impact beyond what is documented.

## Reporting a vulnerability

Do not open a public issue or pull request for a suspected vulnerability.

Report it privately through GitHub: **Security → Report a vulnerability** on this repository (GitHub private vulnerability reporting). Include the affected version or commit, a description of the issue, and a minimal reproduction if you have one.

You should receive an acknowledgement within 7 days. Please allow a reasonable embargo period for a fix before public disclosure; we will coordinate timing with you in the advisory thread.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.4.x | Unreleased (`main`) |
| 0.3.x | Yes |
| 0.2.x | Yes |

Fixes land on `main` and ship in the next 0.4.x release. There is no 0.1.x support line.

## Scope notes

- The crate does not perform HTTP, TLS, retries, replay defense, or request/response correlation; issues in those layers belong to the embedding application.
- Zeroization guarantees and their limits are described in README.md ("Rotation and memory handling").
- There is no bug bounty program.
