# Cryptographic Dependency Inventory

**Inventory version:** 2

- Reviewed Cargo.lock SHA-256: `cb3fed2e6bc3653fdab3cfd026c828418c183aa97535308668dd15d59fdf6bfa`
- Root crate policy: `#![forbid(unsafe_code)]`
- Backend registry checksum: `4e81a6030cdbef95407ef7924aa2b60469d1263e094b667295cd3d787c2c3095`

The reviewed boundary is the exact package, version, enabled-feature, registry-checksum, and source-scan-status snapshot in `ci/crypto-inventory.snapshot`. `ci/check-crypto-inventory.sh` obtains enabled feature edges from `cargo tree --locked -e features`, associates each checksum with its Cargo.lock package stanza, and fails if that view or the reviewed boundary changes.

| Dependency | Resolved version | Enabled features | Registry checksum | Source-scan status | SDK responsibility |
| --- | --- | --- | --- | --- | --- |
| `base64` | `0.22.1` | `alloc`, `default`, `std` | `72b3254f16251a8381aa12e40e3c4d2f0199f8c6508fbecb9d91f575e0fbb8c6` | reviewed: no unsafe source | Standard-padded encoded envelope fields plus SDK canonicality checks |
| `getrandom` | `0.4.3` | `default`, `sys_rng` | `300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099` | reviewed: unsafe source present | Operating-system randomness for each session key and request metadata |
| `gmcrypto-core` | `1.11.0` | `default`, `x509` | `4e81a6030cdbef95407ef7924aa2b60469d1263e094b667295cd3d787c2c3095` | reviewed: no unsafe source | SM2 signing, verification and wrapping; SM3; SM4; PKCS#8, SPKI, PEM, and X.509 parsing |
| `crypto-bigint` | `0.7.5` | `subtle`, `zeroize` | `1a52aa3fcda4e6302a9f48734f234d35d4721b96f8fe07d073f07ce9df4f0271` | reviewed: unsafe source present | Backend integer arithmetic |
| `ctutils` | `0.4.2` | `default`, `subtle` | `7d5515a3834141de9eafb9717ad39eea8247b5674e6066c404e8c4b365d2a29e` | reviewed: no unsafe source | Backend constant-time selection and equality utilities |
| `cmov` | `0.5.4` | `default` | `0c9ea0ac24bc397ab3c98583a3c9ba74fa56b09a4449bbe172b9b1ddb016027a` | reviewed: unsafe source present | Backend architecture-specific conditional-move primitives |
| `cpubits` | `0.1.1` | `default` | `15b85f9c39137c3a891689859392b1bd49812121d0d61c9caf00d46ed5ce06ae` | reviewed: no unsafe source | Backend CPU-width bit utilities |
| `rand_core` | `0.10.1` | `default` | `63b8176103e19a2643978565ca18b50549f6101881c443590420e4dc998a3c69` | reviewed: no unsafe source | Backend RNG trait boundary |
| `spin` | `0.10.1` | `once` | `023a211cb3138dbc438680b32560ad89f699977624c9f8dbb95a47d5b4c07dd3` | reviewed: unsafe source present | Backend one-time initialization support |
| `subtle` | `2.6.1` | `none` | `13c2bddecc57b384dee18652358fb23172facb8a2c51ccc10d74c157bdea3292` | reviewed: unsafe source present | Backend constant-time utility boundary |
| `zeroize` | `1.9.0` | `alloc`, `default`, `derive`, `zeroize_derive` | `e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e` | reviewed: unsafe source present | SDK-owned session-key, plaintext, and authentication-input guards |
| `zeroize_derive` | `1.5.0` | `default` | `3c50655cbb0fe3fc43170059e702f1ce5e19b84cec58dc87b037a09935c2f328` | reviewed: no unsafe source | Macro implementation used by zeroization derives |

The direct manifest request is `gmcrypto-core` | `1.11.0` | `x509`; its enabled feature set also includes `default`.

## AEAD feature boundary

The rows below are compiled only under the opt-in `aead` feature (`aead = ["gmcrypto-core/sm4-aead"]`). They are locked in `Cargo.lock` unconditionally because Cargo locks the maximal feature graph, but a default build compiles none of this code. The `gmcrypto-core` row here overrides the default-boundary row's enabled-feature set; its registry checksum and scan status are identical. `ci/check-crypto-inventory.sh` validates this table as an overlay on the default boundary using `cargo tree --locked --features aead`.

| Dependency | Resolved version | Enabled features | Registry checksum | Source-scan status | SDK responsibility |
| --- | --- | --- | --- | --- | --- |
| `gmcrypto-core` | `1.11.0` | `default`, `sm4-aead`, `x509` | `4e81a6030cdbef95407ef7924aa2b60469d1263e094b667295cd3d787c2c3095` | reviewed: no unsafe source | Adds SM4-GCM sealing and opening for the AEAD envelope mode |
| `gmcrypto-simd` | `1.11.0` | `none` | `31a7928890d12bd4064aba2664435fc62b2a6a487f8c2611d26856f31d5ceca4` | reviewed: unsafe source present | GHASH carryless-multiply and SIMD SM4 S-box backends quarantined out of `gmcrypto-core` |
| `cpufeatures` | `0.2.17` | `default` | `59ed5838eebb26a2bb2e58f6d5b5316989ae9d08bab10e0e6d103e656d1b0280` | reviewed: unsafe source present | Runtime CPU-capability detection for SIMD backend selection |

The `sm4-aead` feature is atomic in `gmcrypto-core` and is defined as `["dep:gmcrypto-simd"]`: enabling GCM alone or CCM alone is not possible, and the SIMD crate is the AVX2/NEON and GHASH `clmul`/`pmull` quarantine that lets `gmcrypto-core` keep `unsafe_code = "forbid"` while `gmcrypto-simd` itself sets `unsafe_code = "warn"`. `cpufeatures` depends on the already-locked `libc`, which remains outside this cryptographic boundary as platform plumbing. No constant-time claim is made for the SIMD backends. Each source-scan status remains limited to the exact registry checksum in its row and is not an audit or a safety proof.

For the `spin` 0.10.0 to 0.10.1 lock refresh, the reviewed manifest retains the `once` feature and otherwise changes only the package version. The runtime-source delta is limited to `src/once.rs`: `Once::force_into_inner` now uses `ManuallyDrop` with `assume_init_read` to prevent a double drop, and the crate adds a regression test for moving out a boxed value. The unsafe-source classification therefore remains `reviewed: unsafe source present`. This records the dependency review; it does not claim that this SDK directly exercised the affected consuming APIs.

For the `gmcrypto-core` 1.9.0 to 1.11.0 refresh, the default (non-AEAD) compiled graph keeps the manifest request at `x509`, the resolved feature set stays `default`, `x509`, and no transitive dependency was added, removed, or re-versioned. The source delta covers six files: `src/lib.rs`, `src/sm4/mod.rs`, `src/sm4/mode_cbc.rs`, `src/sm4/cbc_streaming.rs`, and the `src/sm4/mode_gcm.rs` and `src/sm4/mode_ccm.rs` AEAD modules, which stay behind the `sm4-aead` feature and are not compiled into the default SDK build. The default compiled delta therefore concentrates in the SM4 CBC path, including the upstream deduplication of PKCS#7 unpadding. The opt-in AEAD graph and its additional transitive packages are recorded separately in the feature-scoped inventory tier above. The 1.11.0 manifest keeps `unsafe_code = "forbid"`, a source scan of the checksummed package found no unsafe item or block, and the classification remains `reviewed: no unsafe source`. The package license metadata changed from `Apache-2.0` to `MIT OR Apache-2.0`, which the dependency policy allowlist accepts. This records the dependency review; it does not claim that this SDK re-established timing behavior.

Each source-scan status is limited to the exact registry checksum in its row and means only whether an unsafe item or unsafe block was found in that package's Rust source during review; it is not an audit or a safety proof. The reviewed `gmcrypto-core` 1.11.0 manifest also sets `unsafe_code = "forbid"`, limited to the checksum above.

Platform plumbing such as `cfg-if`, `libc`, and `r-efi` is intentionally outside this cryptographic boundary because it selects or binds operating-system facilities rather than implementing the reviewed cryptographic primitives. Generic-container and arithmetic scaffolding inside the resolved backend graph — `hybrid-array`, `typenum`, `num-traits`, and the build-time `autocfg` — is likewise outside the boundary because it provides type-level array and numeric-trait machinery rather than implementing the reviewed primitives. It remains pinned by Cargo.lock and therefore changes still invalidate the recorded lockfile hash. This boundary is not a claim that every transitive dependency, platform implementation, compiler, allocator, or operating system has been source-reviewed.

No universal constant-time claim is made. The backend describes constant-time design, but this SDK has not independently established timing, cache, power, electromagnetic, fault-injection, compiler, operating-system, allocator, or hardware behavior.

## Evidence

Public SM2 verification, SM3, and SM4 known-answer tests live in `tests/standard_vectors.rs`. SDK-level negative tests cover wrong roles and keys, malformed and wrong-length wrapped keys, padding and ciphertext changes, malformed and changed signatures, strict Base64, context mismatch, and opaque inbound errors. Private deployed-wire compatibility remains external.

## Update policy

Any direct or resolved cryptographic dependency, feature, registry checksum, or Cargo.lock change invalidates this inventory. Update it only after reviewing the new source and manifest, rerunning known-answer and semantic-negative tests, running dependency policy, updating the recorded lockfile checksum and machine-readable snapshot, and producing a new RC artifact identity.
