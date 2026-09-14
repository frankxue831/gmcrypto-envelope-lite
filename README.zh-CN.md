# gmcrypto-envelope-lite

> 本文件是英文 [README.md](README.md) 的中文翻译，内容以英文版为准。代码示例的文档测试（doctest）编译仅针对英文版；本文件不参与 doctest 编译。

`gmcrypto-envelope-lite` 是一个小型、同步（synchronous）、不绑定 HTTP 实现（HTTP-neutral）的 Rust 库，用于 SM2/SM3 签名（signature）和 SM4 安全信封（secure envelope）。它**未经独立审计（independent audit）**。请将其视为安全敏感软件，依据你的威胁模型（threat model）进行审查，并在部署前完成自己的密码学与集成评估。

纳入版本管理的[安全模型（Security model）](SECURITY_MODEL.md) 是安全声明、不作出的安全声明、信任边界（trust boundary）以及调用方必须实施的控制措施的权威清单。

## 在生态系统中的定位

`gmcrypto-envelope-lite` 是位于 `gmcrypto-core` 之上、独立进行版本管理的公共协议层（public protocol layer）；它使用核心密码学能力，但不在其公共应用程序编程接口（API）中暴露核心类型。合作方专用的线协议映射（wire mapping）、身份（identity）和精确线协议测试夹具（exact-wire fixture）保留在私有下游适配器（downstream adapter）中。

正式成员资格、分层、版本管理、准入规则和兼容性门禁（compatibility gate）由 [gmcrypto Rust 生态系统章程](https://github.com/frankxue831/gm-crypto-rs/blob/main/docs/ECOSYSTEM.md) 定义。本 Rust 包（crate）的门禁测试套件是候选 `gmcrypto-core` 发布版本的第 1 项兼容性门禁：`ci/check-compatibility-gate.sh` 会针对候选核心版本，在本 crate 交付的每一种特性（feature）配置下运行该套件；章程要求任何核心版本发布前都必须通过一次运行。

本 crate 将应用字节转换为与传输无关（transport-neutral）的 `RequestParts`，并且仅在通过认证（authentication）后才打开 `ResponseParts`。它不发送 HTTP 请求、不选择异步运行时（async runtime）、不建立传输层安全（TLS）连接、不重试请求、不管理端点（endpoint），也不强制使用某个 HTTP 客户端。

## 模型与信任边界

一个 `SecureClient` 拥有一份经过验证的 `ClientConfig`、四个按角色区分的密钥，以及一个 `ProtocolAdapter`。它是不可变的（immutable），并且满足 `Send + Sync`。请为每个身份创建一个客户端；不要将单个实例用作可变的多身份注册表。

四种密钥角色明确如下：

- 本地签名私钥（signing private key）；
- 本地解密私钥（decryption private key）；
- 远端验签公钥（verification public key）；
- 远端加密公钥（encryption public key）。

`KeyMaterial::new` 接受全部四种角色，并拒绝字节完全相同的本地私钥或字节完全相同的远端公钥。`KeyMaterial::shared` 会有意将同一个本地密钥同时用于签名和解密，并将同一个远端密钥同时用于验签和加密；只有协议明确指定共享角色时，才应使用这一便捷方法。同样明确表达共享意图的便捷方法 `shared_from_pem`、`shared_from_der` 和 `shared_from_files` 会加载这种共享角色配置。使用独立角色的协议应使用 `PrivateKey` 和 `PublicKey` 上的加载方法，然后调用 `KeyMaterial::new`。

`ProtocolAdapter` 仅映射身份元数据（metadata）、每次请求的协议上下文（protocol context）和不透明的信封字段。它无法访问明文（plaintext）、私钥或公钥对象，也无法访问调用方提供的自定义标头（custom header）。自定义标头在适配器输出之后追加；如果发生不区分大小写的名称冲突，则会拒绝，而不会覆盖已输出的标头。

## 认证模式

新协议优先使用 `AuthenticationMode::ContextBound`。其签名转录（signed transcript）精确如下：

```text
0x01 || u64be(domain_len) || domain || u64be(context_len) || context || u64be(plaintext_len) || plaintext
```

长度以字节计。域（domain）固定在不可变的客户端配置中，而适配器根据请求的语义数据推导每次请求的上下文。

`ClientConfig::iv` 是固定的 SM4-CBC 初始化向量（IV），仅用于兼容现有的旧版线协议。固定的密码分组链接（CBC）IV 在密钥复用时会产生确定性结果，并可能泄露明文前缀是否相同；为每个信封生成新的会话密钥（session key）可以缩小这种暴露范围，但并不能将这一构造变成现代认证加密（authenticated encryption）设计。`ContextBound` 仅扩展签名所认证的内容。它不替代 CBC，不修复固定 IV 或模式泄露（mode leakage）风险，也不提供对一次性数值（nonce）/IV 误用的抵抗能力。

不要将这种固定 IV 的 CBC 设计复制到新协议中。新集成应启用可选的 `aead` 特性，并选择“选择信封模式”中描述的 SM4-GCM 信封模式（envelope mode）；未启用该特性时，本 crate 不提供带附加数据的认证加密（AEAD）信封配置方案。

`AuthenticationMode::LegacyPlaintext` 仅为兼容旧版而存在。其 SM2 签名仅覆盖明文；它不认证信封元数据或传输标头。使用此模式的部署必须使用带认证的 TLS（authenticated TLS），并且必须实现应用层重放防护（replay protection）和请求/响应关联（request/response correlation）。

由于旧版线协议的签名覆盖明文，打开旧版信封必然要先解密、再验签。对于格式错误或未通过认证的密码学输入，本 crate 统一返回 `Error::InvalidEnvelope`，但统一错误并不能消除时间差异。调用方不得让失败类别、响应正文、日志详细程度、重试行为或耗时成为外部可观察的区别。

## 选择信封模式

信封模式和 AEAD 算法由 `ClientConfig` 固定，绝不根据传入字节推断：不存在协商（negotiation）或回退（fallback），客户端会直接拒绝其他模式或算法的信封。`AuthenticationMode`（SM2 签名覆盖的内容）是独立的维度，可与每一种模式组合。

| | `EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm)` — 特性 `aead`（推荐的 AEAD） | `EnvelopeMode::Aead(AeadAlgorithm::Sm4Ccm)` — 特性 `aead` | `EnvelopeMode::LegacyCbc` — 兼容性 |
| --- | --- | --- | --- |
| 载荷密码算法（payload cipher） | SM4-GCM，每个信封使用新生成的随机 12 字节 nonce 和完整的 16 字节认证标签（tag）；帧标识（frame id）为 `0x01` | SM4-CCM，每个信封使用新生成的随机 12 字节 nonce 和完整的 16 字节标签；帧标识为 `0x02`；明文上限默认为 `SM4_CCM_DEFAULT_MAX_PLAINTEXT_BYTES`（64 KiB），可显式提高至最大值 `SM4_CCM_MAX_PLAINTEXT_BYTES`（`2^24 - 1`） | 使用所配置固定 IV 的 SM4-CBC |
| 密文完整性（ciphertext integrity） | AEAD 标签，在产生任何明文之前验证 | AEAD 标签；CCM 先解密计数器模式（CTR）明文，再验证 CBC 消息认证码（CBC-MAC），若标签验证失败则擦除暂存明文（不会擦除密码原语内部的其他副本——参见 `SECURITY_MODEL.md`） | 密码算法本身不提供；仅依靠解密后的 SM2 签名 |
| 绑定的元数据 | 始终包含帧头（frame header）；在 `ContextBound` 下还包含域分隔符（domain separator）和协议上下文（在 `LegacyPlaintext` 下这些字段为空），全部纳入附加认证数据（AAD） | 与 GCM 相同的 AAD | 仅签名转录 |
| 重放防护 | 无——由应用负责 | 无——由应用负责 | 无——由应用负责 |
| 预期用途 | 新集成 | 线协议要求 CCM 的对端 | 已部署的现有线协议，无限期支持 |

在 AEAD 下，SM2 签名仍是强制要求：会话密钥使用公钥加密，因此仅凭标签无法证明谁封装了信封。启用 `aead` 特性时，必须指定 `envelope_mode`；省略它会产生 `Error::Configuration`，而不会静默默认使用 CBC。未启用该特性时，CBC 是唯一的信封模式。AEAD 配置不得设置 `iv`：

```no_run
# #[cfg(feature = "aead")] {
use gmcrypto_envelope_lite::{AeadAlgorithm, AuthenticationMode, ClientConfig, EnvelopeMode};

let mode = AuthenticationMode::context_bound(b"example-app/envelope/v1")
    .expect("nonempty domain separator");
let config = ClientConfig::builder()
    .local_identity_id("demo-client")
    .api_version("example-v1")
    .local_certificate_id("example-local-signing-certificate")
    .expected_remote_signing_certificate_id("example-remote-signing-certificate")
    .remote_encryption_certificate_id("example-remote-encryption-certificate")
    .local_signer_id(b"demo-local-signer")
    .expected_remote_signer_id(b"demo-remote-signer")
    .authentication_mode(mode)
    .envelope_mode(EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm))
    .build();
assert!(config.is_ok());
# }
```

## 构造客户端

所有协议映射都是显式的；没有内置的远端线协议名称。新集成应启用 `aead` 特性，并将 SM4-GCM 信封模式与上下文绑定认证（context-bound authentication）搭配使用。其 `ProtocolAdapter` 定义线协议：每个签名覆盖哪些认证上下文（authentication context），以及如何传输信封字段。适配器永远不会接触明文或密钥材料（key material）。

```no_run
# #[cfg(feature = "aead")] {
use std::sync::Arc;

use gmcrypto_envelope_lite::{
    AdapterError, AdapterErrorKind, AdapterResult, AeadAlgorithm, AuthenticationContext,
    AuthenticationMode, ClientConfig, ClientIdentity, EnvelopeMode, KeyMaterial, ParsedResponse,
    PrivateKey, ProtocolAdapter, ProtocolRequestContext, PublicKey, RequestParts, ResponseParts,
    SecureClient, SecureEnvelope,
};

struct ExampleContextAdapter;

impl ProtocolAdapter for ExampleContextAdapter {
    fn request_authentication_context(
        &self,
        _identity: &ClientIdentity,
        context: &ProtocolRequestContext,
    ) -> AdapterResult<AuthenticationContext> {
        // Bind semantic request data the verifying peer re-derives from the
        // received wire fields.
        AuthenticationContext::context_bound(
            format!(
                "operation={}&request-id={}",
                context.operation(),
                context.metadata().request_id()
            )
            .into_bytes(),
        )
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidField))
    }

    fn build_request(
        &self,
        identity: &ClientIdentity,
        context: &ProtocolRequestContext,
        envelope: &SecureEnvelope,
    ) -> AdapterResult<RequestParts> {
        RequestParts::new(
            [
                ("X-Envelope-Local-Identity", identity.local_identity_id()),
                ("X-Envelope-Operation", context.operation()),
                ("X-Envelope-Request-Id", context.metadata().request_id()),
                ("X-Envelope-Request-Signature", envelope.signature.as_str()),
                (
                    "X-Envelope-Request-Wrapped-Key",
                    envelope.wrapped_session_key.as_str(),
                ),
            ],
            envelope.cipher.as_str(),
        )
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidField))
    }

    fn parse_response(&self, response: ResponseParts) -> AdapterResult<ParsedResponse> {
        let header = |name: &str| {
            response
                .headers()
                .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.to_owned())
                .ok_or_else(|| AdapterError::new(AdapterErrorKind::MissingField))
        };
        let envelope = SecureEnvelope {
            cipher: response.body().to_owned(),
            wrapped_session_key: header("X-Envelope-Response-Wrapped-Key")?,
            signature: header("X-Envelope-Response-Signature")?,
        };
        let certificate = header("X-Envelope-Response-Remote-Signing-Certificate")?;
        // The remote binds the request id it answers into its signed
        // transcript; the application still correlates the verified response
        // with its originating request.
        let request_id = header("X-Envelope-Request-Id")?;
        let context = AuthenticationContext::context_bound(
            format!("request-id={request_id}").into_bytes(),
        )
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidField))?;
        ParsedResponse::new(envelope, certificate, context)
    }
}

fn client(key_password: &[u8]) -> Result<SecureClient, Box<dyn std::error::Error>> {
    let keys = KeyMaterial::new(
        PrivateKey::from_encrypted_file("example-local-signing.pem", key_password)?,
        PrivateKey::from_encrypted_file("example-local-decryption.pem", key_password)?,
        PublicKey::from_file("example-remote-verification.pem")?,
        PublicKey::from_file("example-remote-encryption.pem")?,
    )?;
    let config = ClientConfig::builder()
        .local_identity_id("demo-client")
        .api_version("example-v1")
        .local_certificate_id("example-local-signing-certificate")
        .expected_remote_signing_certificate_id("example-remote-signing-certificate")
        .remote_encryption_certificate_id("example-remote-encryption-certificate")
        .local_signer_id(b"demo-local-signer")
        .expected_remote_signer_id(b"demo-remote-signer")
        .authentication_mode(AuthenticationMode::context_bound(
            b"example-app/envelope/v1",
        )?)
        .envelope_mode(EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm))
        .build()?;
    Ok(SecureClient::new(
        config,
        keys,
        Arc::new(ExampleContextAdapter),
    )?)
}
# let key_password = std::env::var("SECURE_ENVELOPE_KEY_PASSWORD").expect("example password");
# let _client = client(key_password.as_bytes()).expect("example client");
# }
```

域分隔符固定在配置中，并像线格式（wire format）一样进行版本管理；每次请求的上下文从请求的语义数据推导，验签对端能够从这些数据重新推导相同的上下文。`examples/build_request.rs` 和 `examples/open_response.rs` 是此集成的完整可运行版本。

### 兼容模式：现有 CBC 线协议

已部署的固定 IV CBC 线协议仍将获得无限期支持；请明确将其配置为兼容模式。启用 `aead` 特性时，构建器（builder）必须在 `.build()` 之前调用 `.envelope_mode(EnvelopeMode::LegacyCbc)`——不会静默默认使用 CBC。对于通过标头映射的线协议（header-mapped wire），当两端都使用本 crate 定义的第 1 版二进制上下文时，可使用 `.context_bound_authentication()` 配合 `AuthenticationMode::ContextBound` 这一便捷方式。下面的模式定义（schema）使用显式的 `.legacy_authentication()` 确认，因为该兼容模式仅对明文签名。

```no_run
use std::sync::Arc;

use gmcrypto_envelope_lite::{
    AuthenticationMode, CipherLocation, ClientConfig, HeaderProtocolAdapter, HeaderSchema,
    KeyMaterial, PrivateKey, PublicKey, SecureClient,
};

fn client(key_password: &[u8]) -> Result<SecureClient, Box<dyn std::error::Error>> {
    let keys = KeyMaterial::new(
        PrivateKey::from_encrypted_file("example-local-signing.pem", key_password)?,
        PrivateKey::from_encrypted_file("example-local-decryption.pem", key_password)?,
        PublicKey::from_file("example-remote-verification.pem")?,
        PublicKey::from_file("example-remote-encryption.pem")?,
    )?;
    let builder = ClientConfig::builder()
        .local_identity_id("demo-client")
        .api_version("example-v1")
        .local_certificate_id("example-local-signing-certificate")
        .expected_remote_signing_certificate_id("example-remote-signing-certificate")
        .remote_encryption_certificate_id("example-remote-encryption-certificate")
        .local_signer_id(b"demo-local-signer")
        .expected_remote_signer_id(b"demo-remote-signer")
        .authentication_mode(AuthenticationMode::LegacyPlaintext)
        // A fixed IV is shown only for legacy wire compatibility.
        .iv(*b"example-iv-00001");
#    #[cfg(feature = "aead")]
#    let builder = builder.envelope_mode(gmcrypto_envelope_lite::EnvelopeMode::LegacyCbc);
    let config = builder.build()?;
    let schema = HeaderSchema::builder()
        .static_request_header("Content-Type", "application/example-envelope")
        .local_identity_header("X-Envelope-Local-Identity")
        .operation_header("X-Envelope-Operation")
        .request_id_header("X-Envelope-Request-Id")
        .request_time_header("X-Envelope-Request-Time")
        .api_version_header("X-Envelope-Api-Version")
        .local_certificate_header("X-Envelope-Local-Certificate")
        .remote_signing_certificate_header("X-Envelope-Remote-Signing-Certificate")
        .remote_encryption_certificate_header("X-Envelope-Remote-Encryption-Certificate")
        .request_signature_header("X-Envelope-Request-Signature")
        .request_wrapped_key_header("X-Envelope-Request-Wrapped-Key")
        .request_cipher(CipherLocation::Body)
        .response_signature_header("X-Envelope-Response-Signature")
        .response_wrapped_key_header("X-Envelope-Response-Wrapped-Key")
        .response_remote_signing_certificate_header(
            "X-Envelope-Response-Remote-Signing-Certificate",
        )
        .response_cipher(CipherLocation::Body)
        .legacy_authentication()
        .build()?;

    Ok(SecureClient::new(
        config,
        keys,
        Arc::new(HeaderProtocolAdapter::new(schema)),
    )?)
}
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let key_password = std::env::var("SECURE_ENVELOPE_KEY_PASSWORD")?;
# let _client = client(key_password.as_bytes())?;
# Ok(())
# }
```

## 迁移现有线协议

信封模式和认证模式由配置固定，不存在协商或回退，因此每一步迁移都需要两端协调变更线协议，而不是仅在客户端进行滚动升级（rolling upgrade）。

**CBC → AEAD。** 启用 `aead` 特性，选择 `EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm)`（推荐的 AEAD）或 `AeadAlgorithm::Sm4Ccm`，并移除 `iv` 设置——AEAD 配置会拒绝已配置的 IV。GCM、CCM 和 CBC 信封的线格式彼此不兼容，固定使用其中一种的客户端会直接拒绝其他种类，因此双方必须在同一次协调变更中切换。SM2 签名、密钥角色和会话密钥封装（wrapped-session-key）构造保持不变。

**LegacyPlaintext → ContextBound。** 选择固定的域分隔符并像线格式一样对其进行版本管理，选择 `AuthenticationMode::context_bound(domain)`，并推导请求与响应上下文，使验签对端能够根据线协议中的数据重新推导它们。通过标头映射的线协议若通过 `.context_bound_authentication()` 采用本 crate 定义的第 1 版二进制编码，则可以使用 `HeaderProtocolAdapter`。ASCII `operation={op}&request-id={id}` 不是本 crate 的标头适配器编码；只要两端达成一致，自定义 `ProtocolAdapter` 实现仍可使用它。签名转录的结构会改变，因此在一种模式下生成的签名绝不会在另一种模式下通过验证，双方必须就模式、域和上下文的精确推导方式达成一致。这仅扩展签名覆盖范围——不会使底层 CBC 构造现代化，也不会修复固定 IV 和模式泄露风险。

这两个维度相互独立：现有部署可以在仍使用 CBC 线协议时采用 `ContextBound`，而迁移后集成的最终状态与新集成相同——AEAD 配合 `ContextBound`。

## HTTP 集成

独立构建每个操作，并将返回的各部分复制到应用所选的 HTTP 协议栈（HTTP stack）中：

```no_run
# fn use_client(client: &gmcrypto_envelope_lite::SecureClient) -> gmcrypto_envelope_lite::Result<()> {
let request = client
    .request("demo-operation")
    .header("X-Envelope-Trace", "demo-trace")?
    .bytes(b"application payload")?;

for (name, value) in request.headers() {
    let (_http_name, _http_value) = (name.as_str(), value.as_str());
    // Set this pair on the chosen HTTP client.
}
let body = request.body();
# let _ = body;
# Ok(())
# }
```

将 HTTP 响应保存为有序的标头键值对序列及其正文，然后传给 `open_response` 或 `open_json_response`：

```no_run
# fn use_response(client: &gmcrypto_envelope_lite::SecureClient) -> gmcrypto_envelope_lite::Result<()> {
use gmcrypto_envelope_lite::ResponseParts;

# let received_headers = Vec::<(String, String)>::new();
# let received_body = String::new();
let response = ResponseParts::new(received_headers, received_body);
let verified_bytes = client.open_response(response)?;
# let _ = verified_bytes;
# Ok(())
# }
```

应用仍须负责 HTTP 方法和统一资源标识符（URI）的选择、TLS 验证、超时、重试安全性、重放防御，以及将已验证的响应与发起它的请求关联。

## 轮换与内存处理

密钥或身份轮换（rotation）意味着构造一个完整的替代客户端，其配置、模式定义（schema）和全部四个密钥均已通过验证。通过应用管理的原子 `Arc` 交换（atomic `Arc` swap）使其生效；不要原地修改正在使用的客户端。进行中的操作可以在旧的不可变实例上完成，而新操作使用替代实例。

本 crate 会对软件开发工具包（SDK）拥有的会话密钥缓冲区、未经验证的明文缓冲区以及 JSON 辅助函数使用的临时明文缓冲区进行清零（zeroization）。它无法保证清零由密码学和序列化（serialization）依赖内部拥有的内存分配、填充（padding）或中间值。它不声称经过独立审计、不声称所有行为都具有恒定时间（constant-time）特性，也不声称能够在进程被攻陷时提供保护。

## 私有映射、兼容性与发布

真实的远端映射、标识符、测试夹具和精确线协议兼容性测试套件必须存放在公共检出目录（public checkout）之外，例如独立实施访问控制的仓库、配置系统或适配器 crate 中。公共检出目录中的未跟踪文件不构成保密边界。在内部部署前，私有兼容性测试套件必须证明与现有远端线协议精确兼容。

从当前文件树中移除敏感材料，并不会将其从 Git 历史中移除。发布时，要么在完成有记录的历史扫描并由所有者明确决定后将本仓库转为公开，要么使用一份全新且经过审查的导出副本。发布前，应扫描完整的导出内容和包内容，并记录审查处置结果。

## 发布状态

版本 0.4.0 尚未发布，正在 `main` 上开发。版本 0.3.0 是当前已打标签的版本线（`v0.3.0`）。版本 0.2.0 仍是已打标签的首个 crates.io 候选版本（`v0.2.0`）。仓库检查会为指定提交生成一组不可变的 `rc-built` 产物（artifact）。尚未向 crates.io 发布；发布 0.2.0 时应基于 `git checkout v0.2.0`，而非更晚的 `main`。发布 0.3.0 时应基于 `git checkout v0.3.0`。发布 0.4.0 时应基于 `git checkout v0.4.0`。

`rc-built` 证明仓库门禁已完成，并不证明后续的外部状态。发布需要满足[发布检查清单](RELEASE_CHECKLIST.md)中的外部门禁；该清单被有意排除在 Cargo 包之外。

## 示例

两个示例均展示新集成的推荐配置——SM4-GCM 信封模式、上下文绑定认证，以及由调用方实现的 `ProtocolAdapter`——因此都声明了 `required-features = ["aead"]`；构建它们时请使用 `--features aead`。固定 IV 的 CBC 兼容配置仅出现在上文明确标注的章节中。

`examples/build_request.rs` 从命令行参数读取载荷和按角色区分的密钥路径，并从 `SECURE_ENVELOPE_KEY_PASSWORD` 读取密钥口令。它仅打印标头名称和加密后的正文长度。`examples/open_response.rs` 读取包含标头键值对和正文的 JSON 响应文档，然后仅打印已验证的字节长度。两个示例都不会发送 HTTP 请求，也不会打印标头值、信封正文、已验证的明文、密钥或秘密信息。
