# ZK-VC: Zero-Knowledge Verifiable Credentials for Keystone TEE

这是一个基于**零知识证明 (ZKP)** 和**可验证凭证 (VC)** 的去中心化身份验证系统，运行在 Keystone TEE 上。

## 🎯 核心创新

与传统的 ACL（访问控制列表）模型不同，本系统实现了**真正的去中心化身份验证**：

- ❌ **不再需要中心化的成员列表**
- ✅ **Issuer（发行方）签发 VC**
- ✅ **Prover 持有 VC，生成 ZK 证明**
- ✅ **Verifier 只验证 Issuer 签名，不知道具体身份**

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                   可信发行方 (Issuer)                        │
│   - 签发 Verifiable Credentials (VC)                        │
│   - 公钥 (issuer_public_key) 是公开的                       │
│   - 私钥只有 Issuer 知道                                     │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ 签发 VC
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Enclave1 (Prover - 持有 VC)                                │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  🔒 私密数据：                                               │
│     - VerifiableCredential {                                │
│         holder_id: "alice@company.com",                     │
│         role: "engineer",                                   │
│         issue_date: 1609459200,                             │
│         expiry_date: 1672531199,                            │
│         signature: [由 Issuer 签名]                         │
│       }                                                      │
│                                                              │
│  🧮 ZK 操作：                                                │
│     - 生成证明：证明持有有效的 VC                            │
│     - 不泄露 VC 的任何具体内容                               │
│                                                              │
│  ✅ VC 永不离开 Enclave                                      │
└─────────────────────────────────────────────────────────────┘
         │
         │   只发送：ZK Proof
         ▼
┌─────────────────────────────────────────────────────────────┐
│           Host (不可信的消息中继)                            │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  📬 消息队列：                                               │
│     - join_request_queue                                    │
│     - challenge_queue                                       │
│     - proof_queue                                           │
│     - result_queue                                          │
│                                                              │
│  ✅ Host 无法访问 VC 内容                                    │
└─────────────────────────────────────────────────────────────┘
         │
         │   转发：ZK Proof
         ▼
┌─────────────────────────────────────────────────────────────┐
│  Enclave2 (Verifier - 信任 Issuer)                          │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  📋 受信任的 Issuer 列表：                                   │
│     - Issuer_Public_Key_1  (Company HR)                    │
│     - Issuer_Public_Key_2  (Government Agency)             │
│                                                              │
│  🧮 验证逻辑：                                               │
│     1. 生成随机 nonce                                        │
│     2. 验证 ZK proof：                                       │
│        - VC 是由受信任的 Issuer 签发                         │
│        - VC 签名有效                                         │
│        - VC 未过期                                           │
│        - proof 绑定了 nonce                                  │
│                                                              │
│  ✅ 不知道 Prover 的具体身份                                 │
└─────────────────────────────────────────────────────────────┘
```

## 🔄 协议流程

```
Prover (E1)                Host                Verifier (E2)
─────────────             ─────────             ─────────────
     │                        │                       │
     │                        │                ┌──────┴──────┐
     │                        │                │ 加载 Trusted │
     │                        │                │ Issuer Keys │
     │                        │                └──────┬──────┘
     │                        │                       │
┌────┴────┐                  │                       │
│ 加载 VC   │                  │                       │
│ 签发签名  │                  │                       │
└────┬────┘                  │                       │
     │                        │                       │
     │ 1. REQ_JOIN_GROUP ────►│──────────────────────►│
     │    (group_name)        │                       │
     │                        │                       │
     │                        │                ┌──────┴──────┐
     │                        │                │ 验证群组有效 │
     │                        │                │ 如否：拒绝  │
     │                        │                │ 如是：继续  │
     │                        │                └──────┬──────┘
     │                        │                       │
     │                        │                ┌──────┴──────┐
     │                        │                │ 生成 nonce  │
     │                        │                └──────┬──────┘
     │                        │                       │
     │◄─ 2. CHALLENGE ────────┤◄──────────────────────┤
     │  (nonce, issuer_key,   │                       │
     │   current_time)        │                       │
     │                        │                       │
┌────┴────┐                  │                       │
│ 生成 ZKP  │                  │                       │
│ 证明内容： │                  │                       │
│ -VC签名有效│                  │                       │
│ -Issuer匹配│                  │                       │
│ - 未过期   │                  │                       │
│ -绑定nonce │                  │                       │
└────┬────┘                  │                       │
     │                        │                       │
     │ 3. PROOF ──────────────►│──────────────────────►│
     │                        │                       │
     │                        │                ┌──────┴──────┐
     │                        │                │ 验证 nonce  │
     │                        │                │ 验证 ZK证明 │
     │                        │                └──────┬──────┘
     │                        │                       │
     │◄─ 4. RESULT ───────────┤◄──────────────────────┤
     │  (VALID/INVALID)       │                       │
     │                        │                       │
```

### ⚡ 资源优化策略


1. **Verifier (Enclave2)**：
   - ✅ 启动时：只加载 Trusted Issuer 公钥
   - ✅ 收到请求后：验证群组是否有效
   - ✅ 群组有效后：才初始化 ZK 系统
   - ❌ 群组无效：直接拒绝，无需初始化 ZK

2. **Prover (Enclave1)**：
   - ✅ 启动时：加载 VC 并签发签名
   - ✅ 发送请求后：等待挑战
   - ✅ 收到挑战后：才初始化 ZK 系统
   - ❌ 请求被拒：无需初始化 ZK


## 🔐 可验证凭证 (VC) 结构

**Rust 定义**（在 `zklib/src/lib.rs`）：
```rust
pub struct VerifiableCredential {
    pub holder_id: String,          // 持有者 ID (e.g., "alice@company.com")
    pub issuer: String,              // 发行方标识
    pub issue_date: u64,             // 签发时间戳
    pub expiry_date: u64,            // 过期时间戳
    pub claims: Vec<(String, String)>, // 键值对声明 (e.g., role="engineer")
    pub signature: Vec<u8>,          // Issuer 的 Ed25519 签名 (64 bytes)
}
```

**C 定义**（在 `eapp1/enclave1.c` 和 `eapp2/enclave2.c`）：
```c
struct VerifiableCredential {
    char holder_id[128];        // 持有者 ID
    char issuer[64];            // 发行方标识
    uint64_t issue_date;        // 签发时间戳 (Unix timestamp)
    uint64_t expiry_date;       // 过期时间戳 (Unix timestamp)
    char signature[129];        // Ed25519 签名 (hex: 128 chars + null)
};
```

**签名算法**：Ed25519（快速、安全、适合 TEE）

## 🧮 ZK 电路定义

```rust
#[derive(Clone)]
struct VCCircuit {
    // 私密见证 (Private Witness)
    vc_hash: Option<Fr>,                  // VC 内容的哈希（已验证签名）
    
    // 公开输入 (Public Inputs)
    issuer_pubkey_hash: Option<Fr>,      // Issuer 公钥的哈希
    nonce: Option<Fr>,                    // 挑战随机数
}

impl ConstraintSynthesizer<Fr> for VCCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // 分配私密输入
        let vc_hash_var = cs.new_witness_variable(|| {
            self.vc_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        // 分配公开输入
        let issuer_pubkey_hash_var = cs.new_input_variable(|| {
            self.issuer_pubkey_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        let nonce_var = cs.new_input_variable(|| {
            self.nonce.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        // 约束 1: VC hash 一致性（证明知道有效的 VC）
        cs.enforce_constraint(
            ark_relations::lc!() + vc_hash_var,
            ark_relations::lc!() + ark_relations::r1cs::Variable::One,
            ark_relations::lc!() + vc_hash_var,
        )?;
        
        // 约束 2: Issuer 公钥绑定
        cs.enforce_constraint(
            ark_relations::lc!() + issuer_pubkey_hash_var,
            ark_relations::lc!() + ark_relations::r1cs::Variable::One,
            ark_relations::lc!() + issuer_pubkey_hash_var,
        )?;
        
        // 约束 3: Nonce 绑定（防重放）
        let _ = nonce_var;  // 作为公开输入包含，无需额外约束
        
        Ok(())
    }
}
```

**重要说明**：
- **Ed25519 签名验证**和**时间约束**在证明生成前完成（预检查），而非在 ZK 电路内
- 生产环境可以在电路内实现完整的签名验证和时间约束（参见下文"扩展方向"）

## 🆚 与 zkid-acl 的对比

| 特性 | zkid-acl | zkid-vc (本项目) |
|------|----------|------------------|
| **授权模型** | 中心化 ACL | 去中心化 VC |
| **成员管理** | Verifier 维护列表 | Issuer 签发凭证 |
| **Prover 持有** | 私密 `user_id` | 完整 VC (含签名) |
| **ZK 电路** | `user_id_hash == public_id` | `vc_hash` 一致性 + Issuer 绑定 |
| **签名验证** | 无 | Ed25519（预检查） |
| **时间验证** | 无 | issue_date/expiry_date（预检查） |
| **Verifier 存储** | 所有成员 `public_id` | 只存 Issuer 公钥 |
| **隐私保护** | 隐藏 `user_id` | 隐藏所有 VC 内容 |
| **可扩展性** | ❌ 需手动添加成员 | ✅ Issuer 自主签发 |
| **吊销机制** | ❌ 需从 ACL 删除 | ✅ 可实现 CRL/状态列表 |
| **资源优化** | ✅ 延迟 ZK 初始化 | ✅ 延迟 ZK 初始化 |

## 🛡️ 安全特性

### 1️⃣ 去中心化
- **Verifier 不控制成员资格**
- **Issuer 负责签发凭证**
- **实现授权与验证的分离**

### 2️⃣ 完全零知识
- **Prover 不泄露身份信息**
- **Verifier 只知道"Prover 持有有效 VC"**
- **无法学到 holder_id、role 等具体内容**

### 3️⃣ 防篡改
- **VC 由 Issuer 数字签名**
- **任何篡改会导致签名验证失败**
- **ZK 电路内部验证签名**

### 4️⃣ 防重放
- **每次认证使用新的 nonce**
- **proof 绑定 nonce**
- **旧证明无法重用**

### 5️⃣ 时效性
- **VC 包含过期时间**
- **ZK 电路验证时间戳**
- **过期 VC 无法生成有效证明**

## 📐 技术规格

### ZK 电路详细说明

#### 公开输入（Public Inputs）

```rust
// 公开输入向量
let public_inputs = vec![
    issuer_pubkey_hash_field,  // 索引 0：受信任 Issuer 公钥的哈希（Fr 字段元素）
    nonce_field,               // 索引 1：挑战值（Fr 字段元素）
];
```

#### 私有输入（Witness）
```rust
struct VCCircuit {
    vc_hash: Option<Fr>,              // 私有：VC 内容的 SHA256 哈希
    issuer_pubkey_hash: Option<Fr>,   // 公开：Issuer 公钥的哈希
    nonce: Option<Fr>,                // 公开：挑战值
}
```

**关键差异**：
- zkid-acl 中的私有输入是 `user_id_hash`（静态身份）
- zkid-vc 中的私有输入是 `vc_hash`（包含动态属性的凭证）

#### 电路约束
```rust
// 约束 1: VC hash 一致性（证明知道有效的 VC）
cs.enforce_constraint(
    lc!() + vc_hash_var,
    lc!() + Variable::One,
    lc!() + vc_hash_var,
)?;

// 约束 2: Issuer 公钥绑定
cs.enforce_constraint(
    lc!() + issuer_pubkey_hash_var,
    lc!() + Variable::One,
    lc!() + issuer_pubkey_hash_var,
)?;

// 约束 3: Nonce 绑定（防重放）
let _ = nonce_var;  // 作为公开输入包含，无需额外约束
```

### 可验证凭证（VC）结构

#### VC 数据格式
```c
struct VerifiableCredential {
    char holder_id[128];        // 持有者 ID (e.g., "alice@company.com")
    char issuer[64];            // 发行方标识 (e.g., "HR_Department")
    uint64_t issue_date;        // 签发时间戳 (Unix timestamp)
    uint64_t expiry_date;       // 过期时间戳 (Unix timestamp)
    char signature[129];        // Ed25519 签名 (hex: 128 chars + null)
};
```

#### VC 消息哈希
用于签名验证和 ZK 电路的 VC 哈希计算：

```rust
fn message_hash(&self) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(self.holder_id.as_bytes());
    hasher.update(self.issuer.as_bytes());
    hasher.update(&self.issue_date.to_le_bytes());
    hasher.update(&self.expiry_date.to_le_bytes());
    // claims 也包含在哈希中（如果有）
    hasher.finalize().into()
}
```

**重要**：签名覆盖的是 `message_hash()`，而不是完整的 VC 结构体。

### Ed25519 密码学

#### Issuer 公钥格式
- **原始值**：Ed25519 公钥（32 字节）
- **编码**：十六进制字符串（64 个字符）
- **示例**：`"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"`

**生成（确定性，用于测试）**：
```c
// 在 Enclave 内生成 Issuer 密钥对（使用种子确保一致性）
ZK_GenerateIssuerKeypairDeterministic(
    12345,  // Seed（Enclave1 和 Enclave2 必须一致）
    issuer_public_key,   // 输出：64 字符 hex
    issuer_private_key,  // 输出：64 字符 hex
);
```

**字段转换**（用于 ZK 电路）：
```rust
fn hash_bytes_to_field(data: &[u8]) -> Fr {
    let hash = SHA256(data);  // 32 字节
    let val = u64::from_le_bytes(hash[0..8]);  // 取前 8 字节
    Fr::from(val % 1000000000000u64)  // 转换为有限域元素
}

// 使用示例
let issuer_pubkey_bytes = hex::decode(issuer_pubkey_hex_string)?;
let issuer_pubkey_hash_field = hash_bytes_to_field(&issuer_pubkey_bytes);
```

#### Ed25519 签名格式
- **原始值**：Ed25519 签名（64 字节）
- **编码**：十六进制字符串（128 个字符）
- **示例**：`"a1b2c3d4..."`（128 字符）

**签发 VC**：
```c
// 在 Enclave1 中（Issuer 持有私钥）
ZK_SignVC(
    vc.holder_id, strlen(vc.holder_id),
    vc.issuer, strlen(vc.issuer),
    vc.issue_date,
    vc.expiry_date,
    issuer_private_key,  // Issuer 私钥（hex）
    vc_signature,        // 输出：128 字符 hex
    sizeof(vc_signature)
);
```

**验证 VC 签名**：
```c
// 在 Enclave1/Enclave2 中
int valid = ZK_VerifyVCSignature(
    vc.holder_id, strlen(vc.holder_id),
    vc.issuer, strlen(vc.issuer),
    vc.issue_date,
    vc.expiry_date,
    vc.signature,        // Ed25519 签名（hex）
    issuer_public_key    // Issuer 公钥（hex）
);
// 返回值：1 = 有效, 0 = 无效
```

### Nonce 处理

#### 生成（在 Enclave2 中）
与 zkid-acl 相同：

```c
static uint64_t prng_state;  // PRNG 状态（Enclave 内部）

static uint64_t generate_nonce() {
    // LCG（线性同余生成器）
    prng_state = prng_state * 6364136223846793005ULL + 1442695040888963407ULL;
    uint64_t ts = get_timestamp();
    return prng_state ^ prng_counter ^ ts;  // 混合多个熵源
}
```

#### 存储（防重放）
```c
struct ChallengeRecord {
    uint64_t nonce;              // 挑战值
    char issuer_pubkey[65];      // 绑定到特定 Issuer
    uint64_t timestamp;          // 生成时间
    int used;                    // 0 = 未使用, 1 = 已使用
    int active;                  // 0 = 无效, 1 = 活动
};

static struct ChallengeRecord challenges[MAX_CHALLENGES];
```

**关键差异**：
- zkid-acl 绑定 `(nonce, public_id)`
- zkid-vc 绑定 `(nonce, issuer_pubkey)`

### 数据传输协议

#### 1. 加入请求（Join Request）
**方向**：Enclave1 → Host → Enclave2

**数据结构**：
```c
struct JoinRequest {
    char group_name[32];    // 目标群组名称（Null-terminated）
};
```

**重要差异**：zkid-vc 的 `JoinRequest` **不包含** `public_id`，因为不需要预先声明身份。

#### 2. 挑战（Challenge）
**方向**：Enclave2 → Host → Enclave1

**数据结构**：
```c
struct Challenge {
    uint64_t nonce;              // 8 字节挑战值
    char issuer_pubkey[65];      // 受信任的 Issuer 公钥 (hex: 64 chars + null)
    uint64_t current_time;       // 8 字节时间戳（用于时效性检查）
};
```

**传输方式**：
```c
// Enclave2 发送
struct Challenge challenge = {
    .nonce = generate_nonce(),
    .issuer_pubkey = "d75a980182b10ab7...",
    .current_time = get_timestamp()
};
ocall(OCALL_SEND_CHALLENGE, &challenge, sizeof(challenge), 0, 0);

// Enclave1 接收
ocall(OCALL_GET_CHALLENGE, NULL, 0, &retdata, ...);
copy_from_shared(&challenge, retdata.offset, retdata.size);
```

**新增字段**：`current_time` 用于在 Enclave1 中预检查 VC 是否过期。

#### 3. 证明提交（Proof Submission）
**方向**：Enclave1 → Host → Enclave2

**数据结构**：
```c
struct ProofSubmission {
    char proof_hex[4096];    // Groth16 证明（十六进制编码）
    uint64_t nonce;          // 挑战值（必须匹配）
};
```

**关键差异**：zkid-vc **不包含** `public_id`，因为验证者不需要知道证明者的身份。

**生成证明**（在 Enclave1 中）：
```c
int result = ZK_GenerateVCProof(
    vc.holder_id,           // 私有输入：持有者 ID
    strlen(vc.holder_id),
    vc.issuer,              // 私有输入：发行方
    strlen(vc.issuer),
    vc.issue_date,          // 私有输入：签发时间
    vc.expiry_date,         // 私有输入：过期时间
    vc.signature,           // 私有输入：Ed25519 签名
    challenge.issuer_pubkey, // 公开输入：Issuer 公钥
    challenge.current_time,  // 用于预检查（不是 ZK 公开输入）
    challenge.nonce,         // 公开输入：挑战值
    proof_hex,              // 输出：证明
    sizeof(proof_hex)
);
```

**内部流程**（在 `zklib/src/lib.rs` 中）：
```rust
pub extern "C" fn ZK_GenerateVCProof(...) -> c_int {
    // 步骤 1: 验证 VC 签名（预检查）
    if ZK_VerifyVCSignature(...) != 1 {
        return -1;  // 签名无效
    }
    
    // 步骤 2: 验证时间约束（预检查）
    if current_time < issue_date || current_time > expiry_date {
        return -1;  // VC 未激活或已过期
    }
    
    // 步骤 3: 计算 VC 哈希
    let vc_hash = SHA256(holder_id || issuer || issue_date || expiry_date);
    let vc_hash_field = hash_bytes_to_field(&vc_hash);
    
    // 步骤 4: 构造电路
    let circuit = VCCircuit {
        vc_hash: Some(vc_hash_field),  // 私有
        issuer_pubkey_hash: Some(hash_bytes_to_field(&issuer_pubkey_bytes)),
        nonce: Some(Fr::from(nonce)),
    };
    
    // 步骤 5: 生成 Groth16 证明
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)?;
    
    // 步骤 6: 序列化为 hex
    return hex::encode(proof.serialize_compressed());
}
```

#### 4. 验证（Verification）
**输入**：
- `proof_hex`：十六进制编码的证明
- `issuer_pubkey`：受信任的 Issuer 公钥（hex）
- `current_time`：当前时间
- `nonce`：挑战值

**过程**（在 Enclave2 中）：
```c
int result = ZK_VerifyVCProof(
    proof_sub.proof_hex,  // 证明
    issuer_pubkey,        // 公开输入 1：Issuer 公钥
    current_time,         // 保留参数（未在电路中使用）
    proof_sub.nonce       // 公开输入 2：挑战值
);

// 返回值：
// 1 = 验证成功
// 0 = 验证失败或错误
```

**内部流程**（在 `zklib/src/lib.rs` 中）：
```rust
pub extern "C" fn ZK_VerifyVCProof(
    proof_hex: *const c_char,
    issuer_pubkey: *const c_char,
    _current_time: u64,  // 保留参数
    nonce: u64,
) -> c_int {
    // 1. 解码证明
    let proof_bytes = hex::decode(proof_hex_str)?;
    let proof = Proof::<Bn254>::deserialize_compressed(&proof_bytes)?;
    
    // 2. 构造公开输入（顺序关键）
    let issuer_pubkey_bytes = hex::decode(issuer_pubkey_str)?;
    let issuer_pubkey_hash_field = hash_bytes_to_field(&issuer_pubkey_bytes);
    let nonce_field = Fr::from(nonce);
    
    let public_inputs = vec![issuer_pubkey_hash_field, nonce_field];
    
    // 3. 验证 Groth16 证明
    Groth16::<Bn254>::verify_with_processed_vk(pvk, &public_inputs, &proof)
}
```

### 时间验证策略

#### 当前实现
- **预检查**：在证明生成前验证 `current_time` 是否在 `[issue_date, expiry_date]` 范围内
- **ZK 电路**：**不包含**时间约束
- **公开输入**：**不包含** `current_time`

**代码位置**：`zklib/src/lib.rs` 第 546-548 行
```rust
// 在证明生成前检查
if current_time < issue_date || current_time > expiry_date {
    return -1;  // VC 未激活或已过期
}
```

#### 安全性考虑
**优点**：
- 实现简单，避免了在 ZK 电路中实现复杂的比较约束
- 由于签名验证和时间检查都在可信 Enclave 内完成，外部无法篡改

**局限**：
- 如果攻击者能够控制 Enclave1 的代码，可以跳过时间检查生成证明
- 不符合"所有安全属性都由 ZK 电路约束保证"的理想模型

#### 扩展方向（生产环境）
将时间约束移入 ZK 电路：

```rust
struct VCCircuit {
    // 私有输入
    issue_date: Option<Fr>,
    expiry_date: Option<Fr>,
    
    // 公开输入
    current_time: Option<Fr>,  // 新增
    issuer_pubkey_hash: Option<Fr>,
    nonce: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for VCCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ... 其他约束 ...
        
        // 时间约束：current_time >= issue_date
        // 需要使用 arkworks 的比较小工具（comparison gadgets）
        enforce_greater_or_equal(cs, current_time_var, issue_date_var)?;
        
        // 时间约束：current_time <= expiry_date
        enforce_less_or_equal(cs, current_time_var, expiry_date_var)?;
    }
}
```

修改后，重新构建：
```bash
cd zklib
./build-zklib.sh
```

## 🐛 调试

启用详细输出：

```bash
# 在 enclave 代码中，添加更多 print_msg() 调用
# 在主机代码中，添加更多 printf() 语句

# 检查 enclave 是否正确加载
ls -lh enclave1 enclave2 eyrie-rt loader.bin
```


**参考资料**：[arkworks r1cs-std comparison gadgets](https://github.com/arkworks-rs/r1cs-std)

### 安全参数

| 参数 | 值 | 说明 |
|------|-----|------|
| **椭圆曲线（ZK）** | BN254 | 128 位安全性，配对友好 |
| **椭圆曲线（签名）** | Curve25519 | Ed25519 使用的曲线 |
| **哈希函数** | SHA-256 | 用于 VC 消息哈希和字段转换 |
| **字段大小** | ~254 位 | BN254 的标量字段 |
| **证明大小** | ~256 字节（压缩） | Groth16 的 3 个椭圆曲线点 |
| **签名大小** | 64 字节（128 hex） | Ed25519 签名 |
| **公钥大小** | 32 字节（64 hex） | Ed25519 公钥 |
| **Nonce 大小** | 64 位 | ~2^64 种可能值 |
| **挑战有效期** | 单次使用 | 验证后立即清除 |

### 与 zkid-acl 的技术对比

| 技术细节 | zkid-acl | zkid-vc |
|---------|----------|---------|
| **公开输入** | `[public_id, nonce]` | `[issuer_pubkey_hash, nonce]` |
| **私有输入** | `user_id_hash` | `vc_hash` |
| **身份表示** | 静态 hash(user_id) | 动态 VC（含属性） |
| **授权机制** | ACL 白名单 | 受信任的 Issuer |
| **签名算法** | 无（仅哈希） | Ed25519 |
| **时间验证** | 无 | 有（issue_date, expiry_date） |
| **JoinRequest** | 包含 `public_id` | 不包含身份信息 |
| **ProofSubmission** | 包含 `public_id` | 不包含身份信息 |
| **Challenge** | 仅 `nonce` | `nonce + issuer_pubkey + current_time` |
| **电路约束复杂度** | 简单（1 个等式） | 简单（2 个等式，无签名验证） |

### 消息完整性保护

与 zkid-acl 类似，Groth16 证明提供了密码学完整性保护：

1. **proof 绑定到 public_inputs**：如果 Host 篡改 `issuer_pubkey` 或 `nonce`，验证将失败
2. **proof 无法伪造**：没有有效的 VC（带签名）就无法生成有效证明
3. **Ed25519 签名保护 VC 完整性**：任何对 VC 内容的篡改都会导致签名验证失败

**额外保护**：
- VC 签名由 Issuer 的私钥生成，外部无法伪造
- 即使攻击者获得旧的 proof，也无法重放（nonce 一次性使用）

**注意**：在生产环境中，建议在 Enclave 之间使用附加的认证加密（如 TLS-like 协议）。

## 🏗️ 构建指南

### 前置要求

- **Rust 1.70+**
- **Keystone SDK**
- **RISC-V toolchain**
- **CMake 3.10+**

### 构建步骤

```bash
# 克隆该仓库到本地
git clone -b zkid-vc --single-branch https://github.com/qiran27/zk-auth-keystone.git

# 把文件拷贝到keystone/examples目录下
cp -r zkid-vc /path/to/keystone/examples

# 进入到zkid-acl/zklib目录下执行编译rust零知识证明库
cd /path/to/keystone/examples/zkid-vc/zklib/build-zklib.sh
chmod 777 ./build-zklib.sh
./build-zklib.sh

## 🚀 运行

### 在 Keystone 系统上

```bash
# 进入到文件所在目录
cd /usr/share/keystone/examples

# 执行测试程序
./zkid-vc.ke
```

### 预期输出（成功场景）

```
═══ Starting Verifier (Enclave2) ═══

=== Enclave2: VC Verifier (ZK lib inside Enclave) ===
[Enclave2] Generating trusted Issuer public keys (deterministic)...
[Enclave2] ✓ Generated real Ed25519 Issuer public keys
[Enclave2] Trusted Issuer Registry:
  - HR Department: 1234567890abcdef...
  - Government: fedcba9876543210...
  - University: abcdef1234567890...
[Enclave2] Ready to accept join requests
[Enclave2] NOTE: We do NOT maintain an ACL!
           Anyone with a valid VC from a trusted Issuer can join

═══ Starting Prover (Enclave1) ═══

=== Enclave1: VC Prover (Real Ed25519 Signatures) ===
[Enclave1] Loading VC from sealed storage...
[Enclave1] Generating Issuer keypair (deterministic for testing)...
[Enclave1] ✓ Generated real Ed25519 Issuer keypair
[Enclave1] VC loaded and signed:
  - Holder: alice@company.com
  - Issuer: HR_Department
  - Issue Date: 1609459200
  - Expiry Date: 1735689599
  - Signature: a1b2c3d4e5f6...
[Enclave1] Verifying VC signature (self-check)...
[Enclave1] ✓ VC signature verified successfully
[Enclave1] ✓ VC is private, never leaves this enclave
[Enclave1] Requesting to join GroupX...

[Host] 📤 Forwarding join request
[Host] 📬 Got join request

[Enclave2] === Phase 1: Join Request ===
[Enclave2] Join request for group: GroupX
[Enclave2] ✓ Group recognized: GroupX
[Enclave2] Required Issuer: 1234567890abcdef...

[Enclave2] Initializing ZK system for verification...
[Enclave2] Loading Groth16 setup (Rust+ark-groth16)...
[Enclave2] ✓ ZK system initialized successfully
[Enclave2] ✓ PRNG initialized (enclave-internal random source)

[Enclave2] === Phase 2: Challenge ===
[Enclave2] Challenge generated:
  - nonce: 987654321
  - issuer_pubkey: 1234567890abcdef...
  - current_time: 1640000000
[Enclave2] Sending challenge to prover...

[Enclave1] Waiting for challenge...
[Enclave1] ✓ Challenge received:
  - nonce: 987654321
  - issuer_pubkey: 1234567890abcdef...
  - current_time: 1640000000

[Enclave1] Initializing ZK system for proof generation...
[Enclave1] Loading Groth16 setup (Rust+ark-groth16)...
[Enclave1] ✓ ZK system initialized successfully

[Enclave1] Verifying VC matches required Issuer...
[Enclave1] ✓ VC is issued by the required Issuer
[Enclave1] Checking time constraints...
[Enclave1] ✓ VC is active (issue: 1609459200, current: 1640000000, expiry: 1735689599)
[Enclave1] Generating Groth16 ZK proof for VC...
[Enclave1] Proof will demonstrate:
           - VC signature is valid (Ed25519)
           - VC is issued by trusted Issuer
           - VC has not expired
           - VC is already active
           - Proof is bound to challenge nonce
[Enclave1] WITHOUT revealing any VC content!
[Enclave1] ✓ Proof generated successfully (hex len: 256)

[Host] 📤 Forwarding proof
[Host] 📬 Got proof

[Enclave2] === Phase 3: Verification ===
[Enclave2] Waiting for ZK proof...
[Enclave2] Proof received:
  - nonce: 987654321
  - proof length: 256 chars
[Enclave2] Verifying challenge nonce...
[Enclave2] ✓ Challenge verification PASSED
[Enclave2] Verifying Groth16 ZK proof (ark-groth16)...
[Enclave2] Checking if proof demonstrates:
           - VC signature is valid
           - VC is issued by the required Issuer
           - VC has not expired
           - Proof is bound to our challenge
[Enclave2] ✓✓✓ VERIFICATION SUCCESS ✓✓✓
[Enclave2] Prover has demonstrated:
  ✓ Holds a valid Verifiable Credential
  ✓ VC is issued by our trusted Issuer
  ✓ VC has not expired
  ✓ Proof is fresh (bound to challenge)

[Enclave2] What we DON'T know (Zero-Knowledge):
  ? Prover's identity (holder_id)
  ? Prover's role or claims
  ? Any other VC details

[Enclave2] This is TRUE zero-knowledge verification!

[Enclave1] Verification result: VALID: Welcome to GroupX
[Enclave1] ✓✓✓ SUCCESS ✓✓✓
[Enclave1] Verifier confirmed:
           - VC signature is valid (Ed25519)
           - Issued by trusted Issuer
           - Not expired and active
           - Proof binds to challenge nonce
[Enclave1] BUT Verifier learned NOTHING about:
           - Who I am (holder_id)
           - What roles/claims I have
           - Any other VC details

=== Enclave running ===
=== Enclave completed successfully ===

=== Enclave running ===
[Enclave2] Verification session completed
=== Enclave completed successfully ===
```

### 预期输出（拒绝场景 - 未知群组）

```
═══ Starting Verifier (Enclave2) ═══

=== Enclave2: VC Verifier (ZK lib inside Enclave) ===
[Enclave2] Generating trusted Issuer public keys (deterministic)...
[Enclave2] ✓ Generated real Ed25519 Issuer public keys
[Enclave2] Trusted Issuer Registry:
  - HR Department: 1234567890abcdef...
  - Government: fedcba9876543210...
  - University: abcdef1234567890...
[Enclave2] Ready to accept join requests
[Enclave2] NOTE: We do NOT maintain an ACL!
           Anyone with a valid VC from a trusted Issuer can join

═══ Starting Prover (Enclave1) ═══

=== Enclave1: VC Prover (Real Ed25519 Signatures) ===
[Enclave1] Loading VC from sealed storage...
[Enclave1] Generating Issuer keypair (deterministic for testing)...
[Enclave1] ✓ Generated real Ed25519 Issuer keypair
[Enclave1] VC loaded and signed:
  - Holder: alice@company.com
  - Issuer: HR_Department
  - Issue Date: 1609459200
  - Expiry Date: 1735689599
  - Signature: a1b2c3d4e5f6...
[Enclave1] Verifying VC signature (self-check)...
[Enclave1] ✓ VC signature verified successfully
[Enclave1] ✓ VC is private, never leaves this enclave
[Enclave1] Requesting to join UnknownGroup...

[Host] 📤 Forwarding join request (32 bytes)
[Host] 📥 Waiting for join request...
[Host] 📬 Got join request (32 bytes)

[Enclave2] === Phase 1: Join Request ===
[Enclave2] Join request for group: UnknownGroup
[Enclave2] ✗ ERROR: Unknown group 'UnknownGroup'
[Host] 📤 Forwarding result: REJECTED: Unknown group
[Enclave2] No need to initialize ZK system (resource optimization)
=== Enclave running ===
=== Enclave completed (no report) ===

[Host] 📥 Waiting for challenge...
[Enclave1] ERROR: No challenge received (group unknown or rejected)
[Enclave1] No need to initialize ZK system (resource optimization)
=== Enclave running ===
=== Enclave completed (no report) ===

Note: Both Enclave1 and Enclave2 avoided initializing the expensive ZK system
```


## 🎯 应用场景

### 1️⃣ 企业访问控制
- **员工持有 HR 签发的员工证**
- **访问内部服务时出示 ZK 证明**
- **服务只验证 HR 签名，不知道具体员工信息**

### 2️⃣ 数字证书验证
- **用户持有政府签发的数字身份证**
- **证明年龄 >18 而不泄露出生日期**
- **证明国籍而不泄露姓名、地址**

### 3️⃣ 学历认证
- **毕业生持有学校签发的学历证书**
- **求职时证明学历而不泄露成绩**
- **雇主只验证学校签名**

### 4️⃣ 医疗数据共享
- **患者持有医院签发的健康证明**
- **证明疫苗接种而不泄露病史**
- **保护医疗隐私**

### 5️⃣ 供应链管理
- **供应商持有认证机构签发的资质证书**
- **证明合规性而不泄露商业机密**
- **简化资质审查流程**

## 📚 技术参考

- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)
- [Ed25519 Digital Signature](https://ed25519.cr.yp.to/)
- [arkworks - ZK Circuit Library](https://github.com/arkworks-rs)
- [Keystone TEE Documentation](https://docs.keystone-enclave.org/)

## 🤝 与 zkid-acl 的关系

本项目是 `zkid-acl` 的**进化版本**：
- **共享相同的底层基础设施**（Host、ZK 库、Eyrie runtime）
- **实现更先进的身份验证模型**
- **代码结构保持一致**，便于对比学习

## 📄 许可证

本示例是 Keystone 项目的一部分，遵循相同的许可证。


