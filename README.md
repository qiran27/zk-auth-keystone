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
     │ 1. REQ_JOIN_GROUP ────►│──────────────────────►│
     │                        │                       │
     │                        │                       │◄─ 生成 nonce
     │                        │                       │   选择 trusted_issuer_key
     │                        │                       │
     │◄─ 2. CHALLENGE ────────┤◄──────────────────────┤
     │  (nonce, issuer_key)   │                       │
     │                        │                       │
┌────┴────┐                  │                       │
│ 生成 ZKP  │                  │                       │
│ 证明内容： │                  │                       │
│ - VC 签名有效│                 │                       │
│ - Issuer 匹配│                 │                       │
│ - 未过期    │                  │                       │
│ - 绑定 nonce│                  │                       │
└────┬────┘                  │                       │
     │                        │                       │
     │ 3. PROOF ──────────────►│──────────────────────►│
     │                        │                       │
     │                        │                       │◄─ 验证 ZKP
     │                        │                       │   检查 nonce
     │                        │                       │
     │◄─ 4. RESULT ───────────┤◄──────────────────────┤
     │  (VALID/INVALID)       │                       │
     │                        │                       │
```

## 🔐 可验证凭证 (VC) 结构

```rust
struct VerifiableCredential {
    // VC 元数据
    holder_id: String,       // 持有者标识 (e.g., "alice@company.com")
    issuer: String,          // 发行方标识
    issue_date: u64,         // 签发时间戳
    expiry_date: u64,        // 过期时间戳
    
    // VC 内容 (可扩展)
    claims: Vec<(String, String)>,  // 键值对 (e.g., role="engineer")
    
    // 密码学绑定
    signature: Vec<u8>,      // Issuer 的数字签名
}
```

**签名算法**：Ed25519（快速、安全、适合 TEE）

## 🧮 ZK 电路定义

```rust
struct VCCircuit {
    // 私密输入 (Witness)
    vc_holder_id: Option<Fr>,
    vc_issue_date: Option<Fr>,
    vc_expiry_date: Option<Fr>,
    vc_signature: Option<Vec<u8>>,
    
    // 公开输入 (Public Inputs)
    trusted_issuer_pubkey: Option<Vec<u8>>,
    current_timestamp: Option<Fr>,
    nonce: Option<Fr>,
}

// 约束条件
impl ConstraintSynthesizer<Fr> for VCCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<()> {
        // 约束 1: VC 签名有效
        //   verify_ed25519_signature(
        //     message = hash(vc_holder_id || vc_issue_date || vc_expiry_date),
        //     signature = vc_signature,
        //     public_key = trusted_issuer_pubkey
        //   ) == true
        
        // 约束 2: VC 未过期
        //   current_timestamp <= vc_expiry_date
        
        // 约束 3: VC 已生效
        //   vc_issue_date <= current_timestamp
        
        // 约束 4: 绑定 nonce（防重放）
        //   nonce 被包含在证明中
        
        Ok(())
    }
}
```

## 🆚 与 zkid-acl 的对比

| 特性 | zkid-acl | zkid-vc (本项目) |
|------|----------|------------------|
| **授权模型** | 中心化 ACL | 去中心化 VC |
| **成员管理** | Verifier 维护列表 | Issuer 签发凭证 |
| **Prover 持有** | 私密 `user_id` | 完整 VC (含签名) |
| **ZK 证明** | `hash(user_id) == public_id` | `verify_signature(VC, issuer_pk)` |
| **Verifier 存储** | 所有成员 ID | 只存 Issuer 公钥 |
| **隐私保护** | 隐藏 user_id | 隐藏所有 VC 内容 |
| **可扩展性** | ❌ 需手动添加成员 | ✅ Issuer 自主签发 |
| **吊销机制** | ❌ 需从 ACL 删除 | ✅ 可实现 CRL/状态列表 |

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

## 🏗️ 构建指南

### 前置要求

- **Rust 1.70+**
- **Keystone SDK**
- **RISC-V toolchain**
- **CMake 3.10+**

### 构建步骤

```bash
# 1. 设置环境变量
export KEYSTONE_SDK_DIR=/path/to/keystone/sdk

# 2. 构建项目
cd examples/zkid-vc
./build.sh

# 3. 运行测试
cd ../../build/examples/zkid-vc
./zkid-vc.ke
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

---

**Built with ❤️ for Decentralized Identity and Zero-Knowledge Proofs**


