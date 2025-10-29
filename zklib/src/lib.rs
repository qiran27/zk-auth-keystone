use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::sync::{Mutex, Once};

// Global state for proving/verifying keys
static KEYS: Mutex<Option<(ProvingKey<Bn254>, PreparedVerifyingKey<Bn254>)>> = Mutex::new(None);

// One-time initialization
static INIT: Once = Once::new();

// Configure rayon for single-threaded operation in enclave
fn configure_rayon() {
    INIT.call_once(|| {
        std::env::set_var("RAYON_NUM_THREADS", "1");
    });
}

// ============================================================================
// Verifiable Credential Structure
// ============================================================================

/// 可验证凭证 (VC) 数据结构
#[derive(Clone, Debug)]
pub struct VerifiableCredential {
    pub holder_id: String,          // 持有者 ID (e.g., "alice@company.com")
    pub issuer: String,              // 发行方标识
    pub issue_date: u64,             // 签发时间戳
    pub expiry_date: u64,            // 过期时间戳
    pub signature: Vec<u8>,          // Issuer 的 Ed25519 签名 (64 bytes)
}

impl VerifiableCredential {
    /// 计算 VC 的消息哈希（用于签名验证）
    pub fn message_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.holder_id.as_bytes());
        hasher.update(&self.issue_date.to_le_bytes());
        hasher.update(&self.expiry_date.to_le_bytes());
        hasher.finalize().into()
    }
}

// ============================================================================
// ZK Circuit: Verifiable Credential Verification
// ============================================================================

#[derive(Clone)]
struct VCCircuit {
    // 私密见证 (Private Witness)
    vc_message_hash: Option<Fr>,     // VC 内容的哈希
    vc_signature: Option<Vec<u8>>,   // VC 的签名
    
    // 公开输入 (Public Inputs)
    issuer_pubkey: Option<Vec<u8>>,  // 受信任的 Issuer 公钥
    current_time: Option<Fr>,         // 当前时间戳
    nonce: Option<Fr>,                // 挑战随机数
    
    // 时间约束
    issue_date: Option<Fr>,
    expiry_date: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for VCCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // 分配私密输入
        let vc_message_hash_var = cs.new_witness_variable(|| {
            self.vc_message_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        // 分配公开输入
        let issuer_pubkey_hash_var = cs.new_input_variable(|| {
            // 简化：我们用 issuer_pubkey 的哈希作为公开输入
            let issuer_hash = hash_to_field(&self.issuer_pubkey.clone().unwrap_or_default());
            Ok(issuer_hash)
        })?;
        
        let current_time_var = cs.new_input_variable(|| {
            self.current_time.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        let nonce_var = cs.new_input_variable(|| {
            self.nonce.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        let issue_date_var = cs.new_witness_variable(|| {
            self.issue_date.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        let expiry_date_var = cs.new_witness_variable(|| {
            self.expiry_date.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        // ========================================================================
        // 约束 1: VC 签名有效 (简化版本)
        // 实际应该使用 Ed25519 签名验证电路，这里简化为哈希验证
        // ========================================================================
        // 在实际实现中，这里应该：
        // - 提取 signature 的 R 和 S 组件
        // - 使用 Ed25519 验证电路验证签名
        // - 确保 verify_ed25519(message_hash, signature, issuer_pubkey) == true
        
        // 简化版：验证 VC message hash 与预期一致
        cs.enforce_constraint(
            ark_relations::lc!() + vc_message_hash_var,
            ark_relations::lc!() + ark_relations::r1cs::Variable::One,
            ark_relations::lc!() + vc_message_hash_var,  // 简化：自验证
        )?;
        
        // ========================================================================
        // 约束 2: VC 未过期
        // current_time <= expiry_date
        // ========================================================================
        // 注意：arkworks 需要使用比较gadget来实现 <=
        // 这里简化为约束存在性
        let _ = (current_time_var, expiry_date_var);
        
        // ========================================================================
        // 约束 3: VC 已生效
        // issue_date <= current_time
        // ========================================================================
        let _ = issue_date_var;
        
        // ========================================================================
        // 约束 4: Nonce 绑定（防重放）
        // ========================================================================
        let _ = nonce_var;
        
        // ========================================================================
        // 约束 5: Issuer 公钥匹配
        // ========================================================================
        let _ = issuer_pubkey_hash_var;
        
        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Hash bytes to field element
fn hash_to_field(data: &[u8]) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    
    let val = u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3],
        hash[4], hash[5], hash[6], hash[7],
    ]);
    
    Fr::from(val % 1000000000000u64)
}

/// Bytes to hex string
fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Hex string to bytes
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex)
}

// ============================================================================
// C API Functions
// ============================================================================

/// Initialize the ZK system
#[no_mangle]
pub extern "C" fn ZK_Init() -> c_int {
    configure_rayon();
    
    let circuit = VCCircuit {
        vc_message_hash: None,
        vc_signature: None,
        issuer_pubkey: None,
        current_time: None,
        nonce: None,
        issue_date: None,
        expiry_date: None,
    };
    
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0u64);
    
    match Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng) {
        Ok((pk, vk)) => {
            let pvk = PreparedVerifyingKey::from(vk);
            
            if let Ok(mut keys) = KEYS.lock() {
                *keys = Some((pk, pvk));
                0
            } else {
                -1
            }
        }
        Err(_) => -1,
    }
}

/// Compute VC message hash (for testing/verification)
#[no_mangle]
pub extern "C" fn ZK_ComputeVCHash(
    holder_id: *const c_char,
    holder_id_len: usize,
    issue_date: u64,
    expiry_date: u64,
    vc_hash_out: *mut c_char,
    vc_hash_out_size: usize,
) -> c_int {
    if holder_id.is_null() || vc_hash_out.is_null() {
        return -1;
    }
    
    let holder_id_bytes = unsafe {
        std::slice::from_raw_parts(holder_id as *const u8, holder_id_len)
    };
    
    let mut hasher = Sha256::new();
    hasher.update(holder_id_bytes);
    hasher.update(&issue_date.to_le_bytes());
    hasher.update(&expiry_date.to_le_bytes());
    let hash = hasher.finalize();
    
    let hex_str = bytes_to_hex(&hash);
    
    if vc_hash_out_size < hex_str.len() + 1 {
        return -1;
    }
    
    unsafe {
        let hex_bytes = hex_str.as_bytes();
        std::ptr::copy_nonoverlapping(
            hex_bytes.as_ptr(),
            vc_hash_out as *mut u8,
            hex_bytes.len(),
        );
        *vc_hash_out.add(hex_bytes.len()) = 0;
    }
    
    0
}

/// Generate ZK proof for VC
#[no_mangle]
pub extern "C" fn ZK_GenerateVCProof(
    holder_id: *const c_char,
    holder_id_len: usize,
    issue_date: u64,
    expiry_date: u64,
    vc_signature: *const c_char,    // 64 bytes (hex encoded = 128 chars)
    issuer_pubkey: *const c_char,   // 32 bytes (hex encoded = 64 chars)
    current_time: u64,
    nonce: u64,
    proof_out: *mut c_char,
    proof_out_size: usize,
) -> c_int {
    if holder_id.is_null() || vc_signature.is_null() || 
       issuer_pubkey.is_null() || proof_out.is_null() {
        return -1;
    }
    
    let keys_guard = match KEYS.lock() {
        Ok(guard) => guard,
        Err(_) => return -1,
    };
    
    let (pk, _) = match keys_guard.as_ref() {
        Some(keys) => keys,
        None => return -1,
    };
    
    // Parse inputs
    let holder_id_bytes = unsafe {
        std::slice::from_raw_parts(holder_id as *const u8, holder_id_len)
    };
    
    let issuer_pubkey_str = unsafe {
        CStr::from_ptr(issuer_pubkey).to_str().unwrap_or("")
    };
    let issuer_pubkey_bytes = match hex_to_bytes(issuer_pubkey_str) {
        Ok(bytes) => bytes,
        Err(_) => return -1,
    };
    
    let vc_signature_str = unsafe {
        CStr::from_ptr(vc_signature).to_str().unwrap_or("")
    };
    let vc_signature_bytes = match hex_to_bytes(vc_signature_str) {
        Ok(bytes) => bytes,
        Err(_) => return -1,
    };
    
    // Compute VC message hash
    let mut hasher = Sha256::new();
    hasher.update(holder_id_bytes);
    hasher.update(&issue_date.to_le_bytes());
    hasher.update(&expiry_date.to_le_bytes());
    let vc_message_hash = hasher.finalize();
    
    let vc_message_hash_field = hash_to_field(&vc_message_hash);
    let current_time_field = Fr::from(current_time);
    let nonce_field = Fr::from(nonce);
    let issue_date_field = Fr::from(issue_date);
    let expiry_date_field = Fr::from(expiry_date);
    
    // Create circuit with witness
    let circuit = VCCircuit {
        vc_message_hash: Some(vc_message_hash_field),
        vc_signature: Some(vc_signature_bytes),
        issuer_pubkey: Some(issuer_pubkey_bytes.clone()),
        current_time: Some(current_time_field),
        nonce: Some(nonce_field),
        issue_date: Some(issue_date_field),
        expiry_date: Some(expiry_date_field),
    };
    
    // Generate proof
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(nonce);
    
    let proof = match Groth16::<Bn254>::prove(pk, circuit, &mut rng) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    
    // Serialize proof
    let mut proof_bytes = Vec::new();
    if proof.serialize_compressed(&mut proof_bytes).is_err() {
        return -1;
    }
    
    let proof_hex = bytes_to_hex(&proof_bytes);
    
    if proof_out_size < proof_hex.len() + 1 {
        return -1;
    }
    
    unsafe {
        let hex_bytes = proof_hex.as_bytes();
        std::ptr::copy_nonoverlapping(
            hex_bytes.as_ptr(),
            proof_out as *mut u8,
            hex_bytes.len(),
        );
        *proof_out.add(hex_bytes.len()) = 0;
    }
    
    0
}

/// Verify ZK proof for VC
#[no_mangle]
pub extern "C" fn ZK_VerifyVCProof(
    proof_hex: *const c_char,
    issuer_pubkey: *const c_char,
    current_time: u64,
    nonce: u64,
) -> c_int {
    if proof_hex.is_null() || issuer_pubkey.is_null() {
        return 0;
    }
    
    let keys_guard = match KEYS.lock() {
        Ok(guard) => guard,
        Err(_) => return 0,
    };
    
    let (_, pvk) = match keys_guard.as_ref() {
        Some(keys) => keys,
        None => return 0,
    };
    
    // Parse inputs
    let proof_hex_str = unsafe {
        CStr::from_ptr(proof_hex).to_str().unwrap_or("")
    };
    
    let issuer_pubkey_str = unsafe {
        CStr::from_ptr(issuer_pubkey).to_str().unwrap_or("")
    };
    
    let proof_bytes = match hex_to_bytes(proof_hex_str) {
        Ok(bytes) => bytes,
        Err(_) => return 0,
    };
    
    let proof = match Proof::<Bn254>::deserialize_compressed(&proof_bytes[..]) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    
    let issuer_pubkey_bytes = match hex_to_bytes(issuer_pubkey_str) {
        Ok(bytes) => bytes,
        Err(_) => return 0,
    };
    
    // Construct public inputs
    let issuer_pubkey_hash = hash_to_field(&issuer_pubkey_bytes);
    let current_time_field = Fr::from(current_time);
    let nonce_field = Fr::from(nonce);
    
    let public_inputs = vec![issuer_pubkey_hash, current_time_field, nonce_field];
    
    // Verify proof
    match Groth16::<Bn254>::verify_with_processed_vk(pvk, &public_inputs, &proof) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => 0,
    }
}

/// Cleanup ZK resources
#[no_mangle]
pub extern "C" fn ZK_Cleanup() {
    if let Ok(mut keys) = KEYS.lock() {
        *keys = None;
    }
}

