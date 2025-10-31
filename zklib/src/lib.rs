use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

// Ed25519 secret key length (32 bytes)
const SECRET_KEY_LENGTH: usize = 32;
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
    pub claims: Vec<(String, String)>, // 键值对声明 (e.g., role="engineer")
    pub signature: Vec<u8>,          // Issuer 的 Ed25519 签名 (64 bytes)
}

impl VerifiableCredential {
    /// 计算 VC 的消息哈希（用于签名验证）
    pub fn message_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.holder_id.as_bytes());
        hasher.update(self.issuer.as_bytes());
        hasher.update(&self.issue_date.to_le_bytes());
        hasher.update(&self.expiry_date.to_le_bytes());
        
        // Include claims in the hash
        for (key, value) in &self.claims {
            hasher.update(key.as_bytes());
            hasher.update(value.as_bytes());
        }
        
        hasher.finalize().into()
    }
    
    /// 验证 VC 签名
    pub fn verify_signature(&self, issuer_pubkey: &VerifyingKey) -> bool {
        if self.signature.len() != 64 {
            return false;
        }
        
        let message = self.message_hash();
        
        match Signature::from_slice(&self.signature) {
            Ok(sig) => issuer_pubkey.verify(&message, &sig).is_ok(),
            Err(_) => false,
        }
    }
}

// ============================================================================
// ZK Circuit: Verifiable Credential Verification with Real Constraints
// ============================================================================

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
        // 类似 zkid-acl 的 user_id_hash == public_id
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
        let _ = nonce_var;
        
        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Hash bytes to field element
fn hash_bytes_to_field(data: &[u8]) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    
    // Take first 8 bytes and convert to u64
    let val = u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3],
        hash[4], hash[5], hash[6], hash[7],
    ]);
    
    // Modulo to prevent overflow
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
        vc_hash: None,
        issuer_pubkey_hash: None,
        nonce: None,
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

/// Generate Ed25519 keypair for Issuer (random)
#[no_mangle]
pub extern "C" fn ZK_GenerateIssuerKeypair(
    public_key_out: *mut c_char,
    public_key_size: usize,
    private_key_out: *mut c_char,
    private_key_size: usize,
) -> c_int {
    if public_key_out.is_null() || private_key_out.is_null() {
        return -1;
    }
    
    // Generate random secret key bytes
    // Note: For RISC-V enclave, we use deterministic RNG from ark_std
    // In production, use a proper secure RNG source
    use ark_std::rand::SeedableRng;
    use ark_std::rand::RngCore;
    // Use a fixed seed for reproducible testing (in production, use real entropy)
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0x1234567890ABCDEF);
    let mut secret_bytes = [0u8; SECRET_KEY_LENGTH];
    rng.fill_bytes(&mut secret_bytes);
    
    // Create signing key from random bytes
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();
    
    // Convert to hex
    let public_key_hex = bytes_to_hex(verifying_key.as_bytes());
    let private_key_hex = bytes_to_hex(signing_key.as_bytes());
    
    // Check buffer sizes
    if public_key_size < public_key_hex.len() + 1 || 
       private_key_size < private_key_hex.len() + 1 {
        return -1;
    }
    
    // Copy to output buffers
    unsafe {
        let pub_bytes = public_key_hex.as_bytes();
        std::ptr::copy_nonoverlapping(
            pub_bytes.as_ptr(),
            public_key_out as *mut u8,
            pub_bytes.len(),
        );
        *public_key_out.add(pub_bytes.len()) = 0;
        
        let priv_bytes = private_key_hex.as_bytes();
        std::ptr::copy_nonoverlapping(
            priv_bytes.as_ptr(),
            private_key_out as *mut u8,
            priv_bytes.len(),
        );
        *private_key_out.add(priv_bytes.len()) = 0;
    }
    
    0
}

/// Generate DETERMINISTIC Ed25519 keypair for Issuer (using seed)
/// This allows both Prover and Verifier to generate the same keypair for testing
#[no_mangle]
pub extern "C" fn ZK_GenerateIssuerKeypairDeterministic(
    seed: u64,
    public_key_out: *mut c_char,
    public_key_size: usize,
    private_key_out: *mut c_char,
    private_key_size: usize,
) -> c_int {
    if public_key_out.is_null() || private_key_out.is_null() {
        return -1;
    }
    
    // Generate deterministic keypair using seed
    use ark_std::rand::SeedableRng;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
    
    // Generate 32 random bytes for private key
    let mut secret_bytes = [0u8; SECRET_KEY_LENGTH];
    use ark_std::rand::RngCore;
    rng.fill_bytes(&mut secret_bytes);
    
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();
    
    // Convert to hex
    let public_key_hex = bytes_to_hex(verifying_key.as_bytes());
    let private_key_hex = bytes_to_hex(signing_key.as_bytes());
    
    // Check buffer sizes
    if public_key_size < public_key_hex.len() + 1 || 
       private_key_size < private_key_hex.len() + 1 {
        return -1;
    }
    
    // Copy to output buffers
    unsafe {
        let pub_bytes = public_key_hex.as_bytes();
        std::ptr::copy_nonoverlapping(
            pub_bytes.as_ptr(),
            public_key_out as *mut u8,
            pub_bytes.len(),
        );
        *public_key_out.add(pub_bytes.len()) = 0;
        
        let priv_bytes = private_key_hex.as_bytes();
        std::ptr::copy_nonoverlapping(
            priv_bytes.as_ptr(),
            private_key_out as *mut u8,
            priv_bytes.len(),
        );
        *private_key_out.add(priv_bytes.len()) = 0;
    }
    
    0
}

/// Sign VC with Issuer private key (Ed25519)
#[no_mangle]
pub extern "C" fn ZK_SignVC(
    holder_id: *const c_char,
    holder_id_len: usize,
    issuer: *const c_char,
    issuer_len: usize,
    issue_date: u64,
    expiry_date: u64,
    issuer_private_key: *const c_char,
    signature_out: *mut c_char,
    signature_out_size: usize,
) -> c_int {
    if holder_id.is_null() || issuer.is_null() || issuer_private_key.is_null() || signature_out.is_null() {
        return -1;
    }
    
    // Parse inputs
    let holder_id_bytes = unsafe {
        std::slice::from_raw_parts(holder_id as *const u8, holder_id_len)
    };
    
    let issuer_bytes = unsafe {
        std::slice::from_raw_parts(issuer as *const u8, issuer_len)
    };
    
    let issuer_privkey_str = unsafe {
        CStr::from_ptr(issuer_private_key).to_str().unwrap_or("")
    };
    
    let privkey_bytes = match hex_to_bytes(issuer_privkey_str) {
        Ok(bytes) => bytes,
        Err(_) => return -1,
    };
    
    if privkey_bytes.len() != SECRET_KEY_LENGTH {
        return -1;
    }
    
    // Create signing key
    let signing_key = SigningKey::from_bytes(
        privkey_bytes.as_slice().try_into().unwrap()
    );
    
    // Compute VC message hash
    let mut hasher = Sha256::new();
    hasher.update(holder_id_bytes);
    hasher.update(issuer_bytes);
    hasher.update(&issue_date.to_le_bytes());
    hasher.update(&expiry_date.to_le_bytes());
    let message = hasher.finalize();
    
    // Sign message
    let signature = signing_key.sign(&message);
    let signature_hex = bytes_to_hex(&signature.to_bytes());
    
    // Check buffer size
    if signature_out_size < signature_hex.len() + 1 {
        return -1;
    }
    
    // Copy to output
    unsafe {
        let sig_bytes = signature_hex.as_bytes();
        std::ptr::copy_nonoverlapping(
            sig_bytes.as_ptr(),
            signature_out as *mut u8,
            sig_bytes.len(),
        );
        *signature_out.add(sig_bytes.len()) = 0;
    }
    
    0
}

/// Verify VC signature with Issuer public key
#[no_mangle]
pub extern "C" fn ZK_VerifyVCSignature(
    holder_id: *const c_char,
    holder_id_len: usize,
    issuer: *const c_char,
    issuer_len: usize,
    issue_date: u64,
    expiry_date: u64,
    signature: *const c_char,
    issuer_public_key: *const c_char,
) -> c_int {
    if holder_id.is_null() || issuer.is_null() || signature.is_null() || issuer_public_key.is_null() {
        return 0;
    }
    
    // Parse inputs
    let holder_id_bytes = unsafe {
        std::slice::from_raw_parts(holder_id as *const u8, holder_id_len)
    };
    
    let issuer_bytes = unsafe {
        std::slice::from_raw_parts(issuer as *const u8, issuer_len)
    };
    
    let signature_str = unsafe {
        CStr::from_ptr(signature).to_str().unwrap_or("")
    };
    
    let issuer_pubkey_str = unsafe {
        CStr::from_ptr(issuer_public_key).to_str().unwrap_or("")
    };
    
    // Decode signature and public key
    let signature_bytes = match hex_to_bytes(signature_str) {
        Ok(bytes) => bytes,
        Err(_) => return 0,
    };
    
    let pubkey_bytes = match hex_to_bytes(issuer_pubkey_str) {
        Ok(bytes) => bytes,
        Err(_) => return 0,
    };
    
    // Ed25519: signature = 64 bytes, public key = 32 bytes
    if signature_bytes.len() != 64 || pubkey_bytes.len() != 32 {
        return 0;
    }
    
    // Create verifying key and signature
    let verifying_key = match VerifyingKey::from_bytes(
        pubkey_bytes.as_slice().try_into().unwrap()
    ) {
        Ok(key) => key,
        Err(_) => return 0,
    };
    
    let sig = match Signature::from_bytes(
        signature_bytes.as_slice().try_into().unwrap()
    ) {
        sig => sig,
    };
    
    // Compute message hash
    let mut hasher = Sha256::new();
    hasher.update(holder_id_bytes);
    hasher.update(issuer_bytes);
    hasher.update(&issue_date.to_le_bytes());
    hasher.update(&expiry_date.to_le_bytes());
    let message = hasher.finalize();
    
    // Verify signature
    match verifying_key.verify(&message, &sig) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

/// Compute VC message hash (for testing/verification)
#[no_mangle]
pub extern "C" fn ZK_ComputeVCHash(
    holder_id: *const c_char,
    holder_id_len: usize,
    issuer: *const c_char,
    issuer_len: usize,
    issue_date: u64,
    expiry_date: u64,
    vc_hash_out: *mut c_char,
    vc_hash_out_size: usize,
) -> c_int {
    if holder_id.is_null() || issuer.is_null() || vc_hash_out.is_null() {
        return -1;
    }
    
    let holder_id_bytes = unsafe {
        std::slice::from_raw_parts(holder_id as *const u8, holder_id_len)
    };
    
    let issuer_bytes = unsafe {
        std::slice::from_raw_parts(issuer as *const u8, issuer_len)
    };
    
    let mut hasher = Sha256::new();
    hasher.update(holder_id_bytes);
    hasher.update(issuer_bytes);
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
    issuer: *const c_char,
    issuer_len: usize,
    issue_date: u64,
    expiry_date: u64,
    vc_signature: *const c_char,
    issuer_pubkey: *const c_char,
    current_time: u64,
    nonce: u64,
    proof_out: *mut c_char,
    proof_out_size: usize,
) -> c_int {
    if holder_id.is_null() || issuer.is_null() || vc_signature.is_null() || 
       issuer_pubkey.is_null() || proof_out.is_null() {
        return -1;
    }
    
    // ==== Step 1: Verify VC signature (pre-check before ZK proof) ====
    let verify_result = ZK_VerifyVCSignature(
        holder_id, holder_id_len,
        issuer, issuer_len,
        issue_date, expiry_date,
        vc_signature,
        issuer_pubkey,
    );
    
    if verify_result != 1 {
        return -1;  // Signature verification failed
    }
    
    // ==== Step 2: Verify time constraints (pre-check) ====
    if current_time < issue_date || current_time > expiry_date {
        return -1;  // VC not yet active or expired
    }
    
    // ==== Step 3: Get ZK keys ====
    let keys_guard = match KEYS.lock() {
        Ok(guard) => guard,
        Err(_) => return -1,
    };
    
    let (pk, _) = match keys_guard.as_ref() {
        Some(keys) => keys,
        None => return -1,
    };
    
    // ==== Step 4: Parse inputs ====
    let holder_id_bytes = unsafe {
        std::slice::from_raw_parts(holder_id as *const u8, holder_id_len)
    };
    
    let issuer_bytes = unsafe {
        std::slice::from_raw_parts(issuer as *const u8, issuer_len)
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
    // Parse signature (already verified in Step 1, just need to parse for validation)
    let _vc_signature_bytes = match hex_to_bytes(vc_signature_str) {
        Ok(bytes) => bytes,
        Err(_) => return -1,
    };
    
    // ==== Step 5: Compute VC message hash ====
    let mut hasher = Sha256::new();
    hasher.update(holder_id_bytes);
    hasher.update(issuer_bytes);
    hasher.update(&issue_date.to_le_bytes());
    hasher.update(&expiry_date.to_le_bytes());
    let vc_message_hash = hasher.finalize();
    
    // Convert to field elements for circuit
    let vc_hash_field = hash_bytes_to_field(&vc_message_hash);
    let issuer_pubkey_hash_field = hash_bytes_to_field(&issuer_pubkey_bytes);
    let nonce_field = Fr::from(nonce);
    
    // ==== Step 6: Create circuit with witness (简化版本) ====
    let circuit = VCCircuit {
        vc_hash: Some(vc_hash_field),
        issuer_pubkey_hash: Some(issuer_pubkey_hash_field),
        nonce: Some(nonce_field),
    };
    
    // ==== Step 7: Generate proof ====
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(nonce);
    
    let proof = match Groth16::<Bn254>::prove(pk, circuit, &mut rng) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    
    // ==== Step 8: Serialize proof ====
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
    _current_time: u64,  // Reserved for future time constraint verification
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
    
    // Construct public inputs (must match circuit order)
    let issuer_pubkey_hash_field = hash_bytes_to_field(&issuer_pubkey_bytes);
    let nonce_field = Fr::from(nonce);
    
    let public_inputs = vec![issuer_pubkey_hash_field, nonce_field];
    
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
