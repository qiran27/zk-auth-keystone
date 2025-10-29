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

// One-time initialization for rayon configuration
static INIT: Once = Once::new();

// Configure rayon for single-threaded operation in enclave
fn configure_rayon() {
    INIT.call_once(|| {
        // This must be called before any rayon operations
        std::env::set_var("RAYON_NUM_THREADS", "1");
    });
}

// ZK Circuit: proves knowledge of user_id such that hash(user_id) == public_id
#[derive(Clone)]
struct UserIDCircuit {
    // Private witness
    user_id_hash: Option<Fr>,
    
    // Public inputs
    public_id: Option<Fr>,
    nonce: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for UserIDCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate private input
        let user_id_hash_var = cs.new_witness_variable(|| {
            self.user_id_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        // Allocate public inputs
        let public_id_var = cs.new_input_variable(|| {
            self.public_id.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        let nonce_var = cs.new_input_variable(|| {
            self.nonce.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        // Constraint: user_id_hash == public_id
        cs.enforce_constraint(
            ark_relations::lc!() + user_id_hash_var,
            ark_relations::lc!() + ark_relations::r1cs::Variable::One,
            ark_relations::lc!() + public_id_var,
        )?;
        
        // Nonce is included as public input (no constraint needed)
        let _ = nonce_var;
        
        Ok(())
    }
}

// Helper: hash bytes to field element
fn hash_to_field(data: &[u8]) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    
    // Take first 8 bytes and convert to u64, then to field element
    let val = u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3],
        hash[4], hash[5], hash[6], hash[7],
    ]);
    
    Fr::from(val % 1000000000000u64)
}

// Helper: bytes to hex string
fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// Helper: hex string to bytes
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex)
}

#[no_mangle]
pub extern "C" fn ZK_Init() -> c_int {
    // Configure rayon for single-threaded operation BEFORE any arkworks operations
    configure_rayon();
    
    // Create dummy circuit for setup
    let circuit = UserIDCircuit {
        user_id_hash: None,
        public_id: None,
        nonce: None,
    };
    
    // Use deterministic RNG for reproducible setup
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0u64);
    
    // Run Groth16 setup (single-threaded mode)
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

#[no_mangle]
pub extern "C" fn ZK_ComputePublicID(
    user_id: *const c_char,
    user_id_len: usize,
    public_id: *mut c_char,
    public_id_size: usize,
) -> c_int {
    if user_id.is_null() || public_id.is_null() {
        return -1;
    }
    
    // Convert C string to Rust slice
    let user_id_bytes = unsafe {
        std::slice::from_raw_parts(user_id as *const u8, user_id_len)
    };
    
    // Compute SHA256 hash
    let mut hasher = Sha256::new();
    hasher.update(user_id_bytes);
    let hash = hasher.finalize();
    
    // Convert to hex string
    let hex_str = bytes_to_hex(&hash);
    
    // Check buffer size
    if public_id_size < hex_str.len() + 1 {
        return -1;
    }
    
    // Copy to output buffer
    unsafe {
        let hex_bytes = hex_str.as_bytes();
        std::ptr::copy_nonoverlapping(
            hex_bytes.as_ptr(),
            public_id as *mut u8,
            hex_bytes.len(),
        );
        // Null terminate
        *public_id.add(hex_bytes.len()) = 0;
    }
    
    0
}

#[no_mangle]
pub extern "C" fn ZK_GenerateProof(
    user_id: *const c_char,
    user_id_len: usize,
    public_id: *const c_char,
    nonce: u64,
    proof_out: *mut c_char,
    proof_out_size: usize,
) -> c_int {
    if user_id.is_null() || public_id.is_null() || proof_out.is_null() {
        return -1;
    }
    
    // Get keys
    let keys_guard = match KEYS.lock() {
        Ok(guard) => guard,
        Err(_) => return -1,
    };
    
    let (pk, _) = match keys_guard.as_ref() {
        Some(keys) => keys,
        None => return -1,
    };
    
    // Convert inputs
    let user_id_bytes = unsafe {
        std::slice::from_raw_parts(user_id as *const u8, user_id_len)
    };
    
    let public_id_str = unsafe {
        CStr::from_ptr(public_id).to_str().unwrap_or("")
    };
    
    // Compute SHA256 of user_id (must match ZK_ComputePublicID)
    let mut hasher = Sha256::new();
    hasher.update(user_id_bytes);
    let user_id_hash_bytes = hasher.finalize();
    let user_id_hash_field = hash_to_field(&user_id_hash_bytes);
    
    // Parse public_id (which is hex-encoded SHA256)
    let public_id_bytes = match hex_to_bytes(public_id_str) {
        Ok(bytes) => bytes,
        Err(_) => return -1,
    };
    let public_id_field = hash_to_field(&public_id_bytes);
    
    // Verify hash match: SHA256(user_id) should equal public_id
    if user_id_hash_field != public_id_field {
        return -1;
    }
    
    let nonce_field = Fr::from(nonce);
    
    // Create circuit with witness
    let circuit = UserIDCircuit {
        user_id_hash: Some(user_id_hash_field),
        public_id: Some(public_id_field),
        nonce: Some(nonce_field),
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
    
    // Convert to hex
    let proof_hex = bytes_to_hex(&proof_bytes);
    
    // Check buffer size
    if proof_out_size < proof_hex.len() + 1 {
        return -1;
    }
    
    // Copy to output
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

#[no_mangle]
pub extern "C" fn ZK_VerifyProof(
    proof_hex: *const c_char,
    public_id: *const c_char,
    nonce: u64,
) -> c_int {
    if proof_hex.is_null() || public_id.is_null() {
        return 0;
    }
    
    // Get keys
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
    
    let public_id_str = unsafe {
        CStr::from_ptr(public_id).to_str().unwrap_or("")
    };
    
    // Decode proof
    let proof_bytes = match hex_to_bytes(proof_hex_str) {
        Ok(bytes) => bytes,
        Err(_) => return 0,
    };
    
    let proof = match Proof::<Bn254>::deserialize_compressed(&proof_bytes[..]) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    
    // Compute public inputs
    let public_id_bytes = match hex_to_bytes(public_id_str) {
        Ok(bytes) => bytes,
        Err(_) => return 0,
    };
    let public_id_field = hash_to_field(&public_id_bytes);
    let nonce_field = Fr::from(nonce);
    
    let public_inputs = vec![public_id_field, nonce_field];
    
    // Verify proof
    match Groth16::<Bn254>::verify_with_processed_vk(pvk, &public_inputs, &proof) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn ZK_Cleanup() {
    if let Ok(mut keys) = KEYS.lock() {
        *keys = None;
    }
}
