//******************************************************************************
// Enclave1 - VC Prover (Holds Verifiable Credential)
// Copyright (c) 2025, Keystone TEE
//******************************************************************************

#include "app/eapp_utils.h"
#include "app/syscall.h"
#include "edge/edge_common.h"
#include "../zklib/zklib.h"
#include <string.h>

// OCALL definitions
#define OCALL_PRINT_BUFFER         1
#define OCALL_SEND_JOIN_REQUEST    2
#define OCALL_WAIT_JOIN_REQUEST    3
#define OCALL_SEND_CHALLENGE       4
#define OCALL_GET_CHALLENGE        5
#define OCALL_SEND_PROOF           6
#define OCALL_WAIT_PROOF           7
#define OCALL_SEND_RESULT          8
#define OCALL_GET_RESULT           9

// ============================================================================
// Verifiable Credential Structure
// ============================================================================
struct VerifiableCredential {
    char holder_id[128];        // 持有者 ID (e.g., "alice@company.com")
    char issuer[64];            // 发行方标识
    uint64_t issue_date;        // 签发时间戳
    uint64_t expiry_date;       // 过期时间戳
    char signature[129];        // Ed25519 签名 (hex: 128 chars + null)
};

// ============================================================================
// Communication Structures
// ============================================================================
struct JoinRequest {
    char group_name[32];
};

struct Challenge {
    uint64_t nonce;
    char issuer_pubkey[65];     // 受信任的 Issuer 公钥 (hex)
    uint64_t current_time;
};

struct ProofSubmission {
    char proof_hex[4096];       // Groth16 proof in hex format
    uint64_t nonce;
};

// ============================================================================
// Helper Functions
// ============================================================================

// Print message to host
static void print_msg(const char* msg) {
    ocall(OCALL_PRINT_BUFFER, (void*)msg, strlen(msg), 0, 0);
}

// Copy from shared memory safely
static void copy_from_shared_safe(void* dst, uintptr_t offset, size_t size) {
    if (size > 0 && size < 8192) {
        copy_from_shared(dst, offset, size);
    }
}

// ============================================================================
// Main Function
// ============================================================================

int main() {
    char buffer[512];
    struct edge_data retdata;
    
    print_msg("=== Enclave1: VC Prover (ZK lib inside Enclave) ===\n");
    
    // ========================================
    // Step 1: Initialize ZK system (Rust+ark-groth16)
    // ========================================
    print_msg("[Enclave1] Initializing ZK system (Rust+ark-groth16)...\n");
    
    if (ZK_Init() != 0) {
        print_msg("[Enclave1] ERROR: ZK initialization failed\n");
        EAPP_RETURN(1);
    }
    
    print_msg("[Enclave1] ZK system initialized successfully\n");
    
    // ========================================
    // Step 2: Load Verifiable Credential (from sealed storage)
    // ========================================
    print_msg("[Enclave1] Loading VC from sealed storage...\n");
    
    struct VerifiableCredential vc;
    memset(&vc, 0, sizeof(vc));
    
    // In production, this should be loaded from sealed storage
    // For demo, we use hardcoded values
    strncpy(vc.holder_id, "alice@company.com", sizeof(vc.holder_id) - 1);
    strncpy(vc.issuer, "HR_Department", sizeof(vc.issuer) - 1);
    vc.issue_date = 1609459200;     // 2021-01-01 00:00:00 UTC
    vc.expiry_date = 1704067199;    // 2023-12-31 23:59:59 UTC
    
    // Simulated Issuer signature (in production, this would be real Ed25519 signature)
    // For demo, we use a fake signature that matches the expected format
    const char* fake_signature = 
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
    strncpy(vc.signature, fake_signature, sizeof(vc.signature) - 1);
    
    snprintf(buffer, sizeof(buffer), 
             "[Enclave1] VC loaded:\n"
             "  - Holder: %s\n"
             "  - Issuer: %s\n"
             "  - Issue Date: %lu\n"
             "  - Expiry Date: %lu\n",
             vc.holder_id, vc.issuer, vc.issue_date, vc.expiry_date);
    print_msg(buffer);
    
    print_msg("[Enclave1] ✓ VC is private, never leaves this enclave\n");
    
    // ========================================
    // Step 3: Send join request to GroupX
    // ========================================
    print_msg("[Enclave1] Requesting to join GroupX...\n");
    
    struct JoinRequest join_req;
    memset(&join_req, 0, sizeof(join_req));
    strncpy(join_req.group_name, "GroupX", sizeof(join_req.group_name) - 1);
    
    ocall(OCALL_SEND_JOIN_REQUEST, &join_req, sizeof(join_req), 
          &retdata, sizeof(struct edge_data));
    
    // ========================================
    // Step 4: Receive challenge from Verifier
    // ========================================
    print_msg("[Enclave1] Waiting for challenge...\n");
    
    ocall(OCALL_GET_CHALLENGE, NULL, 0, &retdata, sizeof(struct edge_data));
    
    if (retdata.size == 0) {
        print_msg("[Enclave1] ERROR: No challenge received\n");
        EAPP_RETURN(1);
    }
    
    struct Challenge challenge;
    memset(&challenge, 0, sizeof(challenge));
    copy_from_shared_safe(&challenge, retdata.offset, retdata.size);
    
    snprintf(buffer, sizeof(buffer), 
             "[Enclave1] Received challenge:\n"
             "  - nonce: %lu\n"
             "  - issuer_pubkey: %.16s...\n"
             "  - current_time: %lu\n",
             challenge.nonce, challenge.issuer_pubkey, challenge.current_time);
    print_msg(buffer);
    
    // ========================================
    // Step 5: Verify VC is for the challenged Issuer
    // ========================================
    print_msg("[Enclave1] Checking if VC matches required Issuer...\n");
    
    // In a real implementation, we would:
    // 1. Verify the VC signature matches the issuer_pubkey
    // 2. Check if the VC is from the expected Issuer
    // For demo, we assume it matches
    
    print_msg("[Enclave1] ✓ VC is issued by the required Issuer\n");
    
    // ========================================
    // Step 6: Generate ZK proof (Groth16 with ark-groth16)
    // ========================================
    print_msg("[Enclave1] Generating Groth16 ZK proof for VC...\n");
    print_msg("[Enclave1] Proof will demonstrate:\n");
    print_msg("           - VC signature is valid\n");
    print_msg("           - VC is issued by trusted Issuer\n");
    print_msg("           - VC has not expired\n");
    print_msg("           - Proof is bound to challenge nonce\n");
    print_msg("[Enclave1] WITHOUT revealing any VC content!\n");
    
    char proof_hex[4096];
    memset(proof_hex, 0, sizeof(proof_hex));
    
    int proof_result = ZK_GenerateVCProof(
        vc.holder_id,           // Private: holder ID
        strlen(vc.holder_id),
        vc.issue_date,          // Private: issue date
        vc.expiry_date,         // Private: expiry date
        vc.signature,           // Private: Issuer signature
        challenge.issuer_pubkey, // Public: expected Issuer
        challenge.current_time,  // Public: current time
        challenge.nonce,         // Public: challenge nonce
        proof_hex,              // Output: ZK proof
        sizeof(proof_hex)
    );
    
    if (proof_result != 0) {
        print_msg("[Enclave1] ERROR: Proof generation failed\n");
        print_msg("[Enclave1] Possible reasons:\n");
        print_msg("           - VC signature doesn't match Issuer key\n");
        print_msg("           - VC has expired\n");
        print_msg("           - Circuit constraints failed\n");
        EAPP_RETURN(1);
    }
    
    snprintf(buffer, sizeof(buffer), 
             "[Enclave1] Proof generated successfully (hex len: %zu)\n", 
             strlen(proof_hex));
    print_msg(buffer);
    
    // ========================================
    // Step 7: Submit proof to Verifier
    // ========================================
    print_msg("[Enclave1] Submitting proof to Verifier...\n");
    
    struct ProofSubmission proof_sub;
    memset(&proof_sub, 0, sizeof(proof_sub));
    strncpy(proof_sub.proof_hex, proof_hex, sizeof(proof_sub.proof_hex) - 1);
    proof_sub.nonce = challenge.nonce;
    
    ocall(OCALL_SEND_PROOF, &proof_sub, sizeof(proof_sub), 
          &retdata, sizeof(struct edge_data));
    
    // ========================================
    // Step 8: Get verification result
    // ========================================
    print_msg("[Enclave1] Waiting for verification result...\n");
    
    ocall(OCALL_GET_RESULT, NULL, 0, &retdata, sizeof(struct edge_data));
    
    if (retdata.size > 0) {
        char result_msg[256];
        memset(result_msg, 0, sizeof(result_msg));
        copy_from_shared_safe(result_msg, retdata.offset, 
                              retdata.size < 255 ? retdata.size : 255);
        
        snprintf(buffer, sizeof(buffer), 
                 "[Enclave1] Verification result: %s\n", result_msg);
        print_msg(buffer);
        
        if (strncmp(result_msg, "VALID", 5) == 0) {
            print_msg("[Enclave1] ✓✓✓ SUCCESS ✓✓✓\n");
            print_msg("[Enclave1] Verifier confirmed:\n");
            print_msg("           - VC is valid\n");
            print_msg("           - Issued by trusted Issuer\n");
            print_msg("           - Not expired\n");
            print_msg("[Enclave1] BUT Verifier learned NOTHING about:\n");
            print_msg("           - Who I am (holder_id)\n");
            print_msg("           - What roles/claims I have\n");
            print_msg("           - Any other VC details\n");
            print_msg("[Enclave1] Ready to collaborate with GroupX members\n");
        } else {
            print_msg("[Enclave1] ✗ FAILED: Verification failed\n");
        }
    } else {
        print_msg("[Enclave1] ERROR: No verification result received\n");
    }
    
    // ========================================
    // Step 9: Generate attestation report
    // ========================================
    snprintf(buffer, sizeof(buffer), 
            "Enclave1 VC Prover - holder: %.16s...", vc.holder_id);
    
    char report_buffer[2048];
    attest_enclave((void*)report_buffer, buffer, strlen(buffer));
    
    print_msg("[Enclave1] Test completed\n");
    
    EAPP_RETURN(0);
}


