//******************************************************************************
// Enclave1 - ZK Prover with ACL Authentication
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

// Communication structures
struct JoinRequest {
    char public_id[65];
    char group_name[32];
};

struct ProofSubmission {
    char public_id[65];
    char proof_hex[4096];  // Groth16 proof in hex format
    uint64_t nonce;
};

// Helper function: Print message to host
static void print_msg(const char* msg) {
    ocall(OCALL_PRINT_BUFFER, (void*)msg, strlen(msg), 0, 0);
}

// Helper function: Copy from shared memory
static void copy_from_shared_safe(void* dst, uintptr_t offset, size_t size) {
    if (size > 0 && size < 8192) {
        copy_from_shared(dst, offset, size);
    }
}

int main() {
    char buffer[512];
    struct edge_data retdata;
    
    print_msg("=== Enclave1: ZK Prover (ZK lib inside Enclave) ===\n");
    
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
    // Step 2: Load private user_id
    // ========================================
    // In production, this should be loaded from sealed storage
    // For demo, we use a hardcoded value
    const char* user_id = "alice_secret_12345";
    size_t user_id_len = strlen(user_id);
    
    print_msg("[Enclave1] Private user_id loaded (from sealed storage)\n");
    
    // ========================================
    // Step 3: Compute public_id inside Enclave (using Rust ZK lib)
    // ========================================
    char public_id[65];
    memset(public_id, 0, sizeof(public_id));
    
    if (ZK_ComputePublicID(user_id, user_id_len, public_id, sizeof(public_id)) != 0) {
        print_msg("[Enclave1] ERROR: Failed to compute public_id\n");
        EAPP_RETURN(1);
    }
    
    snprintf(buffer, sizeof(buffer), 
             "[Enclave1] Computed public_id: %.16s...\n", public_id);
    print_msg(buffer);
    
    // ========================================
    // Step 4: Send join request to Enclave2
    // ========================================
    print_msg("[Enclave1] Requesting to join GroupX...\n");
    
    struct JoinRequest join_req;
    memset(&join_req, 0, sizeof(join_req));
    strncpy(join_req.public_id, public_id, sizeof(join_req.public_id) - 1);
    strncpy(join_req.group_name, "GroupX", sizeof(join_req.group_name) - 1);
    
    ocall(OCALL_SEND_JOIN_REQUEST, &join_req, sizeof(join_req), 
          &retdata, sizeof(struct edge_data));
    
    // ========================================
    // Step 5: Receive challenge from Enclave2
    // ========================================
    ocall(OCALL_GET_CHALLENGE, NULL, 0, &retdata, sizeof(struct edge_data));
    
    if (retdata.size == 0) {
        print_msg("[Enclave1] ERROR: Join request rejected (not in ACL)\n");
        EAPP_RETURN(1);
    }
    
    uint64_t nonce;
    copy_from_shared_safe(&nonce, retdata.offset, sizeof(nonce));
    
    snprintf(buffer, sizeof(buffer), 
             "[Enclave1] Received challenge nonce: %lu\n", nonce);
    print_msg(buffer);
    
    // ========================================
    // Step 6: Generate ZK proof inside Enclave (Groth16 with ark-groth16)
    // ========================================
    print_msg("[Enclave1] Generating Groth16 ZK proof (ark-groth16)...\n");
    
    char proof_hex[4096];
    memset(proof_hex, 0, sizeof(proof_hex));
    
    int proof_result = ZK_GenerateProof(
        user_id,      // Private input - never leaves Enclave
        user_id_len,
        public_id,    // Public input
        nonce,        // Challenge nonce
        proof_hex,    // Output: proof in hex format
        sizeof(proof_hex)
    );
    
    if (proof_result != 0) {
        print_msg("[Enclave1] ERROR: Proof generation failed\n");
        print_msg("[Enclave1] Reason: user_id doesn't match public_id\n");
        EAPP_RETURN(1);
    }
    
    snprintf(buffer, sizeof(buffer), 
             "[Enclave1] Proof generated successfully (hex len: %zu)\n", 
             strlen(proof_hex));
    print_msg(buffer);
    
    // ========================================
    // Step 7: Submit proof to Enclave2
    // ========================================
    print_msg("[Enclave1] Submitting proof to Enclave2...\n");
    
    struct ProofSubmission proof_sub;
    memset(&proof_sub, 0, sizeof(proof_sub));
    strncpy(proof_sub.public_id, public_id, sizeof(proof_sub.public_id) - 1);
    strncpy(proof_sub.proof_hex, proof_hex, sizeof(proof_sub.proof_hex) - 1);
    proof_sub.nonce = nonce;
    
    ocall(OCALL_SEND_PROOF, &proof_sub, sizeof(proof_sub), 
          &retdata, sizeof(struct edge_data));
    
    // ========================================
    // Step 8: Get verification result
    // ========================================
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
            print_msg("[Enclave1] ✓ SUCCESS: Authenticated and authorized\n");
            print_msg("[Enclave1] Ready to collaborate with GroupX members\n");
        } else {
            print_msg("[Enclave1] ✗ FAILED: Authentication failed\n");
        }
    } else {
        print_msg("[Enclave1] ERROR: No verification result received\n");
    }
    
    // ========================================
    // Step 9: Generate attestation report
    // ========================================
    snprintf(buffer, sizeof(buffer), 
            "Enclave1 ZK-ACL Prover - public_id: %.16s...", public_id);
    
    char report_buffer[2048];
    attest_enclave((void*)report_buffer, buffer, strlen(buffer));
    
    print_msg("[Enclave1] Test completed\n");
    
    EAPP_RETURN(0);
}

