//******************************************************************************
// Enclave2 - ZK Verifier with ACL (Access Control List)
// Copyright (c) 2025, Keystone TEE
//******************************************************************************

#include "app/eapp_utils.h"
#include "app/syscall.h"
#include "edge/edge_common.h"
#include "../zklib/zklib.h"
#include <string.h>

// OCALL definitions (must match host.cpp)
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

// ACL for GroupX (stored securely inside Enclave2)
// In production, this could be loaded from sealed storage
static const char* ACL_GroupX[] = {
    "39695f33deef797075fa1abb90f6838d58b9689f649236909634ec6f474c90bf",  // Alice: SHA256("alice_secret_12345")
    "7f3a1e9d5c2b8f4e6a3c1d9e7b5f2a8d4c6e1b9f7a3d5c2e8b4f6a1d9c7e5b3f",  // Bob (example)
    "2d5e8b3f6a1c9e7d4b2f5a8c1e6d9b3a7f4c2e5b8d1a6f9c3e7b5a2d8f4c6e1b",  // Charlie (example)
    NULL
};

// Challenge records (stored inside Enclave2)
#define MAX_CHALLENGES 10
struct ChallengeRecord {
    uint64_t nonce;
    char public_id[65];
    uint64_t timestamp;
    int used;
    int active;
};

static struct ChallengeRecord challenges[MAX_CHALLENGES];
static int challenge_count = 0;

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

// Helper function: Get current timestamp (simplified)
static uint64_t get_timestamp() {
    // In production, use a proper time source
    static uint64_t counter = 1000000;
    return counter++;
}

// Helper function: Simple PRNG state (for demo purposes)
static uint64_t prng_state = 0;
static uint64_t prng_counter = 0;

// Helper function: Initialize PRNG with entropy
static void init_prng() {
    // NOTE: rdcycle instruction causes illegal instruction exception in user mode
    // Use software-based entropy sources instead
    uint64_t ts = get_timestamp();
    uint64_t addr = (uint64_t)&prng_state;  // Memory address as entropy
    
    // Mix entropy sources
    prng_state = ts ^ (addr << 16) ^ (addr >> 16);
    prng_state = prng_state * 6364136223846793005ULL + 1442695040888963407ULL;
    
    // Additional mixing with function pointer
    uint64_t func_addr = (uint64_t)&init_prng;
    prng_state ^= func_addr;
    prng_counter = ts;
}

// Helper function: Generate secure random nonce (using enclave-internal PRNG)
static uint64_t generate_nonce() {
    // LCG (Linear Congruential Generator) for demo
    // In production, use a cryptographically secure PRNG
    prng_state = prng_state * 6364136223846793005ULL + 1442695040888963407ULL;
    prng_counter++;
    
    // Mix with counter and timestamp for additional entropy
    uint64_t ts = get_timestamp();
    
    return prng_state ^ prng_counter ^ ts;
}

// Check if public_id is in ACL
static int check_acl(const char* public_id) {
    print_msg("[Enclave2-ACL] Checking ACL...\n");
    
    for (int i = 0; ACL_GroupX[i] != NULL; i++) {
        if (strncmp(ACL_GroupX[i], public_id, 64) == 0) {
            return 1;  // Found in ACL
        }
    }
    
    return 0;  // Not in ACL
}

// Store a new challenge
static int store_challenge(uint64_t nonce, const char* public_id) {
    for (int i = 0; i < MAX_CHALLENGES; i++) {
        if (!challenges[i].active) {
            challenges[i].nonce = nonce;
            strncpy(challenges[i].public_id, public_id, 64);
            challenges[i].timestamp = get_timestamp();
            challenges[i].used = 0;
            challenges[i].active = 1;
            challenge_count++;
            return 0;
        }
    }
    return -1;  // No space
}

// Verify and consume challenge
static int verify_and_consume_challenge(uint64_t nonce, const char* public_id) {
    for (int i = 0; i < MAX_CHALLENGES; i++) {
        if (challenges[i].active &&
            challenges[i].nonce == nonce &&
            strncmp(challenges[i].public_id, public_id, 64) == 0) {
            
            if (challenges[i].used) {
                return -2;  // Already used (replay attack)
            }
            
            // Mark as used (one-time use)
            challenges[i].used = 1;
            challenges[i].active = 0;
            challenge_count--;
            
            return 0;  // Valid
        }
    }
    
    return -1;  // Not found or invalid
}

int main() {
    char buffer[512];
    struct edge_data retdata;
    
    print_msg("=== Enclave2: ZK Verifier with ACL (ZK lib inside Enclave) ===\n");
    
    // ========================================
    // Step 1: Initialize ZK system (Rust+ark-groth16)
    // ========================================
    print_msg("[Enclave2] Initializing ZK system (Rust+ark-groth16)...\n");
    
    if (ZK_Init() != 0) {
        print_msg("[Enclave2] ERROR: ZK initialization failed\n");
        EAPP_RETURN(1);
    }
    
    print_msg("[Enclave2] ZK system initialized successfully\n");
    
    // Initialize PRNG with entropy from CPU cycle counter
    init_prng();
    print_msg("[Enclave2] PRNG initialized (enclave-internal random source)\n");
    
    // Initialize challenge storage
    memset(challenges, 0, sizeof(challenges));
    
    snprintf(buffer, sizeof(buffer), 
             "[Enclave2] ACL loaded: %d authorized public_ids\n", 3);
    print_msg(buffer);
    
    print_msg("[Enclave2] Ready to accept join requests\n");
    
    // ========================================
    // Main verification loop
    // ========================================
    
    // ========================================
    // Phase 1: AUTHORIZATION - Receive join request and check ACL
    // ========================================
    print_msg("\n[Enclave2] === Phase 1: Authorization ===\n");
    
    ocall(OCALL_WAIT_JOIN_REQUEST, NULL, 0, &retdata, sizeof(struct edge_data));
    
    if (retdata.size == 0) {
        print_msg("[Enclave2] No join request received\n");
        EAPP_RETURN(1);
    }
    
    struct JoinRequest join_req;
    memset(&join_req, 0, sizeof(join_req));
    copy_from_shared_safe(&join_req, retdata.offset, retdata.size);
    
    snprintf(buffer, sizeof(buffer), 
             "[Enclave2] Join request received:\n");
    print_msg(buffer);
    snprintf(buffer, sizeof(buffer), 
             "  - public_id: %.16s...\n", join_req.public_id);
    print_msg(buffer);
    snprintf(buffer, sizeof(buffer), 
             "  - group: %s\n", join_req.group_name);
    print_msg(buffer);
    
    // Check ACL
    if (!check_acl(join_req.public_id)) {
        snprintf(buffer, sizeof(buffer), 
                 "[Enclave2] ✗ Authorization FAILED: public_id not in ACL\n");
        print_msg(buffer);
        
        const char* reject_msg = "REJECTED: Not in ACL";
        ocall(OCALL_SEND_RESULT, (void*)reject_msg, strlen(reject_msg), 0, 0);
        
        EAPP_RETURN(1);
    }
    
    snprintf(buffer, sizeof(buffer), 
             "[Enclave2] ✓ Authorization PASSED: public_id is in ACL\n");
    print_msg(buffer);
    
    // ========================================
    // Phase 2: AUTHENTICATION - Generate challenge
    // ========================================
    print_msg("\n[Enclave2] === Phase 2: Authentication ===\n");
    
    uint64_t nonce = generate_nonce();
    
    if (store_challenge(nonce, join_req.public_id) != 0) {
        print_msg("[Enclave2] ERROR: Failed to store challenge\n");
        EAPP_RETURN(1);
    }
    
    snprintf(buffer, sizeof(buffer), 
             "[Enclave2] Challenge generated: nonce = %lu\n", nonce);
    print_msg(buffer);
    
    print_msg("[Enclave2] Sending challenge to prover...\n");
    ocall(OCALL_SEND_CHALLENGE, &nonce, sizeof(nonce), 0, 0);
    
    // ========================================
    // Phase 3: VERIFICATION - Receive and verify proof
    // ========================================
    print_msg("\n[Enclave2] === Phase 3: Verification ===\n");
    
    print_msg("[Enclave2] Waiting for proof...\n");
    ocall(OCALL_WAIT_PROOF, NULL, 0, &retdata, sizeof(struct edge_data));
    
    if (retdata.size == 0) {
        print_msg("[Enclave2] ERROR: No proof received\n");
        EAPP_RETURN(1);
    }
    
    struct ProofSubmission proof_sub;
    memset(&proof_sub, 0, sizeof(proof_sub));
    copy_from_shared_safe(&proof_sub, retdata.offset, retdata.size);
    
    snprintf(buffer, sizeof(buffer), 
             "[Enclave2] Proof received:\n");
    print_msg(buffer);
    snprintf(buffer, sizeof(buffer), 
             "  - public_id: %.16s...\n", proof_sub.public_id);
    print_msg(buffer);
    snprintf(buffer, sizeof(buffer), 
             "  - nonce: %lu\n", proof_sub.nonce);
    print_msg(buffer);
    snprintf(buffer, sizeof(buffer), 
             "  - proof length: %zu chars\n", strlen(proof_sub.proof_hex));
    print_msg(buffer);
    
    // Verify challenge
    int challenge_result = verify_and_consume_challenge(
        proof_sub.nonce, 
        proof_sub.public_id
    );
    
    if (challenge_result == -2) {
        print_msg("[Enclave2] ✗ Challenge verification FAILED: Replay attack detected\n");
        
        const char* reject_msg = "REJECTED: Replay attack";
        ocall(OCALL_SEND_RESULT, (void*)reject_msg, strlen(reject_msg), 0, 0);
        
        EAPP_RETURN(1);
    } else if (challenge_result != 0) {
        print_msg("[Enclave2] ✗ Challenge verification FAILED: Invalid or expired nonce\n");
        
        const char* reject_msg = "REJECTED: Invalid challenge";
        ocall(OCALL_SEND_RESULT, (void*)reject_msg, strlen(reject_msg), 0, 0);
        
        EAPP_RETURN(1);
    }
    
    print_msg("[Enclave2] ✓ Challenge verification PASSED\n");
    
    // Verify ZK proof inside Enclave (Groth16 with ark-groth16)
    print_msg("[Enclave2] Verifying Groth16 ZK proof (ark-groth16)...\n");
    
    int verification_result = ZK_VerifyProof(
        proof_sub.proof_hex,
        proof_sub.public_id,
        proof_sub.nonce
    );
    
    if (verification_result == 1) {
        snprintf(buffer, sizeof(buffer), 
                 "[Enclave2] ✓✓✓ VERIFICATION SUCCESS ✓✓✓\n");
        print_msg(buffer);
        
        snprintf(buffer, sizeof(buffer), 
                 "[Enclave2] Prover with public_id %.16s... is:\n", 
                 proof_sub.public_id);
        print_msg(buffer);
        print_msg("  - Authorized (in ACL)\n");
        print_msg("  - Authenticated (valid ZK proof)\n");
        print_msg("  - Verified (knows the secret user_id)\n");
        
        const char* success_msg = "VALID: Welcome to GroupX";
        ocall(OCALL_SEND_RESULT, (void*)success_msg, strlen(success_msg), 0, 0);
        
        print_msg("[Enclave2] Ready to collaborate with verified member\n");
        
    } else {
        snprintf(buffer, sizeof(buffer), 
                 "[Enclave2] ✗ ZK proof verification FAILED\n");
        print_msg(buffer);
        
        const char* fail_msg = "INVALID: Proof verification failed";
        ocall(OCALL_SEND_RESULT, (void*)fail_msg, strlen(fail_msg), 0, 0);
    }
    
    // ========================================
    // Generate attestation report
    // ========================================
    snprintf(buffer, sizeof(buffer), 
            "Enclave2 ZK-ACL Verifier - GroupX with %d members", 3);
    
    char report_buffer[2048];
    attest_enclave((void*)report_buffer, buffer, strlen(buffer));
    
    print_msg("\n[Enclave2] Verification session completed\n");
    
    EAPP_RETURN(0);
}
