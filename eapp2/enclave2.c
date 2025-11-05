//******************************************************************************
// Enclave2 - VC Verifier (Trusts Issuer Public Keys)
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
#define OCALL_GET_ISSUER_INFO      10
#define OCALL_GET_TRUSTED_ISSUERS  11

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
// Trusted Issuer Registry (replaces ACL)
// ============================================================================

// List of trusted Issuer public keys
// In production, this could be loaded from sealed storage or managed dynamically
// NOTE: These should be replaced with REAL Ed25519 public keys (32 bytes hex = 64 chars)
// For testing, we generate these dynamically in main()
static char TRUSTED_ISSUER_HR[65];       // HR Department
static char TRUSTED_ISSUER_GOV[65];      // Government Agency
static char TRUSTED_ISSUER_UNI[65];      // University

static const char** TRUSTED_ISSUERS = NULL;
static const char* TRUSTED_ISSUERS_ARRAY[4] = {NULL, NULL, NULL, NULL};

// Map group names to trusted Issuers
static const char* get_trusted_issuer_for_group(const char* group_name) {
    if (strcmp(group_name, "GroupX") == 0) {
        return TRUSTED_ISSUERS_ARRAY[0];  // HR Department
    } else if (strcmp(group_name, "GroupY") == 0) {
        return TRUSTED_ISSUERS_ARRAY[1];  // Government
    } else if (strcmp(group_name, "GroupZ") == 0) {
        return TRUSTED_ISSUERS_ARRAY[2];  // University
    }
    return NULL;  // Unknown group
}

// ============================================================================
// Challenge Management (防重放攻击)
// ============================================================================

#define MAX_CHALLENGES 10
struct ChallengeRecord {
    uint64_t nonce;
    char issuer_pubkey[65];
    uint64_t timestamp;
    int used;
    int active;
};

static struct ChallengeRecord challenges[MAX_CHALLENGES];
static int challenge_count = 0;

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

// Get current timestamp (simplified)
static uint64_t get_timestamp() {
    // In production, use a proper time source
    static uint64_t counter = 1640000000;  // ~2021-12-20
    return counter++;
}

// Simple PRNG state (for demo purposes)
static uint64_t prng_state = 0;
static uint64_t prng_counter = 0;

// Initialize PRNG with entropy
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

// Generate secure random nonce (using enclave-internal PRNG)
static uint64_t generate_nonce() {
    // LCG (Linear Congruential Generator) for demo
    // In production, use a cryptographically secure PRNG
    prng_state = prng_state * 6364136223846793005ULL + 1442695040888963407ULL;
    prng_counter++;
    
    // Mix with counter and timestamp for additional entropy
    uint64_t ts = get_timestamp();
    
    return prng_state ^ prng_counter ^ ts;
}

// Store a new challenge
static int store_challenge(uint64_t nonce, const char* issuer_pubkey) {
    for (int i = 0; i < MAX_CHALLENGES; i++) {
        if (!challenges[i].active) {
            challenges[i].nonce = nonce;
            strncpy(challenges[i].issuer_pubkey, issuer_pubkey, 64);
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
static int verify_and_consume_challenge(uint64_t nonce, const char* issuer_pubkey) {
    for (int i = 0; i < MAX_CHALLENGES; i++) {
        if (challenges[i].active &&
            challenges[i].nonce == nonce &&
            strncmp(challenges[i].issuer_pubkey, issuer_pubkey, 64) == 0) {
            
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

// ============================================================================
// Main Function
// ============================================================================

int main() {
    char buffer[512];
    struct edge_data retdata;
    
    print_msg("=== Enclave2: VC Verifier (ZK lib inside Enclave) ===\n");
    
    // ========================================
    // Step 1: Generate Trusted Issuer Public Keys (deterministic, inside enclave)
    // ========================================
    print_msg("[Enclave2] Generating trusted Issuer public keys (deterministic)...\n");
    
    // Generate HR Department keypair (seed 12345)
    char hr_privkey[65];
    memset(TRUSTED_ISSUER_HR, 0, sizeof(TRUSTED_ISSUER_HR));
    memset(hr_privkey, 0, sizeof(hr_privkey));
    
    if (ZK_GenerateIssuerKeypairDeterministic(
        12345,  // Seed for HR Department (must match Enclave1)
        TRUSTED_ISSUER_HR, sizeof(TRUSTED_ISSUER_HR),
        hr_privkey, sizeof(hr_privkey)
    ) != 0) {
        print_msg("[Enclave2] ERROR: Failed to generate HR Issuer keypair\n");
        EAPP_RETURN(1);
    }
    
    // Generate Government Agency keypair (seed 67890)
    char gov_privkey[65];
    memset(TRUSTED_ISSUER_GOV, 0, sizeof(TRUSTED_ISSUER_GOV));
    memset(gov_privkey, 0, sizeof(gov_privkey));
    
    if (ZK_GenerateIssuerKeypairDeterministic(
        67890,  // Seed for Government
        TRUSTED_ISSUER_GOV, sizeof(TRUSTED_ISSUER_GOV),
        gov_privkey, sizeof(gov_privkey)
    ) != 0) {
        print_msg("[Enclave2] ERROR: Failed to generate Gov Issuer keypair\n");
        EAPP_RETURN(1);
    }
    
    // Generate University keypair (seed 11111)
    char uni_privkey[65];
    memset(TRUSTED_ISSUER_UNI, 0, sizeof(TRUSTED_ISSUER_UNI));
    memset(uni_privkey, 0, sizeof(uni_privkey));
    
    if (ZK_GenerateIssuerKeypairDeterministic(
        11111,  // Seed for University
        TRUSTED_ISSUER_UNI, sizeof(TRUSTED_ISSUER_UNI),
        uni_privkey, sizeof(uni_privkey)
    ) != 0) {
        print_msg("[Enclave2] ERROR: Failed to generate Uni Issuer keypair\n");
        EAPP_RETURN(1);
    }
    
    // Setup TRUSTED_ISSUERS_ARRAY
    TRUSTED_ISSUERS_ARRAY[0] = TRUSTED_ISSUER_HR;
    TRUSTED_ISSUERS_ARRAY[1] = TRUSTED_ISSUER_GOV;
    TRUSTED_ISSUERS_ARRAY[2] = TRUSTED_ISSUER_UNI;
    TRUSTED_ISSUERS_ARRAY[3] = NULL;
    
    print_msg("[Enclave2] ✓ Generated real Ed25519 Issuer public keys\n");
    print_msg("[Enclave2] Trusted Issuer Registry:\n");
    snprintf(buffer, sizeof(buffer), 
             "  - HR Department: %.16s...\n", TRUSTED_ISSUER_HR);
    print_msg(buffer);
    snprintf(buffer, sizeof(buffer), 
             "  - Government: %.16s...\n", TRUSTED_ISSUER_GOV);
    print_msg(buffer);
    snprintf(buffer, sizeof(buffer), 
             "  - University: %.16s...\n", TRUSTED_ISSUER_UNI);
    print_msg(buffer);
    
    print_msg("[Enclave2] Ready to accept join requests\n");
    print_msg("[Enclave2] NOTE: We do NOT maintain an ACL!\n");
    print_msg("           Anyone with a valid VC from a trusted Issuer can join\n");
    
    // ========================================
    // Phase 1: RECEIVE Join Request
    // ========================================
    print_msg("\n[Enclave2] === Phase 1: Join Request ===\n");
    
    ocall(OCALL_WAIT_JOIN_REQUEST, NULL, 0, &retdata, sizeof(struct edge_data));
    
    if (retdata.size == 0) {
        print_msg("[Enclave2] No join request received\n");
        EAPP_RETURN(1);
    }
    
    struct JoinRequest join_req;
    memset(&join_req, 0, sizeof(join_req));
    copy_from_shared_safe(&join_req, retdata.offset, retdata.size);
    
    snprintf(buffer, sizeof(buffer), 
             "[Enclave2] Join request for group: %s\n", join_req.group_name);
    print_msg(buffer);
    
    // Look up trusted Issuer for this group
    const char* issuer_pubkey = get_trusted_issuer_for_group(join_req.group_name);
    
    if (issuer_pubkey == NULL) {
        snprintf(buffer, sizeof(buffer), 
                 "[Enclave2] ✗ ERROR: Unknown group '%s'\n", join_req.group_name);
        print_msg(buffer);
        print_msg("[Enclave2] No need to initialize ZK system (resource optimization)\n");
        
        const char* reject_msg = "REJECTED: Unknown group";
        ocall(OCALL_SEND_RESULT, (void*)reject_msg, strlen(reject_msg), 0, 0);
        
        EAPP_RETURN(1);
    }
    
    snprintf(buffer, sizeof(buffer), 
             "[Enclave2] ✓ Group recognized: %s\n", join_req.group_name);
    print_msg(buffer);
    snprintf(buffer, sizeof(buffer), 
             "[Enclave2] Required Issuer: %.16s...\n", issuer_pubkey);
    print_msg(buffer);
    
    // ========================================
    // Step 2: Initialize ZK system (only after valid join request)
    // ========================================
    print_msg("\n[Enclave2] Initializing ZK system for verification...\n");
    print_msg("[Enclave2] Loading Groth16 setup (Rust+ark-groth16)...\n");
    
    if (ZK_Init() != 0) {
        print_msg("[Enclave2] ERROR: ZK initialization failed\n");
        
        const char* error_msg = "REJECTED: System error";
        ocall(OCALL_SEND_RESULT, (void*)error_msg, strlen(error_msg), 0, 0);
        
        EAPP_RETURN(1);
    }
    
    print_msg("[Enclave2] ✓ ZK system initialized successfully\n");
    
    // Initialize PRNG with entropy
    init_prng();
    print_msg("[Enclave2] ✓ PRNG initialized (enclave-internal random source)\n");
    
    // Initialize challenge storage
    memset(challenges, 0, sizeof(challenges));
    
    // ========================================
    // Phase 2: CHALLENGE - Generate and send challenge
    // ========================================
    print_msg("\n[Enclave2] === Phase 2: Challenge ===\n");
    
    uint64_t nonce = generate_nonce();
    uint64_t current_time = get_timestamp();
    
    if (store_challenge(nonce, issuer_pubkey) != 0) {
        print_msg("[Enclave2] ERROR: Failed to store challenge\n");
        EAPP_RETURN(1);
    }
    
    snprintf(buffer, sizeof(buffer), 
             "[Enclave2] Challenge generated:\n"
             "  - nonce: %lu\n"
             "  - issuer_pubkey: %.16s...\n"
             "  - current_time: %lu\n",
             nonce, issuer_pubkey, current_time);
    print_msg(buffer);
    
    print_msg("[Enclave2] Sending challenge to prover...\n");
    print_msg("[Enclave2] Prover must prove they hold a valid VC from this Issuer\n");
    
    struct Challenge challenge;
    memset(&challenge, 0, sizeof(challenge));
    challenge.nonce = nonce;
    strncpy(challenge.issuer_pubkey, issuer_pubkey, sizeof(challenge.issuer_pubkey) - 1);
    challenge.current_time = current_time;
    
    ocall(OCALL_SEND_CHALLENGE, &challenge, sizeof(challenge), 0, 0);
    
    // ========================================
    // Phase 3: VERIFICATION - Receive and verify proof
    // ========================================
    print_msg("\n[Enclave2] === Phase 3: Verification ===\n");
    
    print_msg("[Enclave2] Waiting for ZK proof...\n");
    ocall(OCALL_WAIT_PROOF, NULL, 0, &retdata, sizeof(struct edge_data));
    
    if (retdata.size == 0) {
        print_msg("[Enclave2] ERROR: No proof received\n");
        EAPP_RETURN(1);
    }
    
    struct ProofSubmission proof_sub;
    memset(&proof_sub, 0, sizeof(proof_sub));
    copy_from_shared_safe(&proof_sub, retdata.offset, retdata.size);
    
    snprintf(buffer, sizeof(buffer), 
             "[Enclave2] Proof received:\n"
             "  - nonce: %lu\n"
             "  - proof length: %zu chars\n",
             proof_sub.nonce, strlen(proof_sub.proof_hex));
    print_msg(buffer);
    
    // Verify challenge
    print_msg("[Enclave2] Verifying challenge nonce...\n");
    
    int challenge_result = verify_and_consume_challenge(
        proof_sub.nonce, 
        issuer_pubkey
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
    print_msg("[Enclave2] Checking if proof demonstrates:\n");
    print_msg("           - VC signature is valid\n");
    print_msg("           - VC is issued by the required Issuer\n");
    print_msg("           - VC has not expired\n");
    print_msg("           - Proof is bound to our challenge\n");
    
    int verification_result = ZK_VerifyVCProof(
        proof_sub.proof_hex,
        issuer_pubkey,
        current_time,
        proof_sub.nonce
    );
    
    if (verification_result == 1) {
        snprintf(buffer, sizeof(buffer), 
                 "[Enclave2] ✓✓✓ VERIFICATION SUCCESS ✓✓✓\n");
        print_msg(buffer);
        
        print_msg("[Enclave2] Prover has demonstrated:\n");
        print_msg("  ✓ Holds a valid Verifiable Credential\n");
        print_msg("  ✓ VC is issued by our trusted Issuer\n");
        print_msg("  ✓ VC has not expired\n");
        print_msg("  ✓ Proof is fresh (bound to challenge)\n");
        print_msg("\n[Enclave2] What we DON'T know (Zero-Knowledge):\n");
        print_msg("  ? Prover's identity (holder_id)\n");
        print_msg("  ? Prover's role or claims\n");
        print_msg("  ? Any other VC details\n");
        print_msg("\n[Enclave2] This is TRUE zero-knowledge verification!\n");
        
        snprintf(buffer, sizeof(buffer), 
                 "VALID: Welcome to %s", join_req.group_name);
        ocall(OCALL_SEND_RESULT, (void*)buffer, strlen(buffer), 0, 0);
        
        print_msg("[Enclave2] Ready to collaborate with verified member\n");
        
    } else {
        snprintf(buffer, sizeof(buffer), 
                 "[Enclave2] ✗ ZK proof verification FAILED\n");
        print_msg(buffer);
        
        print_msg("[Enclave2] Possible reasons:\n");
        print_msg("  - VC signature is invalid\n");
        print_msg("  - VC is from wrong Issuer\n");
        print_msg("  - VC has expired\n");
        print_msg("  - Proof is malformed\n");
        
        const char* fail_msg = "INVALID: Proof verification failed";
        ocall(OCALL_SEND_RESULT, (void*)fail_msg, strlen(fail_msg), 0, 0);
    }
    
    // ========================================
    // Generate attestation report
    // ========================================
    snprintf(buffer, sizeof(buffer), 
            "Enclave2 VC Verifier - Group: %s", join_req.group_name);
    
    char report_buffer[2048];
    attest_enclave((void*)report_buffer, buffer, strlen(buffer));
    
    print_msg("\n[Enclave2] Verification session completed\n");
    
    EAPP_RETURN(0);
}


