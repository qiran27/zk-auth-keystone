#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   Building Rust ZK Library (ark-groth16) for VC          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "Error: Rust/Cargo not installed"
    echo "Install from: https://rustup.rs/"
    exit 1
fi

echo "Using Rust: $(rustc --version)"
echo ""

# Install cbindgen if not present
if ! command -v cbindgen &> /dev/null; then
    echo "Installing cbindgen for C header generation..."
    cargo install cbindgen
fi

# Install RISC-V target
echo "Ensuring RISC-V target is installed..."
rustup target add riscv64gc-unknown-linux-gnu 2>/dev/null || true

# Generate C header file
echo "Generating C header file..."
cbindgen --config cbindgen.toml --crate zklib-vc --output zklib.h

if [ ! -f "zklib.h" ]; then
    echo "Warning: Header generation failed, creating manual header"
    cat > zklib.h << 'EOF'
#ifndef _ZKLIB_VC_H_
#define _ZKLIB_VC_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the ZK system and generate proving/verifying keys.
 * Must be called before any other ZK operations.
 * 
 * @return 0 on success, -1 on failure
 */
int ZK_Init(void);

/**
 * Generate Ed25519 keypair for Issuer (random).
 * 
 * @param public_key_out Output buffer for hex-encoded public key (65 bytes)
 * @param public_key_size Size of public_key_out buffer
 * @param private_key_out Output buffer for hex-encoded private key (65 bytes)
 * @param private_key_size Size of private_key_out buffer
 * @return 0 on success, -1 on failure
 */
int ZK_GenerateIssuerKeypair(
    char* public_key_out,
    size_t public_key_size,
    char* private_key_out,
    size_t private_key_size
);

/**
 * Generate DETERMINISTIC Ed25519 keypair for Issuer (using seed).
 * This allows both Prover and Verifier to generate the same keypair for testing.
 * 
 * @param seed Deterministic seed for key generation
 * @param public_key_out Output buffer for hex-encoded public key (65 bytes)
 * @param public_key_size Size of public_key_out buffer
 * @param private_key_out Output buffer for hex-encoded private key (65 bytes)
 * @param private_key_size Size of private_key_out buffer
 * @return 0 on success, -1 on failure
 */
int ZK_GenerateIssuerKeypairDeterministic(
    uint64_t seed,
    char* public_key_out,
    size_t public_key_size,
    char* private_key_out,
    size_t private_key_size
);

/**
 * Sign VC with Issuer private key (Ed25519).
 * 
 * @param holder_id Holder identifier
 * @param holder_id_len Length of holder_id
 * @param issuer Issuer identifier
 * @param issuer_len Length of issuer
 * @param issue_date Issue timestamp
 * @param expiry_date Expiry timestamp
 * @param issuer_private_key Hex-encoded issuer private key (64 chars)
 * @param signature_out Output buffer for hex-encoded signature (129 bytes)
 * @param signature_out_size Size of signature_out buffer
 * @return 0 on success, -1 on failure
 */
int ZK_SignVC(
    const char* holder_id,
    size_t holder_id_len,
    const char* issuer,
    size_t issuer_len,
    uint64_t issue_date,
    uint64_t expiry_date,
    const char* issuer_private_key,
    char* signature_out,
    size_t signature_out_size
);

/**
 * Verify VC signature with Issuer public key.
 * 
 * @param holder_id Holder identifier
 * @param holder_id_len Length of holder_id
 * @param issuer Issuer identifier
 * @param issuer_len Length of issuer
 * @param issue_date Issue timestamp
 * @param expiry_date Expiry timestamp
 * @param signature Hex-encoded VC signature
 * @param issuer_public_key Hex-encoded issuer public key
 * @return 1 if valid, 0 if invalid
 */
int ZK_VerifyVCSignature(
    const char* holder_id,
    size_t holder_id_len,
    const char* issuer,
    size_t issuer_len,
    uint64_t issue_date,
    uint64_t expiry_date,
    const char* signature,
    const char* issuer_public_key
);

/**
 * Compute the VC message hash for testing/verification.
 * 
 * @param holder_id Holder identifier
 * @param holder_id_len Length of holder_id
 * @param issuer Issuer identifier
 * @param issuer_len Length of issuer
 * @param issue_date Issue timestamp
 * @param expiry_date Expiry timestamp
 * @param vc_hash_out Output buffer for hex-encoded hash
 * @param vc_hash_out_size Size of output buffer (must be >= 65 bytes)
 * @return 0 on success, -1 on failure
 */
int ZK_ComputeVCHash(
    const char* holder_id,
    size_t holder_id_len,
    const char* issuer,
    size_t issuer_len,
    uint64_t issue_date,
    uint64_t expiry_date,
    char* vc_hash_out,
    size_t vc_hash_out_size
);

/**
 * Generate a zero-knowledge proof for a Verifiable Credential.
 * 
 * @param holder_id Holder identifier
 * @param holder_id_len Length of holder_id
 * @param issuer Issuer identifier
 * @param issuer_len Length of issuer
 * @param issue_date Issue timestamp
 * @param expiry_date Expiry timestamp
 * @param vc_signature Hex-encoded VC signature (128 chars)
 * @param issuer_pubkey Hex-encoded issuer public key (64 chars)
 * @param current_time Current timestamp
 * @param nonce Challenge nonce from verifier
 * @param proof_out Output buffer for hex-encoded proof
 * @param proof_out_size Size of proof_out buffer (must be >= 512 bytes)
 * @return 0 on success, -1 on failure
 */
int ZK_GenerateVCProof(
    const char* holder_id,
    size_t holder_id_len,
    const char* issuer,
    size_t issuer_len,
    uint64_t issue_date,
    uint64_t expiry_date,
    const char* vc_signature,
    const char* issuer_pubkey,
    uint64_t current_time,
    uint64_t nonce,
    char* proof_out,
    size_t proof_out_size
);

/**
 * Verify a zero-knowledge proof for a Verifiable Credential.
 * 
 * @param proof_hex Hex-encoded proof string
 * @param issuer_pubkey Hex-encoded issuer public key
 * @param current_time Current timestamp
 * @param nonce Challenge nonce that was sent to prover
 * @return 1 if proof is valid, 0 if invalid or error
 */
int ZK_VerifyVCProof(
    const char* proof_hex,
    const char* issuer_pubkey,
    uint64_t current_time,
    uint64_t nonce
);

/**
 * Cleanup ZK resources.
 * Should be called when done with ZK operations.
 */
void ZK_Cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // _ZKLIB_VC_H_
EOF
fi

echo "✓ Header generated: zklib.h"
echo ""

# Build for RISC-V with single-threaded rayon
echo "Building static library for RISC-V64 (single-threaded mode)..."
RAYON_NUM_THREADS=1 cargo build --release --target riscv64gc-unknown-linux-gnu

if [ ! -f "target/riscv64gc-unknown-linux-gnu/release/libzklib_vc.a" ]; then
    echo "Error: Build failed"
    exit 1
fi

# Copy to expected location
cp target/riscv64gc-unknown-linux-gnu/release/libzklib_vc.a libzklib.a

SIZE=$(du -h libzklib.a | cut -f1)
echo ""
echo "✓ Library built: libzklib.a ($SIZE)"
echo ""

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              Build completed successfully!               ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "ZK library ready for Enclave integration"
echo ""


