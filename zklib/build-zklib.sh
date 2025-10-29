#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║    Building Rust ZK Library (ark-groth16) for RISC-V     ║"
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
cbindgen --config cbindgen.toml --crate zklib --output zklib.h

if [ ! -f "zklib.h" ]; then
    echo "Warning: Header generation failed, creating manual header"
    cat > zklib.h << 'EOF'
#ifndef _ZKLIB_H_
#define _ZKLIB_H_

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
 * Compute the public ID from a user ID.
 * public_id = SHA256(user_id)
 * 
 * @param user_id User identifier (arbitrary bytes)
 * @param user_id_len Length of user_id
 * @param public_id Output buffer for hex-encoded public ID
 * @param public_id_size Size of public_id buffer (must be >= 65 bytes)
 * @return 0 on success, -1 on failure
 */
int ZK_ComputePublicID(
    const char* user_id, 
    size_t user_id_len, 
    char* public_id, 
    size_t public_id_size
);

/**
 * Generate a zero-knowledge proof that the prover knows user_id
 * such that SHA256(user_id) == public_id, without revealing user_id.
 * 
 * @param user_id Secret user identifier
 * @param user_id_len Length of user_id
 * @param public_id Hex-encoded public ID to prove knowledge of
 * @param nonce Challenge nonce from verifier (for replay protection)
 * @param proof_out Output buffer for hex-encoded proof
 * @param proof_out_size Size of proof_out buffer (must be >= 512 bytes)
 * @return 0 on success, -1 on failure
 */
int ZK_GenerateProof(
    const char* user_id,
    size_t user_id_len,
    const char* public_id,
    uint64_t nonce,
    char* proof_out,
    size_t proof_out_size
);

/**
 * Verify a zero-knowledge proof.
 * 
 * @param proof_hex Hex-encoded proof string
 * @param public_id Hex-encoded public ID being claimed
 * @param nonce Challenge nonce that was sent to prover
 * @return 1 if proof is valid, 0 if invalid or error
 */
int ZK_VerifyProof(
    const char* proof_hex,
    const char* public_id,
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

#endif // _ZKLIB_H_
EOF
fi

echo "✓ Header generated: zklib.h"
echo ""

# Build for RISC-V with single-threaded rayon
echo "Building static library for RISC-V64 (single-threaded mode)..."
RAYON_NUM_THREADS=1 cargo build --release --target riscv64gc-unknown-linux-gnu

if [ ! -f "target/riscv64gc-unknown-linux-gnu/release/libzklib.a" ]; then
    echo "Error: Build failed"
    exit 1
fi

# Copy to expected location
cp target/riscv64gc-unknown-linux-gnu/release/libzklib.a libzklib.a

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