#!/bin/bash

# Build script for zkid-vc example
# This script builds the zkid-vc application for Keystone TEE

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR="${SCRIPT_DIR}/../../build"

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║        Building ZK-VC for Keystone TEE                   ║"
echo "║      (Verifiable Credentials + Zero-Knowledge)           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "Error: Rust is not installed"
    echo "Please install Rust from https://rustup.rs/"
    exit 1
fi

echo "Using Rust: $(rustc --version)"
echo ""

# Check if KEYSTONE_SDK_DIR is set
if [ -z "$KEYSTONE_SDK_DIR" ]; then
    echo "Error: KEYSTONE_SDK_DIR is not set"
    echo "Please set it to your Keystone SDK directory:"
    echo "  export KEYSTONE_SDK_DIR=/path/to/keystone/sdk"
    exit 1
fi

echo "Using Keystone SDK: $KEYSTONE_SDK_DIR"
echo ""

# Build Rust ZK library first
echo "Step 1: Building Rust ZK library (arkworks)..."
cd "$SCRIPT_DIR/zklib"
./build-zklib.sh
if [ $? -ne 0 ]; then
    echo "Error: Failed to build Rust ZK library"
    exit 1
fi
echo "✓ Rust ZK library built successfully"
echo ""

# Create build directory if it doesn't exist
if [ ! -d "$BUILD_DIR" ]; then
    echo "Creating build directory: $BUILD_DIR"
    mkdir -p "$BUILD_DIR"
fi

cd "$BUILD_DIR"

echo "Step 2: Running CMake..."
cmake .. \
    -DKEYSTONE_SDK_DIR="$KEYSTONE_SDK_DIR"

echo ""
echo "Step 3: Building zkid-vc package..."
make -j$(nproc) zkid-vc-package

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║            Build completed successfully!                 ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Binaries:"
echo "  - Prover:   $BUILD_DIR/examples/zkid-vc/enclave1"
echo "  - Verifier: $BUILD_DIR/examples/zkid-vc/enclave2"
echo "  - Host:     $BUILD_DIR/examples/zkid-vc/zkid-vc-runner"
echo "  - ZK Lib:   $SCRIPT_DIR/zklib/libzklib.a"
echo ""
echo "To run the test:"
echo "  cd $BUILD_DIR/examples/zkid-vc"
echo "  ./zkid-vc-runner enclave1 enclave2 eyrie-rt loader.bin"
echo "  # or"
echo "  ./zkid-vc.ke"
echo ""

