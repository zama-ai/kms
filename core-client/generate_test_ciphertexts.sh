#!/bin/bash

# Default key ID if not provided
DEFAULT_KEY_ID="cedede762b38dd11f72eed5e48f1cec79539e700"

mkdir -p ./core-client/artifacts

# Parse command-line arguments
KEY_ID=${1:-$DEFAULT_KEY_ID}

echo "Generating test ciphertexts with key ID: $KEY_ID"

# Generate EBOOL (value 1)
echo "Generating EBOOL ciphertext (value: 1)"
cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml decrypt \
  --to-encrypt 1 \
  --data-type ebool \
  --key-id $KEY_ID \
  --ciphertext-output-path ./core-client/artifacts/output-file-1.bin \
  --precompute-sns

# Generate EUINT4 (value 3)
echo "Generating EUINT4 ciphertext (value: 3)"
cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml decrypt \
  --to-encrypt 3 \
  --data-type euint4 \
  --key-id $KEY_ID \
  --ciphertext-output-path ./core-client/artifacts/output-file-2.bin \
  --precompute-sns

# Generate EUINT8 (value 6)
echo "Generating EUINT8 ciphertext (value: 6)"
cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml decrypt \
  --to-encrypt 6 \
  --data-type euint8 \
  --key-id $KEY_ID \
  --ciphertext-output-path ./core-client/artifacts/output-file-3.bin \
  --precompute-sns

# Generate EUINT16 (value 9)
echo "Generating EUINT16 ciphertext (value: 9)"
cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml decrypt \
  --to-encrypt 9 \
  --data-type euint16 \
  --key-id $KEY_ID \
  --ciphertext-output-path ./core-client/artifacts/output-file-4.bin \
  --precompute-sns

# Generate EUINT32 (value 13)
echo "Generating EUINT32 ciphertext (value: 13)"
cargo run --bin kms-core-client -- -f core-client/config/client_local_threshold.toml decrypt \
  --to-encrypt 13 \
  --data-type euint32 \
  --key-id $KEY_ID \
  --ciphertext-output-path ./core-client/artifacts/output-file-5.bin \
  --precompute-sns

echo "All ciphertexts generated successfully!"
echo "Files created:"
echo "  - core-client/artifacts/output-file-1.bin (EBOOL, value 1)"
echo "  - core-client/artifacts/output-file-2.bin (EUINT4, value 3)"
echo "  - core-client/artifacts/output-file-3.bin (EUINT8, value 6)"
echo "  - core-client/artifacts/output-file-4.bin (EUINT16, value 9)"
echo "  - core-client/artifacts/output-file-5.bin (EUINT32, value 13)"
