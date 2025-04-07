#!/bin/bash

# Default key ID if not provided
DEFAULT_KEY_ID="d329c261a95fd2ee4ee69a7f3910cd550de97885d5ec512304f707268624a408"
DEFAULT_MODE="threshold"

# Create artifacts directory if it doesn't exist
mkdir -p ./core-client/artifacts

# Display usage information
usage() {
  echo "Usage: $0 [OPTIONS]"
  echo
  echo "Options:"
  echo "  -k, --key-id KEY_ID    Specify the key ID (default: $DEFAULT_KEY_ID)"
  echo "  -m, --mode MODE        Specify the mode: 'threshold' or 'centralized' (default: $DEFAULT_MODE)"
  echo "  -h, --help             Display this help message and exit"
  echo
  exit 1
}

# Parse command-line arguments
KEY_ID=$DEFAULT_KEY_ID
MODE=$DEFAULT_MODE

while [[ $# -gt 0 ]]; do
  case $1 in
    -k|--key-id)
      KEY_ID="$2"
      shift 2
      ;;
    -m|--mode)
      MODE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Unknown option: $1"
      usage
      ;;
  esac
done

# Validate mode
if [[ "$MODE" != "threshold" && "$MODE" != "centralized" ]]; then
  echo "Error: Mode must be either 'threshold' or 'centralized'"
  usage
fi

# Set the configuration file based on the mode
if [[ "$MODE" == "threshold" ]]; then
  CONFIG_FILE="core-client/config/client_local_threshold.toml"
else
  CONFIG_FILE="core-client/config/client_local_centralized.toml"
fi

echo "Generating test ciphertexts with:"
echo "  - Key ID: $KEY_ID"
echo "  - Mode: $MODE"
echo "  - Config file: $CONFIG_FILE"
echo

# Generate EBOOL (value 1)
echo "Generating EBOOL ciphertext (value: 1)"
cargo run --bin kms-core-client -- -f $CONFIG_FILE decrypt from-args \
  --to-encrypt 1 \
  --data-type ebool \
  --key-id $KEY_ID \
  --ciphertext-output-path ./core-client/artifacts/output-file-1.bin \
  --precompute-sns

# Generate EUINT4 (value 3)
echo "Generating EUINT4 ciphertext (value: 3)"
cargo run --bin kms-core-client -- -f $CONFIG_FILE decrypt from-args \
  --to-encrypt 3 \
  --data-type euint4 \
  --key-id $KEY_ID \
  --ciphertext-output-path ./core-client/artifacts/output-file-2.bin \
  --precompute-sns

# Generate EUINT8 (value 6)
echo "Generating EUINT8 ciphertext (value: 6)"
cargo run --bin kms-core-client -- -f $CONFIG_FILE decrypt from-args \
  --to-encrypt 6 \
  --data-type euint8 \
  --key-id $KEY_ID \
  --ciphertext-output-path ./core-client/artifacts/output-file-3.bin \
  --precompute-sns

# Generate EUINT16 (value 9)
echo "Generating EUINT16 ciphertext (value: 9)"
cargo run --bin kms-core-client -- -f $CONFIG_FILE decrypt from-args \
  --to-encrypt 9 \
  --data-type euint16 \
  --key-id $KEY_ID \
  --ciphertext-output-path ./core-client/artifacts/output-file-4.bin \
  --precompute-sns

# Generate EUINT32 (value 13)
echo "Generating EUINT32 ciphertext (value: 13)"
cargo run --bin kms-core-client -- -f $CONFIG_FILE decrypt from-args \
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
