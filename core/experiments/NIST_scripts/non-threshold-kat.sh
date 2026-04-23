#!/bin/bash

# This script runs the non-threshold NIST KAT coverage for the TFHE flow and the
# ZK PoK flow.
#
# It checks that the TFHE binary:
# - generates deterministic client and server keys whose serialized hashes match
#   the expected reference values,
# - generates ciphertexts for 43 and 4445 whose serialized hashes match the
#   expected reference values,
# - generates addition and multiplication ciphertexts and reports their hashes
#   as warning-only checks because they depend on the FFT implementation and may
#   vary across machines,
# - decrypts all generated ciphertexts and verifies the plaintext results.
#
# It also checks that the ZK PoK binary:
# - generates a CRS whose serialized hash matches the expected reference value,
# - generates a proof whose serialized hash matches the expected reference
#   value,
# - successfully verifies the generated proof against the generated CRS.


echo "Generating and verifying TFHE KAT ..."
cargo run --bin non-threshold-tfhe-kat --release --

echo "Generating and verifying ZK PoK KAT ..."
cargo run --bin non-threshold-zk-pok-kat --release
