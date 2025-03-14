use alloy::{
    // hex,
    network::{AnyNetwork, EthereumWallet},
    providers::ProviderBuilder,
    sol,
};

use alloy_primitives::{Bytes, U256};
use alloy_provider::Provider;

use alloy_signer_local::PrivateKeySigner;
use anyhow::{anyhow, Result};
use rand::{thread_rng, Rng};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs)]
    #[sol(
        rpc,
        bytecode = "6080604052348015600e575f5ffd5b5061084f8061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610034575f3560e01c806302fd1a64146100385780636cc331d414610054575b5f5ffd5b610052600480360381019061004d91906103a4565b610070565b005b61006e60048036038101906100699190610435565b610168565b005b5f600167ffffffffffffffff81111561008c5761008b6104a6565b5b6040519080825280602002602001820160405280156100bf57816020015b60608152602001906001900390816100aa5790505b50905082828080601f0160208091040260200160405190810160405280939291908181526020018383808284375f81840152601f19601f82011690508083019250505050505050815f81518110610119576101186104d3565b5b6020026020010181905250857f61568d6eb48e62870afffd55499206a54a8f78b04a627e00ed097161fc05d6be86868460405161015893929190610675565b60405180910390a2505050505050565b837f65f08f69e8c1b4ac1d9713dbb80e04c021f8f218464b7c42fc44ba6edeb284a2848484905060405161019d9291906106bb565b60405180910390a25f600167ffffffffffffffff8111156101c1576101c06104a6565b5b6040519080825280602002602001820160405280156101fa57816020015b6101e76102e9565b8152602001906001900390816101df5790505b50905084815f81518110610211576102106104d3565b5b60200260200101515f01818152505083815f81518110610234576102336104d3565b5b6020026020010151602001818152505082828080601f0160208091040260200160405190810160405280939291908181526020018383808284375f81840152601f19601f82011690508083019250505050505050815f8151811061029b5761029a6104d3565b5b602002602001015160400181905250847f025fdc13f195e82af9db316a5f973ccab89cf66d8a2d2f1e6242ad74d48bcf62826040516102da91906107f9565b60405180910390a25050505050565b60405180606001604052805f81526020015f8152602001606081525090565b5f5ffd5b5f5ffd5b5f819050919050565b61032281610310565b811461032c575f5ffd5b50565b5f8135905061033d81610319565b92915050565b5f5ffd5b5f5ffd5b5f5ffd5b5f5f83601f84011261036457610363610343565b5b8235905067ffffffffffffffff81111561038157610380610347565b5b60208301915083600182028301111561039d5761039c61034b565b5b9250929050565b5f5f5f5f5f606086880312156103bd576103bc610308565b5b5f6103ca8882890161032f565b955050602086013567ffffffffffffffff8111156103eb576103ea61030c565b5b6103f78882890161034f565b9450945050604086013567ffffffffffffffff81111561041a5761041961030c565b5b6104268882890161034f565b92509250509295509295909350565b5f5f5f5f6060858703121561044d5761044c610308565b5b5f61045a8782880161032f565b945050602061046b8782880161032f565b935050604085013567ffffffffffffffff81111561048c5761048b61030c565b5b6104988782880161034f565b925092505092959194509250565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52603260045260245ffd5b5f82825260208201905092915050565b828183375f83830152505050565b5f601f19601f8301169050919050565b5f6105398385610500565b9350610546838584610510565b61054f8361051e565b840190509392505050565b5f81519050919050565b5f82825260208201905092915050565b5f819050602082019050919050565b5f81519050919050565b5f82825260208201905092915050565b8281835e5f83830152505050565b5f6105b582610583565b6105bf818561058d565b93506105cf81856020860161059d565b6105d88161051e565b840191505092915050565b5f6105ee83836105ab565b905092915050565b5f602082019050919050565b5f61060c8261055a565b6106168185610564565b93508360208202850161062885610574565b805f5b85811015610663578484038952815161064485826105e3565b945061064f836105f6565b925060208a0199505060018101905061062b565b50829750879550505050505092915050565b5f6040820190508181035f83015261068e81858761052e565b905081810360208301526106a28184610602565b9050949350505050565b6106b581610310565b82525050565b5f6040820190506106ce5f8301856106ac565b6106db60208301846106ac565b9392505050565b5f81519050919050565b5f82825260208201905092915050565b5f819050602082019050919050565b61071481610310565b82525050565b5f606083015f83015161072f5f86018261070b565b506020830151610742602086018261070b565b506040830151848203604086015261075a82826105ab565b9150508091505092915050565b5f610772838361071a565b905092915050565b5f602082019050919050565b5f610790826106e2565b61079a81856106ec565b9350836020820285016107ac856106fc565b805f5b858110156107e757848403895281516107c88582610767565b94506107d38361077a565b925060208a019950506001810190506107af565b50829750879550505050505092915050565b5f6020820190508181035f8301526108118184610786565b90509291505056fea2646970667358221220082b9d923d20e836adb1bb712abff08c22e4d554a284b876f584c9ed65c5c1a764736f6c634300081c0033"
    )]
    #[derive(Debug)]
    MockDecryptionManager,
    "emulation/artifacts/decrypt_test/MockDecryptionManager.abi"
);

const PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

// Path to the output files containing different ciphertexts
const OUTPUT_FILE_PATHS: [&str; 5] = [
    "./core-client/artifacts/output-file-1.bin", // ebool
    "./core-client/artifacts/output-file-2.bin", // euint4
    "./core-client/artifacts/output-file-3.bin", // euint8
    "./core-client/artifacts/output-file-4.bin", // euint16
    "./core-client/artifacts/output-file-5.bin", // euint32
];

// FHE type names corresponding to the output files
const FHE_TYPE_NAMES: [&str; 5] = ["ebool", "euint4", "euint8", "euint16", "euint32"];

// Default key ID (64-character hex string without 0x prefix)
// This matches the format seen in the KMS Core logs
const DEFAULT_KEY_ID: &str = "92cbc7f4279a09607e8985c67bb1f20da1bb9c4d821be0b5b670e5f0c02ed872";

// Precomputed static request IDs as 256-bit hex strings (64 characters)
const STATIC_REQUEST_IDS: [&str; 5] = [
    // 256-bit request ID for ebool (with type encoded in first byte)
    "0100000000000000000000000000000000000000000000000000000000000000",
    // 256-bit request ID for euint4 (with type encoded in first byte)
    "0200000000000000000000000000000000000000000000000000000000000000",
    // 256-bit request ID for euint8 (with type encoded in first byte)
    "0300000000000000000000000000000000000000000000000000000000000000",
    // 256-bit request ID for euint16 (with type encoded in first byte)
    "0400000000000000000000000000000000000000000000000000000000000000",
    // 256-bit request ID for euint32 (with type encoded in first byte)
    "0500000000000000000000000000000000000000000000000000000000000000",
];

/// Parse a hex string into a U256
fn parse_hex_to_u256(hex_str: &str) -> Result<U256> {
    // Remove "0x" prefix if present
    let cleaned_hex = hex_str.trim_start_matches("0x");

    // Validate that it's a hex string
    if !cleaned_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("Invalid hex string: {}", hex_str));
    }

    // Always use the full 32-byte (64 hex chars) format for U256
    let value = if cleaned_hex.len() < 64 {
        // Pad with leading zeros to ensure 32 bytes
        let padded_hex = format!("{:0>64}", cleaned_hex);
        U256::from_str(&format!("0x{}", padded_hex))?
    } else {
        // Normal parsing for 32-byte values
        U256::from_str(&format!("0x{}", cleaned_hex))?
    };

    Ok(value)
}

/// Validate and format a key ID as a 32-byte hex string (64 characters without 0x prefix)
fn validate_key_id(key_id: &str) -> Result<String> {
    // Remove 0x prefix if present
    let clean_key_id = key_id.trim_start_matches("0x");

    // Check if it's a valid hex string
    if clean_key_id.chars().any(|c| !c.is_ascii_hexdigit()) {
        return Err(anyhow!("Key ID must be a hex string"));
    }

    // Check if it's the right length (32 bytes = 64 hex chars)
    if clean_key_id.len() != 64 {
        return Err(anyhow!("Key ID must be exactly 32 bytes (64 hex chars)"));
    }

    Ok(clean_key_id.to_string())
}

/// Print information about a key ID in multiple formats
fn print_key_id_info(label: &str, hex_id: &str) {
    let u256_value = parse_hex_to_u256(&format!("0x{}", hex_id)).unwrap_or_default();

    println!("╔═══════════════════════════════════════════════════════════════════════════");
    println!("║ {} Information", label);
    println!("╠═══════════════════════════════════════════════════════════════════════════");
    println!("║ Hex format (what blockchain expects): {}", hex_id);
    println!("║ U256 numeric value (on-chain): {}", u256_value);
    println!("╚═══════════════════════════════════════════════════════════════════════════");
}

/// Print request ID information (now in hex format)
fn print_request_id_info(request_id_hex: &str, request_id: U256) {
    println!("╔═══════════════════════════════════════════════════════════════════════════");
    println!("║ Request ID Information:");
    println!("╠═══════════════════════════════════════════════════════════════════════════");
    println!("║ Hex (what KMS Core expects): {}", request_id_hex);
    println!("║ U256 value: {}", request_id);
    println!("╚═══════════════════════════════════════════════════════════════════════════");
}

/// Generate a properly formatted handle U256 value for the given FHE type
/// This creates a full 256-bit (32-byte) handle with the FHE type encoded
fn generate_fhe_handle_u256(fhe_type: u8) -> U256 {
    // Create a 32-byte handle
    let mut handle = [0u8; 32];

    // Set the FHE type in the first byte
    handle[0] = fhe_type;

    // Fill the rest with random data to create a unique ID
    thread_rng().fill(&mut handle[1..30]);

    // Keep the last two bytes for special purposes
    // Set the index byte (position 30)
    handle[30] = fhe_type; // Also encode FHE type here for backward compatibility

    // Set the version byte (position 31)
    handle[31] = 1; // Version 1 for new format

    // Convert the 32-byte array to a U256
    U256::from_be_bytes(handle)
}

/// Map FHE type name to its numeric value
fn fhe_type_name_to_value(fhe_type_name: &str) -> u8 {
    match fhe_type_name {
        name if name.starts_with("ebool") => 0,
        name if name.starts_with("euint4") => 1,
        name if name.starts_with("euint8") => 2,
        name if name.starts_with("euint16") => 3,
        name if name.starts_with("euint32") => 4,
        _ => 0, // Default to ebool
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Get command line arguments
    let args: Vec<String> = std::env::args().collect();

    // Check if key ID is provided as argument and validate it
    let key_id_hex = if args.len() > 1 {
        match validate_key_id(&args[1]) {
            Ok(id) => {
                println!("Using key ID from command line: {}", id);
                id
            }
            Err(e) => {
                eprintln!("Error with provided key ID: {}", e);
                eprintln!("Using default key ID: {}", DEFAULT_KEY_ID);
                DEFAULT_KEY_ID.to_string()
            }
        }
    } else {
        println!("No key ID provided. Usage: {} <hex_key_id>", args[0]);
        println!("Using default key ID: {}", DEFAULT_KEY_ID);
        DEFAULT_KEY_ID.to_string()
    };

    // For the contract call, we need the U256 value
    let key_id_u256 = parse_hex_to_u256(&format!("0x{}", key_id_hex))?;

    // Print info about the key ID
    print_key_id_info("Key ID", &key_id_hex);

    let signer: PrivateKeySigner = PRIVATE_KEY.parse().expect("should parse private key");
    let wallet = EthereumWallet::from(signer);

    // Create a provider with the Arbitrum Sepolia network and the wallet.
    let rpc_url = "http://0.0.0.0:8545".parse()?;
    let provider = ProviderBuilder::new()
        .network::<AnyNetwork>()
        .wallet(wallet)
        .on_http(rpc_url);

    // Deploy the contract
    println!("Deploying contract...");
    let contract = MockDecryptionManager::deploy(provider.clone()).await?;
    println!("Contract deployed at: {:#x}", contract.address());

    // Initial delay to let connections stabilize
    tokio::time::sleep(Duration::from_secs(10)).await;

    const EMISSION_INTERVAL: Duration = Duration::from_secs(15);
    println!(
        "Starting event emission loop with {}s interval...",
        EMISSION_INTERVAL.as_secs()
    );

    for ((output_file_path, fhe_type_name), request_id_hex) in OUTPUT_FILE_PATHS
        .iter()
        .zip(FHE_TYPE_NAMES.iter())
        .zip(STATIC_REQUEST_IDS.iter())
    {
        let start_time = std::time::Instant::now();

        // Convert hex request ID to U256 for the contract call
        let request_id = U256::from_str(&format!("0x{}", request_id_hex))?;

        // Print request ID information
        print_request_id_info(request_id_hex, request_id);

        // Load the ciphertext from the output file
        println!("Reading ciphertext from: {}", output_file_path);
        let cipher_text = match fs::read(Path::new(output_file_path)) {
            Ok(data) => {
                println!("Successfully read {} bytes of ciphertext", data.len());
                Bytes::from(data)
            }
            Err(e) => {
                eprintln!("Error reading output file: {}", e);
                println!("Using empty ciphertext as fallback");
                Bytes::new()
            }
        };

        // Generate a proper ctHandle with the correct FHE type byte
        let fhe_type_value = fhe_type_name_to_value(fhe_type_name);
        let ct_handle = generate_fhe_handle_u256(fhe_type_value);

        // Get the handle bytes to verify it's correctly formatted
        let handle_bytes = ct_handle.to_be_bytes::<32>();
        println!(
            "Generated ctHandle with FHE type byte {} at position 30",
            handle_bytes[30]
        );

        // Important: We're using the ct_handle as the request_id because
        // in the contract, request_id becomes ctHandle in the emitted event
        let request_id = ct_handle;

        println!("║ Request ID / ctHandle (hex): {:x}", request_id);
        println!("║ Key ID (hex): {}", key_id_hex);
        println!("║ Ciphertext size: {} bytes", cipher_text.len());
        println!("║ FHE Type: {}", fhe_type_name);
        println!("║ ctHandle FHE type byte: {}", fhe_type_value);
        println!("╚═══════════════════════════════════════════════════════════════════════════");

        // Create a transaction with our request_id (which is also our ctHandle with the FHE type)
        let call = contract.emitEvents(request_id, key_id_u256, cipher_text.clone());

        // Send transaction to emit events with the loaded cipher text
        println!("╔═══════════════════════════════════════════════════════════════════════════");
        println!("║ Emitting Event");
        println!("╠═══════════════════════════════════════════════════════════════════════════");
        println!("║ Request ID / ctHandle (hex): {:x}", request_id);
        println!("║ Key ID (hex): {}", key_id_hex);
        println!("║ Ciphertext size: {} bytes", cipher_text.len());
        println!("║ FHE Type: {}", fhe_type_name);
        println!("║ ctHandle FHE type byte: {}", fhe_type_value);
        println!("╚═══════════════════════════════════════════════════════════════════════════");

        // Create a transaction with explicit gas settings
        let tx = call.send().await?;
        println!("Event transaction sent: {:?}", tx.tx_hash());

        // Calculate remaining time in the interval and sleep if needed
        let elapsed = start_time.elapsed();
        if elapsed < EMISSION_INTERVAL {
            tokio::time::sleep(EMISSION_INTERVAL - elapsed).await;
        }

        // Wait for transaction to be mined
        let receipt = provider.get_transaction_receipt(*tx.tx_hash()).await?;
        if let Some(r) = receipt {
            println!(
                "Transaction mined! Block: {:#?}",
                r.block_number.unwrap_or_default()
            );
        } else {
            println!("Warning: Transaction not mined immediately");
        }
    }
    Ok(())
}
