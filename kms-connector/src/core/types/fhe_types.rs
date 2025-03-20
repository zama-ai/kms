use alloy::{hex, primitives::U256};
use kms_grpc::kms::v1::FheType;
use tracing::{error, info};

/// Get string representation of FHE type
pub fn fhe_type_to_string(fhe_type: i32) -> &'static str {
    match fhe_type {
        t if t == FheType::Ebool as i32 => "EBOOL",
        t if t == FheType::Euint4 as i32 => "EUINT4",
        t if t == FheType::Euint8 as i32 => "EUINT8",
        t if t == FheType::Euint16 as i32 => "EUINT16",
        t if t == FheType::Euint32 as i32 => "EUINT32",
        t if t == FheType::Euint64 as i32 => "EUINT64",
        t if t == FheType::Euint128 as i32 => "EUINT128",
        t if t == FheType::Euint160 as i32 => "EUINT160",
        t if t == FheType::Euint256 as i32 => "EUINT256",
        t if t == FheType::Euint512 as i32 => "EUINT512",
        t if t == FheType::Euint1024 as i32 => "EUINT1024",
        t if t == FheType::Euint2048 as i32 => "EUINT2048",
        _ => "UNKNOWN",
    }
}

/// Extract FHE type from handle bytes
pub fn extract_fhe_type_from_handle(bytes: &[u8]) -> i32 {
    // Format: keccak256(keccak256(bundleCiphertext)+index)[0:29] + index + type + version
    // - Last byte (31): Version (currently 0)
    // - Second-to-last byte (30): FHE Type
    // - Third-to-last byte (29): Handle index
    // - Rest (0-28): Hash data
    if bytes.len() >= 32 {
        let type_byte = bytes[30]; // FHE type is at index 30

        if type_byte >= 12 {
            error!("Unknown FHE type byte: {}, must be less than 12", type_byte);
            return FheType::Ebool as i32;
        }

        match type_byte {
            0 => FheType::Ebool as i32,
            1 => FheType::Euint4 as i32,
            2 => FheType::Euint8 as i32,
            3 => FheType::Euint16 as i32,
            4 => FheType::Euint32 as i32,
            5 => FheType::Euint64 as i32,
            6 => FheType::Euint128 as i32,
            7 => FheType::Euint160 as i32,
            8 => FheType::Euint256 as i32,
            9 => FheType::Euint512 as i32,
            10 => FheType::Euint1024 as i32,
            11 => FheType::Euint2048 as i32,
            _ => unreachable!(), // We checked type_byte < 12 above
        }
    } else {
        error!("Handle too short: {} bytes, expected 32 bytes", bytes.len());
        FheType::Ebool as i32
    }
}

/// Extract FHE type and log result details
pub fn log_and_extract_result<T>(
    _result: &T,
    fhe_type: i32,
    request_id: U256,
    user_addr: Option<&[u8]>,
) where
    T: AsRef<[u8]>,
{
    let fhe_type_str = fhe_type_to_string(fhe_type);

    match user_addr {
        Some(addr) => info!(
            "Reencrypted result type: {} for request {} (user: 0x{})",
            fhe_type_str,
            request_id,
            hex::encode(addr)
        ),
        None => info!(
            "Decrypted result type: {} for request {}",
            fhe_type_str, request_id
        ),
    }
}

/// Convert a string request ID to a valid hex format that KMS Core expects
/// Returns an error if the request ID cannot be properly formatted
pub fn format_request_id(request_id: U256) -> String {
    let bytes = request_id.to_be_bytes::<32>();
    hex::encode(bytes)
}
