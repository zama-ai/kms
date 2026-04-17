use sha2::{Digest, Sha256};

pub fn check_hash(label: &str, bytes: &[u8], expected_hash: &str, warn_only: bool) {
    let computed_hash = hex::encode(Sha256::digest(bytes));

    if computed_hash != expected_hash {
        if warn_only {
            println!(
                "⚠️ Hash mismatch for {label}. Expected: {expected_hash}, Got: {computed_hash}"
            );
        } else {
            panic!("❌ Hash mismatch for {label}. Expected: {expected_hash}, Got: {computed_hash}");
        }
    } else {
        println!("✅ Hash match for {label}: {computed_hash}");
    }
}
