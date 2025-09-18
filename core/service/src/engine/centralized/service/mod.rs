//
// Module Structure for Service Components
//
// - crs_gen.rs: Common Reference String generation implementation
// - decryption.rs: Decryption service implementation
// - endpoint.rs: Service endpoint and API handlers
// - key_gen.rs: Key generation implementation

// Module components
mod crs_gen;
mod decryption;
mod initiator;
mod key_gen;
mod preprocessing;

// Re-export all the service components
pub use crs_gen::*;
pub use decryption::*;
pub use initiator::*;
pub use key_gen::*;
pub use preprocessing::*;

#[cfg(test)]
mod tests {
    use crate::{
        cryptography::internal_crypto_types::gen_sig_keys,
        engine::centralized::central_kms::RealCentralizedKms,
        vault::storage::{file::FileStorage, StorageType},
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use std::path::Path;

    pub(crate) async fn setup_central_test_kms(
        path: Option<&Path>,
    ) -> RealCentralizedKms<FileStorage, FileStorage> {
        let mut rng = AesRng::seed_from_u64(39);
        let (_verf_key, sig_key) = gen_sig_keys(&mut rng);
        let pub_storage = FileStorage::new(path, StorageType::PUB, None).unwrap();
        let (kms, _health_service) = RealCentralizedKms::new(
            pub_storage.clone(),
            FileStorage::new(path, StorageType::PRIV, None).unwrap(),
            None,
            None,
            sig_key,
            None,
        )
        .await
        .expect("Could not create KMS");
        kms
    }
}
