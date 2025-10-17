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
        cryptography::internal_crypto_types::{gen_sig_keys, PublicSigKey},
        engine::centralized::central_kms::RealCentralizedKms,
        vault::storage::ram::RamStorage,
    };
    use aes_prng::AesRng;

    pub(crate) async fn setup_central_test_kms(
        rng: &mut AesRng,
    ) -> (RealCentralizedKms<RamStorage, RamStorage>, PublicSigKey) {
        let (verf_key, sig_key) = gen_sig_keys(rng);
        let public_storage = RamStorage::new();
        let private_storage = RamStorage::new();
        let (kms, _health_service) =
            RealCentralizedKms::new(public_storage, private_storage, None, None, sig_key, None)
                .await
                .expect("Could not create KMS");
        (kms, verf_key)
    }
}
