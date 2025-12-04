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
    use crate::consts::{DEFAULT_MPC_CONTEXT, SAFE_SER_SIZE_LIMIT, SIGNING_KEY_ID};
    use crate::engine::context::{NodeInfo, SoftwareVersion};
    use crate::engine::traits::ContextManager;
    use crate::vault::storage::store_versioned_at_request_id;
    use crate::{
        cryptography::signatures::{gen_sig_keys, PublicSigKey},
        engine::centralized::central_kms::RealCentralizedKms,
        vault::storage::ram::RamStorage,
    };
    use aes_prng::AesRng;
    use kms_grpc::kms::v1::{MpcContext, NewMpcContextRequest};
    use kms_grpc::rpc_types::PrivDataType;
    use tfhe::safe_serialization::safe_serialize;

    /// This also adds a dummy context
    pub(crate) async fn setup_central_test_kms(
        rng: &mut AesRng,
    ) -> (RealCentralizedKms<RamStorage, RamStorage>, PublicSigKey) {
        let (verf_key, sig_key) = gen_sig_keys(rng);
        let public_storage = RamStorage::new();
        let mut private_storage = RamStorage::new();

        // store sig_key in private storage
        store_versioned_at_request_id(
            &mut private_storage,
            &SIGNING_KEY_ID,
            &sig_key,
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();

        let (kms, _health_service) =
            RealCentralizedKms::new(public_storage, private_storage, None, None, sig_key, None)
                .await
                .expect("Could not create KMS");

        let kms_node = NodeInfo {
            mpc_identity: "test_node".to_string(),
            party_id: 1,
            verification_key: Some(verf_key.clone()),
            external_url: "http://test_node.com:1234".to_string(),
            ca_cert: None,
            public_storage_url: "http://test_storage.com:1234".to_string(),
            extra_verification_keys: vec![],
        };
        let mut software_version = Vec::new();
        safe_serialize(
            &SoftwareVersion::current(),
            &mut software_version,
            SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        kms.context_manager
            .new_mpc_context(tonic::Request::new(NewMpcContextRequest {
                new_context: Some(MpcContext {
                    mpc_nodes: vec![kms_node.try_into().unwrap()],
                    context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                    software_version,
                    threshold: 0,
                    pcr_values: vec![],
                }),
            }))
            .await
            .unwrap();

        (kms, verf_key)
    }
}
