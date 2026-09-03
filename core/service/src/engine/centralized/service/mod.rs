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
    use crate::conf::{CoreConfig, init_conf};
    use crate::consts::DEFAULT_MPC_CONTEXT;
    use crate::engine::context::{NodeInfo, SchemeDigests, SoftwareVersion};
    use crate::engine::traits::ContextManager;
    use crate::util::key_setup::store_server_signing_keys;
    use crate::{
        cryptography::signatures::{NodeSigningIdentity, PublicSigKey, gen_sig_keys},
        engine::centralized::central_kms::RealCentralizedKms,
        vault::storage::ram::RamStorage,
    };
    use aes_prng::AesRng;
    use kms_grpc::kms::v1::{MpcContext, NewMpcContextRequest};

    /// This also adds a dummy context
    pub(crate) async fn setup_central_test_kms(
        rng: &mut AesRng,
    ) -> (RealCentralizedKms<RamStorage, RamStorage>, PublicSigKey) {
        let (verf_key, sig_key) = gen_sig_keys(rng);
        let mut public_storage = RamStorage::new();
        let mut private_storage = RamStorage::new();

        // Store the signing key privately and its verification key / address publicly, the
        // same shape `kms-gen-keys` leaves behind in production.
        store_server_signing_keys(&mut public_storage, &mut private_storage, &sig_key)
            .await
            .unwrap();
        let core_config: CoreConfig = init_conf("config/default_centralized.toml").unwrap();
        let (kms, _health_service) = RealCentralizedKms::new(
            core_config,
            public_storage,
            private_storage,
            None,
            None,
            NodeSigningIdentity::ecdsa_only(sig_key),
        )
        .await
        .expect("Could not create KMS");

        let kms_node = NodeInfo {
            mpc_identity: "test_node".to_string(),
            party_id: 1,
            external_url: "http://test_node.com:1234".to_string(),
            ca_cert: None,
            public_storage_url: "http://test_storage.com:1234".to_string(),
            public_storage_prefix: None,
            extra_signer_addresses: vec![],
            scheme_digests: SchemeDigests::from_ecdsa_verification_key(&verf_key),
        };
        kms.context_manager
            .new_mpc_context(tonic::Request::new(NewMpcContextRequest {
                new_context: Some(MpcContext {
                    mpc_nodes: vec![kms_node.try_into().unwrap()],
                    context_id: Some((*DEFAULT_MPC_CONTEXT).into()),
                    software_version: SoftwareVersion::current().unwrap().to_string(),
                    threshold: 0,
                    pcr_values: vec![],
                }),
            }))
            .await
            .unwrap();

        (kms, verf_key)
    }
}
