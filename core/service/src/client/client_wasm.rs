use crate::cryptography::internal_crypto_types::{PrivateSigKey, PublicSigKey};
#[cfg(feature = "non-wasm")]
use aes_prng::AesRng;
#[cfg(feature = "non-wasm")]
use rand::SeedableRng;
use std::collections::HashMap;
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use wasm_bindgen::prelude::*;

/// For user decryption, we only use the Addr variant,
/// for everything else, we use the Pk variant.
#[derive(Clone)]
pub enum ServerIdentities {
    Pks(HashMap<u32, PublicSigKey>),
    Addrs(HashMap<u32, alloy_primitives::Address>),
}

impl ServerIdentities {
    pub fn len(&self) -> usize {
        match &self {
            ServerIdentities::Pks(vec) => vec.len(),
            ServerIdentities::Addrs(vec) => vec.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Core Client
///
/// Simple client to interact with the KMS servers. This can be seen as a proof-of-concept
/// and reference code for validating the KMS. The logic supplied by the client will be
/// distributed across the aggregator/proxy and smart contracts.
#[wasm_bindgen]
pub struct Client {
    // rng is never used when compiled to wasm
    #[cfg(feature = "non-wasm")]
    pub(crate) rng: Box<AesRng>,
    pub(crate) server_identities: ServerIdentities,
    pub(crate) client_address: alloy_primitives::Address,
    pub(crate) client_sk: Option<PrivateSigKey>,
    pub(crate) params: DKGParams,
    pub(crate) decryption_mode: DecryptionMode,
}

impl Client {
    /// Constructor method to be used for WASM and other situations where data cannot be directly loaded
    /// from a [PublicStorage].
    ///
    /// * `server_pks` - a set of tkms core public keys.
    /// * `client_address` - the client wallet address.
    /// * `client_sk` - client private key.
    ///   This is optional because sometimes the private signing key is kept
    ///   in a secure location, e.g., hardware wallet or web extension.
    ///   Calling functions that requires `client_sk` when it is None will return an error.
    /// * `params` - the FHE parameters.
    /// * `decryption_mode` - the decryption mode to use. Currently available modes are: NoiseFloodSmall and BitDecSmall.
    ///   If set to none, DecryptionMode::default() is used.
    pub fn new(
        server_pks: HashMap<u32, PublicSigKey>,
        client_address: alloy_primitives::Address,
        client_sk: Option<PrivateSigKey>,
        params: DKGParams,
        decryption_mode: Option<DecryptionMode>,
    ) -> Self {
        let decryption_mode = decryption_mode.unwrap_or_default();
        Client {
            #[cfg(feature = "non-wasm")]
            rng: Box::new(AesRng::from_entropy()), // todo should be argument
            server_identities: ServerIdentities::Pks(server_pks),
            client_address,
            client_sk,
            params,
            decryption_mode,
        }
    }

    pub fn get_server_pks(&self) -> anyhow::Result<&HashMap<u32, PublicSigKey>> {
        match &self.server_identities {
            ServerIdentities::Pks(inner) => Ok(inner),
            ServerIdentities::Addrs(_) => {
                Err(anyhow::anyhow!("expected public keys, got addresses"))
            }
        }
    }

    pub fn get_server_addrs(&self) -> HashMap<u32, alloy_primitives::Address> {
        match &self.server_identities {
            ServerIdentities::Pks(pks) => pks
                .iter()
                .map(|(i, pk)| (*i, alloy_signer::utils::public_key_to_address(pk.pk())))
                .collect(),
            ServerIdentities::Addrs(inner) => inner.clone(),
        }
    }

    pub fn get_client_address(&self) -> alloy_primitives::Address {
        self.client_address
    }
}
