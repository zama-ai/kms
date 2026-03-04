use crate::cryptography::signatures::{PrivateSigKey, PublicSigKey};
#[cfg(feature = "non-wasm")]
use aes_prng::AesRng;
use kms_grpc::{ContextId, RequestId};
#[cfg(feature = "non-wasm")]
use rand::SeedableRng;
use std::collections::{HashMap, HashSet};
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use wasm_bindgen::prelude::*;

/// For user decryption, we only use the Addr variant,
/// for everything else, we use the Pk variant.
#[derive(Clone)]
pub enum ServerIdentities {
    Pks(HashMap<ContextId, HashSet<PublicSigKey>>),
    Addrs(HashMap<ContextId, HashSet<alloy_primitives::Address>>),
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
    pub(crate) servers: usize,
    pub(crate) decryption_mode: DecryptionMode,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish()
    }
}

impl Client {
    /// Constructor method to be used for WASM and other situations where data cannot be directly loaded
    /// from a [PublicStorage].
    ///
    /// * `server_pks` - a map mapping a context ID to the total set of public keys that are acceptable for that context.
    /// * `client_address` - the client wallet address.
    /// * `client_sk` - client private key.
    ///   This is optional because sometimes the private signing key is kept
    ///   in a secure location, e.g., hardware wallet or web extension.
    ///   Calling functions that requires `client_sk` when it is None will return an error.
    /// * `params` - the FHE parameters.
    /// * `servers` - the number of servers in the MPC setup. This is used to determine the decryption mode to use.
    /// * `decryption_mode` - the decryption mode to use. Currently available modes are: NoiseFloodSmall and BitDecSmall.
    ///   If set to none, DecryptionMode::default() is used.
    pub fn new(
        server_pks: HashMap<ContextId, HashSet<PublicSigKey>>,
        client_address: alloy_primitives::Address,
        client_sk: Option<PrivateSigKey>,
        params: DKGParams,
        servers: usize,
        decryption_mode: Option<DecryptionMode>,
    ) -> Self {
        let decryption_mode = decryption_mode.unwrap_or_default();
        Client {
            #[cfg(feature = "non-wasm")]
            rng: Box::new(AesRng::from_entropy()), // todo should be argument
            server_identities: ServerIdentities::Pks(server_pks),
            client_address,
            client_sk,
            servers,
            params,
            decryption_mode,
        }
    }

    // todo more substantial change since this messes with validation logic. we need to get context id from request extradata and use this to pick the right key
    pub fn get_server_pks(&self) -> anyhow::Result<&HashMap<ContextId, HashSet<PublicSigKey>>> {
        match &self.server_identities {
            ServerIdentities::Pks(inner) => Ok(inner),
            ServerIdentities::Addrs(_) => {
                Err(anyhow::anyhow!("expected public keys, got addresses"))
            }
        }
    }

    pub fn get_server_addrs(&self) -> HashMap<ContextId, HashSet<alloy_primitives::Address>> {
        match &self.server_identities {
            ServerIdentities::Pks(pks) => pks
                .iter()
                .map(|(i, pk_set)| (*i, pk_set.iter().map(|pk| pk.address()).collect()))
                .collect(),
            ServerIdentities::Addrs(inner) => inner.clone(),
        }
    }

    pub fn get_client_address(&self) -> alloy_primitives::Address {
        self.client_address
    }
}
