use crate::cryptography::signatures::{PrivateSigKey, PublicSigKey};
#[cfg(feature = "non-wasm")]
use aes_prng::AesRng;
#[cfg(feature = "non-wasm")]
use rand::SeedableRng;
use std::collections::HashMap;
use threshold_execution::endpoints::decryption::DecryptionMode;
use threshold_execution::tfhe_internals::parameters::DKGParams;
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

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish()
    }
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
        Self::from_identities(
            ServerIdentities::Pks(server_pks),
            client_address,
            client_sk,
            params,
            decryption_mode,
        )
    }

    /// The one place a [Client] is assembled from parts: every public constructor differs only in
    /// which identity variant it holds and which fields it fixes.
    pub(crate) fn from_identities(
        server_identities: ServerIdentities,
        client_address: alloy_primitives::Address,
        client_sk: Option<PrivateSigKey>,
        params: DKGParams,
        decryption_mode: Option<DecryptionMode>,
    ) -> Self {
        Client {
            #[cfg(feature = "non-wasm")]
            rng: Box::new(AesRng::from_entropy()), // todo should be argument
            server_identities,
            client_address,
            client_sk,
            params,
            decryption_mode: decryption_mode.unwrap_or_default(),
        }
    }

    /// Constructor for the Solana user-decryption path.
    ///
    /// Additive: it exists because a Solana client has no EVM wallet address to supply, and the
    /// recipient it de-signcrypts under is its 32-byte ed25519 key, passed per call. The
    /// `client_address` field is therefore zero and unused on this path — never a derivative of the
    /// wallet key, which is what a truncating derivation would make it.
    ///
    /// * `server_addrs` - the registered KMS node signer addresses, keyed by party id — on Solana,
    ///   the host program's KMS-context signer set, which the caller holds as its own trusted
    ///   configuration or reads on chain. This set is the trust anchor of response verification: a
    ///   key carried inside a response acts only under its binding to one of these addresses, so
    ///   nothing read out of a response may populate it — a response must never supply the trust
    ///   it is then verified against. Addresses rather than full keys, because an address is what
    ///   the on-chain KMS context records; a caller holding full keys passes the addresses they
    ///   determine, as [`Self::get_server_addrs`] derives them.
    /// * `params` - the FHE parameters.
    /// * `decryption_mode` - as in [`Self::new`].
    pub fn new_solana(
        server_addrs: HashMap<u32, alloy_primitives::Address>,
        params: DKGParams,
        decryption_mode: Option<DecryptionMode>,
    ) -> Self {
        Self::from_identities(
            ServerIdentities::Addrs(server_addrs),
            alloy_primitives::Address::ZERO,
            None,
            params,
            decryption_mode,
        )
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
            ServerIdentities::Pks(pks) => pks.iter().map(|(i, pk)| (*i, pk.address())).collect(),
            ServerIdentities::Addrs(inner) => inner.clone(),
        }
    }

    pub fn get_client_address(&self) -> alloy_primitives::Address {
        self.client_address
    }
}
