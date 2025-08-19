use crate::anyhow_error_and_log;
use crate::client::client_wasm::Client;
use crate::cryptography::internal_crypto_types::PublicSigKey;
use crate::cryptography::internal_crypto_types::Signature;
use crate::engine::base::BaseKmsStruct;
use crate::engine::traits::BaseKms;
use crate::vault::storage::{
    crypto_material::{
        get_client_signing_key, get_client_verification_key, get_core_verification_key,
    },
    Storage, StorageReader,
};
use futures_util::future::{try_join_all, TryFutureExt};
use itertools::Itertools;
use std::collections::HashMap;
use std::fmt;
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use threshold_fhe::hashing::DomainSep;

/// Client data type
///
/// Enum which represents the different kinds of public information that can be stored as part of key generation.
/// In practice this means the CRS and different types of public keys.
/// Data of this type is supposed to be readable by anyone on the internet
/// and stored on a medium that _may_ be susceptible to malicious modifications.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ClientDataType {
    SigningKey, // Type of the client's signing key
    VerfKey,    // Type for the servers verification keys
}

impl fmt::Display for ClientDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ClientDataType::SigningKey => write!(f, "SigningKey"),
            ClientDataType::VerfKey => write!(f, "VerfKey"),
        }
    }
}

impl Client {
    /// Helper method to create a client based on a specific type of storage for loading the keys.
    /// Observe that this method is decoupled from the [Client] to ensure wasm compliance as wasm cannot handle
    /// file reading or generic traits.
    ///
    /// * `client_storage` - the storage where the client's keys (for signing and verifying) are stored.
    /// * `pub_storages` - the storages where the public verification keys of the servers are stored. These must be unique.
    /// * `params` - the FHE parameters
    /// * `decryption_mode` - the decryption mode to use. Currently available modes are: NoiseFloodSmall and BitDecSmall.
    ///   If set to none, DecryptionMode::default() is used.
    pub async fn new_client<ClientS: Storage, PubS: StorageReader>(
        client_storage: ClientS,
        pub_storages: HashMap<u32, PubS>,
        params: &DKGParams,
        decryption_mode: Option<DecryptionMode>,
    ) -> anyhow::Result<Client> {
        let pks = try_join_all(pub_storages.iter().map(|(party_id, cur_storage)| {
            get_core_verification_key(cur_storage).map_ok(|pk| (*party_id, pk))
        }))
        .await?
        .into_iter()
        .collect::<HashMap<_, _>>();

        let pks_unique_count = pks.values().unique().count();

        if pks_unique_count != pks.len() {
            return Err(anyhow_error_and_log(format!(
                "Duplicate public keys present in map: {} unique, {} total",
                pks_unique_count,
                pks.len()
            )));
        }

        let client_pk = get_client_verification_key(&client_storage).await?;
        let client_address = alloy_primitives::Address::from_public_key(client_pk.pk());

        let client_sk = get_client_signing_key(&client_storage).await?;

        Ok(Client::new(
            pks,
            client_address,
            Some(client_sk),
            *params,
            decryption_mode,
        ))
    }

    /// Verify the signature received from the server on keys or other data objects.
    /// This verification will pass if one of the public keys can verify the signature.
    pub(crate) fn verify_server_signature<T: serde::Serialize + AsRef<[u8]>>(
        &self,
        dsep: &DomainSep,
        data: &T,
        signature: &[u8],
    ) -> anyhow::Result<()> {
        if self
            .find_verifying_public_key(dsep, data, signature)
            .is_some()
        {
            Ok(())
        } else {
            Err(anyhow::anyhow!("server signature verification failed"))
        }
    }

    /// Verify the signature received from the server on keys or other data objects
    /// and return the public key that verified the signature.
    pub(crate) fn find_verifying_public_key<T: serde::Serialize + AsRef<[u8]>>(
        &self,
        dsep: &DomainSep,
        data: &T,
        signature: &[u8],
    ) -> Option<PublicSigKey> {
        let signature_struct: Signature = match bc2wrap::deserialize(signature) {
            Ok(signature_struct) => signature_struct,
            Err(_) => {
                tracing::error!("Could not deserialize signature");
                return None;
            }
        };

        let server_pks = match self.get_server_pks() {
            Ok(pks) => pks,
            Err(e) => {
                tracing::error!("failed to get server pks ({})", e);
                return None;
            }
        };

        for verf_key in server_pks.values() {
            let ok = BaseKmsStruct::verify_sig(dsep, &data, &signature_struct, verf_key).is_ok();
            if ok {
                return Some(verf_key.clone());
            }
        }
        None
    }
}
