use crate::anyhow_error_and_log;
use crate::client::client_wasm::Client;
use crate::engine::base::hash_sol_struct;
use crate::vault::storage::{
    crypto_material::{
        get_client_signing_key, get_client_verification_key, get_core_verification_key,
    },
    Storage, StorageReader,
};
use alloy_dyn_abi::Eip712Domain;
use alloy_sol_types::SolStruct;
use futures_util::future::{try_join_all, TryFutureExt};
use itertools::Itertools;
use std::collections::HashMap;
use std::fmt;
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;

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

    pub(crate) fn verify_external_signature<T: SolStruct>(
        &self,
        data: &T,
        domain: &Eip712Domain,
        external_sig: &[u8],
    ) -> anyhow::Result<()> {
        if self
            .find_verifying_address(data, domain, external_sig)
            .is_some()
        {
            Ok(())
        } else {
            Err(anyhow::anyhow!("external signature verification failed"))
        }
    }

    pub(crate) fn find_verifying_address<T: SolStruct>(
        &self,
        data: &T,
        domain: &Eip712Domain,
        external_sig: &[u8],
    ) -> Option<alloy_primitives::Address> {
        if external_sig.len() != 65 {
            tracing::error!(
                "external signature has the wrong length, expected 65 got {}",
                external_sig.len()
            );
            return None;
        }
        // Since the signature is 65 bytes long, the last byte is the parity bit
        // so we extract it and use it as the parity.
        let sig = alloy_signer::Signature::from_bytes_and_parity(
            external_sig,
            external_sig[64] & 0x01 == 0,
        );
        let hash = if let Ok(h) = hash_sol_struct(data, domain) {
            h
        } else {
            tracing::error!("Could not hash SolStruct");
            return None;
        };

        let addr = if let Ok(a) = sig.recover_address_from_prehash(&hash) {
            a
        } else {
            tracing::error!("Could not recover address from signature");
            return None;
        };

        self.get_server_addrs()
            .into_values()
            .find(|&verf_key| verf_key == addr)
    }
}
