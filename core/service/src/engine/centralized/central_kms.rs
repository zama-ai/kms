use crate::anyhow_error_and_log;
#[cfg(feature = "non-wasm")]
use crate::backup::operator::RecoveryValidationMaterial;
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::consts::{DEC_CAPACITY, MIN_DEC_CACHE};
#[cfg(feature = "non-wasm")]
use crate::cryptography::attestation::SecurityModuleProxy;
use crate::cryptography::decompression;
#[cfg(feature = "non-wasm")]
use crate::cryptography::encryption::UnifiedPublicEncKey;
use crate::cryptography::signatures::{PrivateSigKey, PublicSigKey, Signature};
#[cfg(feature = "non-wasm")]
use crate::cryptography::signcryption::SigncryptFHEPlaintext;
use crate::cryptography::signcryption::UnifiedSigncryptionKey;
#[cfg(feature = "non-wasm")]
use crate::engine::backup_operator::RealBackupOperator;
use crate::engine::base::CrsGenMetadata;
use crate::engine::base::{BaseKmsStruct, KmsFheKeyHandles};
use crate::engine::base::{KeyGenMetadata, PubDecCallValues, UserDecryptCallValues};
#[cfg(feature = "non-wasm")]
use crate::engine::context_manager::RealContextManager;
#[cfg(feature = "non-wasm")]
use crate::engine::traits::{BackupOperator, ContextManager};
use crate::engine::traits::{BaseKms, Kms};
use crate::engine::validation::DSEP_USER_DECRYPTION;
use crate::engine::Shutdown;
#[cfg(feature = "non-wasm")]
use crate::grpc::metastore_status_service::CustodianMetaStore;
#[cfg(feature = "non-wasm")]
use crate::util::key_setup::FhePublicKey;
use crate::util::meta_store::MetaStore;

use crate::util::rate_limiter::{RateLimiter, RateLimiterConfig};
use crate::vault::storage::{
    crypto_material::CentralizedCryptoMaterialStorage, read_all_data_versioned,
    read_pk_at_request_id,
};
#[cfg(feature = "non-wasm")]
use crate::vault::{storage::Storage, Vault};
use aes_prng::AesRng;
#[cfg(feature = "non-wasm")]
use kms_grpc::kms::v1::TypedSigncryptedCiphertext;
#[cfg(feature = "non-wasm")]
use kms_grpc::kms::v1::UserDecryptionResponsePayload;
use kms_grpc::kms::v1::{CiphertextFormat, TypedCiphertext, TypedPlaintext};
#[cfg(feature = "non-wasm")]
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
#[cfg(feature = "non-wasm")]
use kms_grpc::rpc_types::KMSType;
use kms_grpc::rpc_types::PrivDataType;
#[cfg(feature = "non-wasm")]
use kms_grpc::rpc_types::PubDataType;
#[cfg(feature = "non-wasm")]
use kms_grpc::RequestId;
use rand::{CryptoRng, Rng, RngCore};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::{fmt, panic};
use tfhe::integer::compression_keys::DecompressionKey;
use tfhe::prelude::FheDecrypt;
use tfhe::safe_serialization::safe_deserialize;
#[cfg(feature = "non-wasm")]
use tfhe::zk::CompactPkeCrs;
#[cfg(feature = "non-wasm")]
use tfhe::Seed;
use tfhe::{
    ClientKey, FheBool, FheUint1024, FheUint128, FheUint16, FheUint160, FheUint2048, FheUint256,
    FheUint32, FheUint4, FheUint512, FheUint64, FheUint8, FheUint80,
};
use tfhe::{FheTypes, ServerKey};
#[cfg(feature = "non-wasm")]
use threshold_fhe::execution::keyset_config::KeySetCompressionConfig;
#[cfg(feature = "non-wasm")]
use threshold_fhe::execution::keyset_config::StandardKeySetConfig;
#[cfg(feature = "non-wasm")]
use threshold_fhe::execution::runtime::party::Role;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
#[cfg(feature = "non-wasm")]
use threshold_fhe::execution::tfhe_internals::public_keysets::FhePubKeySet;
#[cfg(feature = "non-wasm")]
use threshold_fhe::execution::zk::ceremony::public_parameters_by_trusted_setup;
use threshold_fhe::hashing::DomainSep;
#[cfg(feature = "non-wasm")]
use threshold_fhe::thread_handles::ThreadHandleGroup;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
#[cfg(feature = "non-wasm")]
use tokio_util::task::TaskTracker;
use tonic_health::pb::health_server::{Health, HealthServer};
use tonic_health::server::HealthReporter;

#[cfg(feature = "non-wasm")]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn async_generate_fhe_keys<PubS, PrivS>(
    sk: &PrivateSigKey,
    storage: CentralizedCryptoMaterialStorage<PubS, PrivS>,
    params: DKGParams,
    keyset_config: StandardKeySetConfig,
    compression_key_id: Option<RequestId>,
    key_id: &RequestId,
    preproc_id: &RequestId,
    seed: Option<Seed>,
    eip712_domain: alloy_sol_types::Eip712Domain,
) -> anyhow::Result<(FhePubKeySet, KmsFheKeyHandles)>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    let (send, recv) = tokio::sync::oneshot::channel();
    let sk_copy = sk.to_owned();
    let key_id_copy = key_id.to_owned();
    let preproc_id_copy = preproc_id.to_owned();

    let existing_key_handle = match compression_key_id {
        Some(compression_key_id_inner) => {
            storage
                .refresh_centralized_fhe_keys(&compression_key_id_inner)
                .await?;
            let existing_key_handle = storage
                .read_cloned_centralized_fhe_keys_from_cache(&compression_key_id_inner)
                .await?;
            Some(existing_key_handle)
        }
        None => None,
    };

    rayon::spawn_fifo(move || {
        let out = generate_fhe_keys(
            &sk_copy,
            params,
            keyset_config,
            existing_key_handle,
            &key_id_copy,
            &preproc_id_copy,
            seed,
            &eip712_domain,
        );
        let _ = send.send(out);
    });
    recv.await.map_err(|e| anyhow::anyhow!(e.to_string()))?
}

#[cfg(feature = "non-wasm")]
pub(crate) async fn async_generate_decompression_keys<PubS, PrivS>(
    storage: CentralizedCryptoMaterialStorage<PubS, PrivS>,
    keyset1_id: &RequestId,
    keyset2_id: &RequestId,
) -> anyhow::Result<DecompressionKey>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    storage.refresh_centralized_fhe_keys(keyset1_id).await?;
    storage.refresh_centralized_fhe_keys(keyset2_id).await?;

    // we need the private glwe key from keyset 2
    let (client_key_2, _, _, _, _, _, _) = storage
        .read_cloned_centralized_fhe_keys_from_cache(keyset2_id)
        .await?
        .client_key
        .into_raw_parts();
    // we need the private compression key from keyset 1
    let (_, _, compression_private_key_1, _, _, _, _) = storage
        .read_cloned_centralized_fhe_keys_from_cache(keyset1_id)
        .await?
        .client_key
        .into_raw_parts();
    match compression_private_key_1 {
        Some(private_compression_key) => {
            let (send, recv) = tokio::sync::oneshot::channel();
            rayon::spawn_fifo(move || {
                let (_, decompression_key) =
                    client_key_2.new_compression_decompression_keys(&private_compression_key);
                let _ = send.send(decompression_key);
            });
            recv.await.map_err(|e| anyhow::anyhow!(e.to_string()))
        }
        None => {
            anyhow::bail!("Compression private key is missing");
        }
    }
}

#[cfg(feature = "non-wasm")]
pub(crate) async fn async_generate_crs(
    sk: &PrivateSigKey,
    params: DKGParams,
    max_num_bits: Option<u32>,
    eip712_domain: alloy_sol_types::Eip712Domain,
    req_id: &RequestId,
    rng: AesRng,
) -> anyhow::Result<(CompactPkeCrs, CrsGenMetadata)> {
    let (send, recv) = tokio::sync::oneshot::channel();
    let sk_copy = sk.to_owned();
    let req_id_copy = req_id.to_owned();

    rayon::spawn_fifo(move || {
        let out = gen_centralized_crs(
            &sk_copy,
            &params,
            max_num_bits,
            &eip712_domain,
            &req_id_copy,
            rng,
        );
        let _ = send.send(out);
    });
    recv.await?
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "non-wasm")]
pub fn generate_fhe_keys(
    sk: &PrivateSigKey,
    params: DKGParams,
    keyset_config: StandardKeySetConfig,
    existing_key_handle: Option<KmsFheKeyHandles>,
    key_id: &RequestId,
    preproc_id: &RequestId,
    seed: Option<Seed>,
    eip712_domain: &alloy_sol_types::Eip712Domain,
) -> anyhow::Result<(FhePubKeySet, KmsFheKeyHandles)> {
    let f = || -> anyhow::Result<(FhePubKeySet, KmsFheKeyHandles)> {
        let tag = key_id.into();
        let client_key = match keyset_config.compression_config {
            KeySetCompressionConfig::Generate => generate_client_fhe_key(params, tag, seed),
            KeySetCompressionConfig::UseExisting => {
                match existing_key_handle {
                    Some(key_handle) => {
                        // we generate the client key as usual,
                        // but we replace the compression private key using an existing compression private key
                        let client_key = generate_client_fhe_key(params, tag, seed);
                        let (client_key, dedicated_compact_private_key, _, _, _, _, tag) = client_key.into_raw_parts();
                        let (_, _, existing_compression_private_key, noise_squashing_key, noise_squashing_compression_key, rerand_key_params, _) = key_handle.client_key.into_raw_parts();
                        ClientKey::from_raw_parts(client_key, dedicated_compact_private_key, existing_compression_private_key, noise_squashing_key,noise_squashing_compression_key,rerand_key_params, tag)
                    },
                    None => anyhow::bail!("existing key handle is required when using existing compression key for keygen")
                }
            }
        };

        let server_key = client_key.generate_server_key();
        let server_key = server_key.into_raw_parts();
        let decompression_key = server_key.3.clone();
        let server_key = ServerKey::from_raw_parts(
            server_key.0,
            server_key.1,
            server_key.2,
            server_key.3,
            server_key.4,
            server_key.5,
            server_key.6,
            server_key.7,
        );
        let public_key = FhePublicKey::new(&client_key);
        let pks = FhePubKeySet {
            public_key,
            server_key,
        };
        let handles = KmsFheKeyHandles::new(
            sk,
            client_key,
            key_id,
            preproc_id,
            &pks,
            decompression_key,
            eip712_domain,
        )?;
        Ok((pks, handles))
    };
    match panic::catch_unwind(f) {
        Ok(x) => x,
        Err(_) => Err(anyhow_error_and_log(
            "FHE key generation panicked!".to_string(),
        )),
    }
}

#[cfg(feature = "non-wasm")]
pub fn generate_client_fhe_key(params: DKGParams, tag: tfhe::Tag, seed: Option<Seed>) -> ClientKey {
    use tfhe::prelude::Tagged;

    let config = params.to_tfhe_config();
    let mut client_key = match seed {
        Some(seed) => ClientKey::generate_with_seed(config, seed),
        None => ClientKey::generate(config),
    };
    *client_key.tag_mut() = tag;
    client_key
}

/// compute the CRS in the centralized KMS.
#[cfg(feature = "non-wasm")]
pub(crate) fn gen_centralized_crs<R: Rng + CryptoRng>(
    sk: &PrivateSigKey,
    params: &DKGParams,
    max_num_bits: Option<u32>,
    eip712_domain: &alloy_sol_types::Eip712Domain,
    req_id: &RequestId,
    mut rng: R,
) -> anyhow::Result<(CompactPkeCrs, CrsGenMetadata)> {
    let sid = req_id.derive_session_id()?;
    let internal_pp = public_parameters_by_trusted_setup(
        &params
            .get_params_basics_handle()
            .get_compact_pk_enc_params(),
        max_num_bits.map(|x| x as usize),
        sid,
        &mut rng,
    )?;
    let pke_params = params
        .get_params_basics_handle()
        .get_compact_pk_enc_params();
    let pp = internal_pp.try_into_tfhe_zk_pok_pp(&pke_params, sid)?;
    let crs_info = crate::engine::base::compute_info_crs(
        sk,
        &crate::engine::base::DSEP_PUBDATA_CRS,
        req_id,
        &pp,
        eip712_domain,
    )?;
    Ok((pp, crs_info))
}

// We only need to derive (de)serialize for test, which is why they're under a cfg_attr.
#[cfg(feature = "non-wasm")]
#[cfg_attr(test, derive(Serialize, serde::Deserialize))]
pub struct CentralizedKmsKeys {
    pub key_info: HashMap<RequestId, KmsFheKeyHandles>,
    pub sig_sk: PrivateSigKey,
    pub sig_pk: PublicSigKey,
}

// We only need to derive (de)serialize for test, which is why they're under a cfg_attr.
#[cfg(test)]
#[cfg_attr(test, derive(Serialize, serde::Deserialize))]
pub(crate) struct CentralizedTestingKeys {
    pub(crate) params: DKGParams,
    pub(crate) centralized_kms_keys: CentralizedKmsKeys,
    pub(crate) pub_fhe_keys: HashMap<RequestId, FhePubKeySet>,
    pub(crate) client_pk: PublicSigKey,
    pub(crate) client_sk: PrivateSigKey,
    pub(crate) server_keys: Vec<PublicSigKey>,
}

#[cfg(feature = "non-wasm")]
#[derive(Debug, Clone)]
pub struct CentralizedPreprocBucket {
    pub(crate) preprocessing_id: RequestId,
    pub(crate) external_signature: Vec<u8>,
    pub(crate) dkg_param: DKGParams,
}

/// Centralized KMS where keys are stored in a local file
/// Observe that the order of write access MUST be as follows to avoid dead locks:
/// PublicStorage -> PrivateStorage -> FheKeys/XXX_meta_map
#[cfg(feature = "non-wasm")]
pub struct CentralizedKms<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    CM: ContextManager + Sync + Send + 'static,
    BO: BackupOperator + Sync + Send + 'static,
> {
    pub(crate) base_kms: BaseKmsStruct,
    pub(crate) crypto_storage: CentralizedCryptoMaterialStorage<PubS, PrivS>,
    // NOT USED - only here to ensure we can keep track of calls similar to the threshold KMS
    pub(crate) init_ids: Arc<RwLock<MetaStore<()>>>,
    // Ensures we can sign responses in the same manner as the threshold KMS
    // and keeps track of the parameters sent during a PreprocRequest
    // to use them in the corresponding KeyGenRequest
    pub(crate) preprocessing_meta_store: Arc<RwLock<MetaStore<CentralizedPreprocBucket>>>,
    // Map storing ongoing key generation requests.
    pub(crate) key_meta_map: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
    // Map storing ongoing public decryption requests.
    pub(crate) pub_dec_meta_store: Arc<RwLock<MetaStore<PubDecCallValues>>>,
    // Map storing ongoing user decryption requests.
    pub(crate) user_dec_meta_store: Arc<RwLock<MetaStore<UserDecryptCallValues>>>,
    // Map storing ongoing CRS generation requests.
    pub(crate) crs_meta_map: Arc<RwLock<MetaStore<CrsGenMetadata>>>,
    pub(crate) custodian_meta_map: Arc<RwLock<CustodianMetaStore>>,
    pub(crate) context_manager: CM,
    pub(crate) backup_operator: BO,
    // Rate limiting
    pub(crate) rate_limiter: RateLimiter,
    // Health reporter for the the grpc server
    pub(crate) health_reporter: Arc<RwLock<HealthReporter>>,
    // Task tacker to ensure that we keep track of all ongoing operations and can cancel them if needed (e.g. during shutdown).
    pub(crate) tracker: Arc<TaskTracker>,
    pub(crate) thread_handles: Arc<RwLock<ThreadHandleGroup>>,
}
#[cfg(feature = "non-wasm")]
pub type RealCentralizedKms<PubS, PrivS> =
    CentralizedKms<PubS, PrivS, RealContextManager<PubS, PrivS>, RealBackupOperator<PubS, PrivS>>;

/// Perform asynchronous decryption and serialize the result
#[cfg(feature = "non-wasm")]
pub fn central_public_decrypt<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
>(
    keys: &KmsFheKeyHandles,
    cts: &[TypedCiphertext],
    metric_tags: Vec<(&'static str, String)>,
) -> anyhow::Result<Vec<TypedPlaintext>> {
    use observability::{
        metrics,
        metrics_names::{OP_PUBLIC_DECRYPT_INNER, TAG_TFHE_TYPE},
    };
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

    tracing::info!("Decrypting list of cipher-texts");
    // run the decryption of each ct in the batch in parallel
    cts.par_iter()
        .map(|ct| {
            let mut inner_timer = metrics::METRICS
                .time_operation(OP_PUBLIC_DECRYPT_INNER)
                .tags(metric_tags.clone())
                .start();
            let fhe_type = ct.fhe_type()?;
            let fhe_type_string = ct.fhe_type_string();
            inner_timer.tag(TAG_TFHE_TYPE, fhe_type_string);
            RealCentralizedKms::<PubS, PrivS>::public_decrypt(
                keys,
                &ct.ciphertext,
                fhe_type,
                ct.ciphertext_format(),
            )
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Perform asynchronous user decryption and serialize the result
#[cfg(feature = "non-wasm")]
#[allow(clippy::too_many_arguments)]
pub async fn async_user_decrypt<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
>(
    keys: &KmsFheKeyHandles,
    sig_key: &PrivateSigKey,
    rng: &mut (impl CryptoRng + RngCore),
    typed_ciphertexts: &[TypedCiphertext],
    req_digest: &[u8],
    client_enc_key: &UnifiedPublicEncKey,
    client_address: &alloy_primitives::Address,
    server_verf_key: Vec<u8>,
    domain: &alloy_sol_types::Eip712Domain,
    metric_tags: Vec<(&'static str, String)>,
    extra_data: Vec<u8>,
) -> anyhow::Result<(UserDecryptionResponsePayload, Vec<u8>)> {
    use observability::{
        metrics,
        metrics_names::{OP_USER_DECRYPT_INNER, TAG_TFHE_TYPE},
    };

    use crate::engine::base::compute_external_user_decrypt_signature;

    let mut all_signcrypted_cts = vec![];
    for typed_ciphertext in typed_ciphertexts {
        let mut inner_timer = metrics::METRICS
            .time_operation(OP_USER_DECRYPT_INNER)
            .tags(metric_tags.clone())
            .start();
        let high_level_ct = &typed_ciphertext.ciphertext;
        let fhe_type = typed_ciphertext.fhe_type()?;
        let fhe_type_string = typed_ciphertext.fhe_type_string();
        inner_timer.tag(TAG_TFHE_TYPE, fhe_type_string);
        let ct_format = typed_ciphertext.ciphertext_format();
        let external_handle = typed_ciphertext.external_handle.clone();
        let signcrypted_ciphertext = RealCentralizedKms::<PubS, PrivS>::user_decrypt(
            keys,
            sig_key,
            rng,
            high_level_ct,
            fhe_type,
            ct_format,
            req_digest,
            client_enc_key,
            client_address.as_ref(),
        )?;
        all_signcrypted_cts.push(TypedSigncryptedCiphertext {
            fhe_type: fhe_type as i32,
            signcrypted_ciphertext,
            external_handle,
            // set to 1 because there's no recomposition in centralized
            packing_factor: 1,
        });
    }

    let payload = UserDecryptionResponsePayload {
        signcrypted_ciphertexts: all_signcrypted_cts,
        digest: req_digest.to_vec(),
        verification_key: server_verf_key,
        party_id: 1, // In the centralized KMS, the server ID is always 1
        degree: 0,   // In the centralized KMS, the degree is always 0 since result is a constant
    };

    let external_signature = compute_external_user_decrypt_signature(
        sig_key,
        &payload,
        domain,
        client_enc_key,
        extra_data,
    )?;

    Ok((payload, external_signature))
}

// impl fmt::Debug for CentralizedKms, we don't want to include the decryption key in the debug output
#[cfg(feature = "non-wasm")]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        CM: ContextManager + Sync + Send + 'static,
        BO: BackupOperator + Sync + Send + 'static,
    > fmt::Debug for CentralizedKms<PubS, PrivS, CM, BO>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CentralizedKms")
            .field("sig_key", &self.base_kms.sig_key)
            .finish() // Don't include fhe_dec_key
    }
}

#[cfg(feature = "non-wasm")]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        CM: ContextManager + Sync + Send + 'static,
        BO: BackupOperator + Sync + Send + 'static,
    > BaseKms for CentralizedKms<PubS, PrivS, CM, BO>
{
    fn verify_sig<T: Serialize + AsRef<[u8]>>(
        dsep: &DomainSep,
        payload: &T,
        signature: &Signature,
        verification_key: &PublicSigKey,
    ) -> anyhow::Result<()> {
        BaseKmsStruct::verify_sig(dsep, payload, signature, verification_key)
    }

    fn sign<T: Serialize + AsRef<[u8]>>(
        &self,
        dsep: &DomainSep,
        msg: &T,
    ) -> anyhow::Result<Signature> {
        self.base_kms.sign(dsep, msg)
    }

    fn digest<T: ?Sized + AsRef<[u8]>>(
        domain_separator: &DomainSep,
        msg: &T,
    ) -> anyhow::Result<Vec<u8>> {
        BaseKmsStruct::digest(domain_separator, &msg)
    }
}

macro_rules! deserialize_to_low_level_and_decrypt_helper {
    ($rust_type:ty,$fout:expr,$ct_format:expr,$serialized_high_level:expr,$keys:expr) => {{
        match $ct_format {
            CiphertextFormat::SmallCompressed => {
                let hl_ct: $rust_type =
                    decompression::tfhe_safe_deserialize_and_uncompress::<$rust_type>(
                        $keys
                            .decompression_key
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("missing decompression key"))?,
                        $serialized_high_level,
                    )?;
                $fout(hl_ct.decrypt(&$keys.client_key))
            }
            CiphertextFormat::SmallExpanded => {
                let hl_ct: $rust_type =
                    decompression::tfhe_safe_deserialize::<$rust_type>($serialized_high_level)?;
                $fout(hl_ct.decrypt(&$keys.client_key))
            }
            CiphertextFormat::BigCompressed => {
                let r = safe_deserialize::<tfhe::CompressedSquashedNoiseCiphertextList>(
                    std::io::Cursor::new($serialized_high_level),
                    SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let ct: tfhe::SquashedNoiseFheUint = r.get(0)?.ok_or(anyhow::anyhow!(
                    "Failed to get first element from CompressedSquashedNoiseCiphertextList"
                ))?;
                let raw_res = ct.decrypt(&$keys.client_key);
                $fout(raw_res)
            }
            CiphertextFormat::BigExpanded => {
                let r = safe_deserialize::<tfhe::SquashedNoiseFheUint>(
                    std::io::Cursor::new($serialized_high_level),
                    SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let raw_res = r.decrypt(&$keys.client_key);
                $fout(raw_res)
            }
        }
    }};
}

fn unsafe_decrypt(
    keys: &KmsFheKeyHandles,
    serialized_high_level: &[u8],
    fhe_type: FheTypes,
    ct_format: CiphertextFormat,
) -> anyhow::Result<TypedPlaintext> {
    let res = match fhe_type {
        FheTypes::Bool => match ct_format {
            CiphertextFormat::SmallCompressed => {
                let hl_ct: FheBool = decompression::tfhe_safe_deserialize_and_uncompress::<FheBool>(
                    keys.decompression_key
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("missing decompression key"))?,
                    serialized_high_level,
                )?;
                TypedPlaintext::from_bool(hl_ct.decrypt(&keys.client_key))
            }
            CiphertextFormat::SmallExpanded => {
                let hl_ct: FheBool =
                    decompression::tfhe_safe_deserialize::<FheBool>(serialized_high_level)?;
                TypedPlaintext::from_bool(hl_ct.decrypt(&keys.client_key))
            }
            CiphertextFormat::BigCompressed => {
                let r = safe_deserialize::<tfhe::CompressedSquashedNoiseCiphertextList>(
                    std::io::Cursor::new(serialized_high_level),
                    SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let ct: tfhe::SquashedNoiseFheBool = r.get(0)?.ok_or(anyhow::anyhow!(
                    "Failed to get first element from CompressedSquashedNoiseCiphertextList"
                ))?;
                let raw_res = ct.decrypt(&keys.client_key);
                TypedPlaintext::from_bool(raw_res)
            }
            CiphertextFormat::BigExpanded => {
                let r = safe_deserialize::<tfhe::SquashedNoiseFheBool>(
                    std::io::Cursor::new(serialized_high_level),
                    SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let raw_res = r.decrypt(&keys.client_key);
                TypedPlaintext::from_bool(raw_res)
            }
        },
        FheTypes::Uint4 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint4,
                TypedPlaintext::from_u4,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheTypes::Uint8 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint8,
                TypedPlaintext::from_u8,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheTypes::Uint16 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint16,
                TypedPlaintext::from_u16,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheTypes::Uint32 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint32,
                TypedPlaintext::from_u32,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheTypes::Uint64 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint64,
                TypedPlaintext::from_u64,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheTypes::Uint80 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint80,
                TypedPlaintext::from_u80,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheTypes::Uint128 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint128,
                TypedPlaintext::from_u128,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheTypes::Uint160 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint160,
                TypedPlaintext::from_u160,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheTypes::Uint256 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint256,
                TypedPlaintext::from_u256,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheTypes::Uint512 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint512,
                TypedPlaintext::from_u512,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheTypes::Uint1024 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint1024,
                TypedPlaintext::from_u1024,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheTypes::Uint2048 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint2048,
                TypedPlaintext::from_u2048,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        unsupported_fhe_type => {
            anyhow::bail!("Unsupported fhe type in unsafe_decrypt {unsupported_fhe_type:?}");
        }
    };
    Ok(res)
}

#[cfg(feature = "non-wasm")]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        CM: ContextManager + Sync + Send + 'static,
        BO: BackupOperator + Sync + Send + 'static,
    > Kms for CentralizedKms<PubS, PrivS, CM, BO>
{
    fn public_decrypt(
        keys: &KmsFheKeyHandles,
        high_level_ct: &[u8],
        fhe_type: FheTypes,
        ct_format: CiphertextFormat,
    ) -> anyhow::Result<TypedPlaintext> {
        match panic::catch_unwind(|| unsafe_decrypt(keys, high_level_ct, fhe_type, ct_format)) {
            Ok(x) => x,
            Err(_) => Err(anyhow_error_and_log("decryption panicked".to_string())),
        }
    }

    // We allow the following lints because we are fine with mutating the rng even if
    // the function fails serializing the singcrypted message.
    #[allow(unknown_lints)]
    #[allow(non_local_effect_before_error_return)]
    fn user_decrypt(
        keys: &KmsFheKeyHandles,
        sig_key: &PrivateSigKey,
        rng: &mut (impl CryptoRng + RngCore),
        ct: &[u8],
        fhe_type: FheTypes,
        ct_format: CiphertextFormat,
        link: &[u8],
        client_enc_key: &UnifiedPublicEncKey,
        client_id: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let signcryption_key = UnifiedSigncryptionKey::new(sig_key, client_enc_key, client_id);
        // Observe that we encrypt the plaintext itself, this is different from the threshold case
        // where it is first mapped to a Vec<ResiduePolyF4Z128> element
        let plaintext = Self::public_decrypt(keys, ct, fhe_type, ct_format)?;
        let enc_res = signcryption_key.signcrypt_plaintext(
            rng,
            &DSEP_USER_DECRYPTION,
            &plaintext.bytes,
            fhe_type,
            link,
        )?;

        tracing::info!("Completed user decryption of ciphertext");

        // LEGACY: for legacy reasons we return the inner payload
        Ok(enc_res.payload)
    }
}

#[cfg(feature = "non-wasm")]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        CM: ContextManager + Sync + Send + 'static,
        BO: BackupOperator + Sync + Send + 'static,
    > CentralizedKms<PubS, PrivS, CM, BO>
{
    pub async fn new(
        public_storage: PubS,
        private_storage: PrivS,
        backup_vault: Option<Vault>,
        security_module: Option<Arc<SecurityModuleProxy>>,
        sk: PrivateSigKey,
        rate_limiter_conf: Option<RateLimiterConfig>,
    ) -> anyhow::Result<(RealCentralizedKms<PubS, PrivS>, HealthServer<impl Health>)> {
        let key_info: HashMap<RequestId, KmsFheKeyHandles> =
            read_all_data_versioned(&private_storage, &PrivDataType::FhePrivateKey.to_string())
                .await?;
        let mut pk_map = HashMap::new();
        for id in key_info.keys() {
            let public_key = read_pk_at_request_id(&public_storage, id).await?;
            pk_map.insert(*id, public_key);
        }
        tracing::info!(
            "loaded key_info with key_ids: {:?}",
            key_info.keys().collect::<Vec<_>>()
        );
        let public_key_info = key_info
            .iter()
            .map(|(id, info)| (id.to_owned(), info.public_key_info.to_owned()))
            .collect();
        let crs_info: HashMap<RequestId, CrsGenMetadata> =
            read_all_data_versioned(&private_storage, &PrivDataType::CrsInfo.to_string()).await?;
        let validation_material: HashMap<RequestId, RecoveryValidationMaterial> =
            read_all_data_versioned(&public_storage, &PubDataType::RecoveryMaterial.to_string())
                .await?;
        let verf_key = PublicSigKey::from_sk(&sk);
        for (cur_req_id, rec_material) in validation_material.iter() {
            if !rec_material.validate(&verf_key) {
                anyhow::bail!("Invalid recovery validation material for key id {cur_req_id}");
            }
        }
        let custodian_context = validation_material
            .into_iter()
            .map(|(r, com)| (r, com.custodian_context().to_owned()))
            .collect();
        let custodian_meta_store =
            Arc::new(RwLock::new(MetaStore::new_from_map(custodian_context)));
        let tracker = Arc::new(TaskTracker::new());

        let crypto_storage = CentralizedCryptoMaterialStorage::new(
            public_storage,
            private_storage,
            backup_vault,
            pk_map,
            key_info,
        );
        let base_kms = BaseKmsStruct::new(KMSType::Centralized, sk)?;
        let context_manager: RealContextManager<PubS, PrivS> = RealContextManager {
            base_kms: base_kms.new_instance().await,
            crypto_storage: crypto_storage.inner.clone(),
            custodian_meta_store: Arc::clone(&custodian_meta_store),
            my_role: Role::indexed_from_one(1), // Centralized KMS is always party 1
        };
        let backup_operator = RealBackupOperator::new(
            Role::indexed_from_one(1), // Centralized KMS is always party 1
            base_kms.new_instance().await,
            crypto_storage.inner.clone(),
            security_module,
        );
        // Update backup vault if it exists
        // This ensures that all files in the private storage are also in the backup vault
        // Thus the vault gets automatically updated incase its location changes, or in case of a deletion
        // Note however that the data in the vault is not checked for corruption.
        backup_operator.update_backup_vault().await?;
        let (health_reporter, health_service) = tonic_health::server::health_reporter();
        // We will serve as soon as the server is started
        health_reporter
            .set_serving::<CoreServiceEndpointServer<CentralizedKms<PubS, PrivS, CM, BO>>>()
            .await;
        Ok((
            CentralizedKms {
                base_kms,
                crypto_storage,
                init_ids: Arc::new(RwLock::new(MetaStore::new_from_map(HashMap::new()))),
                preprocessing_meta_store: Arc::new(RwLock::new(MetaStore::new_from_map(
                    HashMap::new(),
                ))),
                key_meta_map: Arc::new(RwLock::new(MetaStore::new_from_map(public_key_info))),
                pub_dec_meta_store: Arc::new(RwLock::new(MetaStore::new(
                    DEC_CAPACITY,
                    MIN_DEC_CACHE,
                ))),
                user_dec_meta_store: Arc::new(RwLock::new(MetaStore::new(
                    DEC_CAPACITY,
                    MIN_DEC_CACHE,
                ))),
                crs_meta_map: Arc::new(RwLock::new(MetaStore::new_from_map(crs_info))),
                custodian_meta_map: Arc::clone(&custodian_meta_store),
                context_manager,
                backup_operator,
                rate_limiter: RateLimiter::new(rate_limiter_conf.unwrap_or_default()),
                health_reporter: Arc::new(RwLock::new(health_reporter)),
                tracker: Arc::clone(&tracker),
                thread_handles: Arc::new(RwLock::new(ThreadHandleGroup::new())),
            },
            health_service,
        ))
    }
}

#[cfg(feature = "non-wasm")]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        CM: ContextManager + Sync + Send + 'static,
        BO: BackupOperator + Sync + Send + 'static,
    > CentralizedKms<PubS, PrivS, CM, BO>
{
    /// Get a reference to the key generation MetaStore
    pub fn get_key_gen_meta_store(&self) -> &Arc<RwLock<MetaStore<KeyGenMetadata>>> {
        &self.key_meta_map
    }

    /// Get a reference to the public decryption MetaStore
    pub fn get_pub_dec_meta_store(&self) -> &Arc<RwLock<MetaStore<PubDecCallValues>>> {
        &self.pub_dec_meta_store
    }

    /// Get a reference to the user decryption MetaStore
    pub fn get_user_dec_meta_store(&self) -> &Arc<RwLock<MetaStore<UserDecryptCallValues>>> {
        &self.user_dec_meta_store
    }

    /// Get a reference to the CRS generation MetaStore
    pub fn get_crs_meta_store(&self) -> &Arc<RwLock<MetaStore<CrsGenMetadata>>> {
        &self.crs_meta_map
    }

    pub fn get_custodian_meta_store(&self) -> &Arc<RwLock<CustodianMetaStore>> {
        &self.custodian_meta_map
    }
}

#[tonic::async_trait]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        CM: ContextManager + Sync + Send + 'static,
        BO: BackupOperator + Sync + Send + 'static,
    > Shutdown for CentralizedKms<PubS, PrivS, CM, BO>
{
    fn shutdown(&self) -> anyhow::Result<JoinHandle<()>> {
        let h_repoter = self.health_reporter.clone();
        let tracker = self.tracker.clone();
        let handle = tokio::task::spawn(async move {
            h_repoter
                .write()
                .await
                .set_not_serving::<CoreServiceEndpointServer<Self>>()
                .await;
            tracker.close();
            tracker.wait().await;
        });
        Ok(handle)
    }
}

#[allow(clippy::let_underscore_future)]
#[cfg(feature = "non-wasm")]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        CM: ContextManager + Sync + Send + 'static,
        BO: BackupOperator + Sync + Send + 'static,
    > Drop for CentralizedKms<PubS, PrivS, CM, BO>
{
    fn drop(&mut self) {
        if let Some(handles) = Arc::get_mut(&mut self.thread_handles) {
            let handles = std::mem::take(handles.get_mut());
            if let Err(e) = handles.join_all_blocking() {
                tracing::error!("Error joining threads on drop: {}", e);
            }
        }
        // Let the shutdown run in the background
        let _ = self.shutdown();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{generate_fhe_keys, CentralizedKmsKeys, CentralizedTestingKeys, Storage};
    #[cfg(feature = "slow_tests")]
    use crate::consts::{
        DEFAULT_CENTRAL_KEYS_PATH, DEFAULT_CENTRAL_KEY_ID, OTHER_CENTRAL_DEFAULT_ID,
    };
    use crate::consts::{DEFAULT_PARAM, OTHER_CENTRAL_TEST_ID, TEST_CENTRAL_KEY_ID};
    use crate::consts::{TEST_CENTRAL_KEYS_PATH, TEST_PARAM};
    use crate::cryptography::error::CryptographyError;
    use crate::cryptography::signatures::gen_sig_keys;
    use crate::cryptography::signcryption::{
        ephemeral_signcryption_key_generation, DesigncryptFHEPlaintext,
    };
    use crate::dummy_domain;
    use crate::engine::base::{compute_handle, derive_request_id};
    use crate::engine::centralized::central_kms::RealCentralizedKms;
    use crate::engine::traits::Kms;
    use crate::engine::validation::DSEP_USER_DECRYPTION;
    use crate::util::file_handling::{read_element, write_element};
    use crate::util::key_setup::test_tools::{compute_cipher, EncryptionConfig};
    use crate::util::rate_limiter::RateLimiter;
    use crate::vault::storage::{file::FileStorage, ram::RamStorage};
    use crate::vault::storage::{store_pk_at_request_id, store_versioned_at_request_id};
    use aes_prng::AesRng;
    use kms_grpc::rpc_types::{PrivDataType, WrappedPublicKey};
    use kms_grpc::RequestId;
    use rand::SeedableRng;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::path::Path;
    use std::str::FromStr;
    use tfhe::{set_server_key, FheTypes};
    use tfhe::{shortint::ClassicPBSParameters, ConfigBuilder, Seed};
    use threshold_fhe::execution::keyset_config::StandardKeySetConfig;
    use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
    use tokio::sync::OnceCell;

    static ONCE_TEST_KEY: OnceCell<CentralizedTestingKeys> = OnceCell::const_new();
    async fn get_test_keys() -> &'static CentralizedTestingKeys {
        ONCE_TEST_KEY
            .get_or_init(|| async { ensure_kms_test_keys().await })
            .await
    }

    #[cfg(feature = "slow_tests")]
    static ONCE_DEFAULT_KEY: OnceCell<CentralizedTestingKeys> = OnceCell::const_new();
    #[cfg(feature = "slow_tests")]
    pub(crate) async fn get_default_keys() -> &'static CentralizedTestingKeys {
        ONCE_DEFAULT_KEY
            .get_or_init(|| async { ensure_kms_default_keys().await })
            .await
    }

    impl<PubS: Storage + Send + Sync + 'static, PrivS: Storage + Send + Sync + 'static>
        RealCentralizedKms<PubS, PrivS>
    {
        pub(crate) fn set_bucket_size(&mut self, bucket_size: usize) {
            let config = crate::util::rate_limiter::RateLimiterConfig {
                bucket_size,
                ..Default::default()
            };
            self.rate_limiter = RateLimiter::new(config);
        }
    }

    // Construct a storage for private keys
    pub(crate) async fn new_priv_ram_storage_from_existing_keys(
        keys: &CentralizedKmsKeys,
    ) -> anyhow::Result<RamStorage> {
        let mut ram_storage = RamStorage::new();
        for (cur_req_id, cur_keys) in &keys.key_info {
            store_versioned_at_request_id(
                &mut ram_storage,
                cur_req_id,
                cur_keys,
                &PrivDataType::FhePrivateKey.to_string(),
            )
            .await?;
        }
        let sk_handle = compute_handle(&keys.sig_pk)?;
        ram_storage
            .store_data(
                &keys.sig_sk,
                &RequestId::from_str(&sk_handle)?,
                &PrivDataType::SigningKey.to_string(),
            )
            .await?;
        Ok(ram_storage)
    }

    pub(crate) async fn new_pub_ram_storage_from_existing_keys(
        keys: &HashMap<
            RequestId,
            threshold_fhe::execution::tfhe_internals::public_keysets::FhePubKeySet,
        >,
    ) -> anyhow::Result<RamStorage> {
        let mut ram_storage = RamStorage::new();
        for (cur_req_id, cur_keys) in keys {
            let wrapped_pk = WrappedPublicKey::Compact(&cur_keys.public_key);
            store_pk_at_request_id(&mut ram_storage, cur_req_id, wrapped_pk).await?;
        }
        Ok(ram_storage)
    }

    #[derive(Clone, PartialEq, Eq)]
    enum SimulationType {
        NoError,
        BadFheKey,
        // below are only used for user encryption
        BadSigKey,
        BadEphemeralKey,
    }

    async fn ensure_kms_test_keys() -> CentralizedTestingKeys {
        setup(
            TEST_PARAM,
            &TEST_CENTRAL_KEY_ID.to_string(),
            &OTHER_CENTRAL_TEST_ID.to_string(),
            TEST_CENTRAL_KEYS_PATH,
        )
        .await
    }

    #[cfg(feature = "slow_tests")]
    pub(crate) async fn ensure_kms_default_keys() -> CentralizedTestingKeys {
        setup(
            DEFAULT_PARAM,
            &DEFAULT_CENTRAL_KEY_ID.to_string(),
            &OTHER_CENTRAL_DEFAULT_ID.to_string(),
            DEFAULT_CENTRAL_KEYS_PATH,
        )
        .await
    }

    async fn setup(
        dkg_params: DKGParams,
        key_id: &str,
        other_key_id: &str,
        key_path: &str,
    ) -> CentralizedTestingKeys {
        if Path::new(key_path).exists() {
            return read_element(key_path).await.unwrap();
        }

        let preproc_id = derive_request_id("CENTRALIZED_DUMMY_PREPROCESSING_ID").unwrap();
        let mut rng = AesRng::seed_from_u64(100);
        let seed = Some(Seed(42));
        let (sig_pk, sig_sk) = gen_sig_keys(&mut rng);
        let domain = dummy_domain();
        let (pub_fhe_keys, key_info) = generate_fhe_keys(
            &sig_sk,
            dkg_params,
            StandardKeySetConfig::default(),
            None,
            &RequestId::from_str(key_id).unwrap(),
            &preproc_id,
            seed,
            &domain,
        )
        .unwrap();
        assert!(pub_fhe_keys.server_key.noise_squashing_key().is_some());
        // check that key_info contains
        let mut key_info_map = HashMap::from([(key_id.to_string().try_into().unwrap(), key_info)]);

        let (other_pub_fhe_keys, other_key_info) = generate_fhe_keys(
            &sig_sk,
            dkg_params,
            StandardKeySetConfig::default(),
            None,
            &RequestId::from_str(other_key_id).unwrap(),
            &preproc_id,
            seed,
            &domain,
        )
        .unwrap();
        assert!(other_pub_fhe_keys
            .server_key
            .noise_squashing_key()
            .is_some());

        // Insert a key with another handle to setup a KMS with multiple keys
        key_info_map.insert(other_key_id.to_string().try_into().unwrap(), other_key_info);
        let pub_fhe_map = HashMap::from([
            (key_id.to_string().try_into().unwrap(), pub_fhe_keys.clone()),
            (
                other_key_id.to_string().try_into().unwrap(),
                other_pub_fhe_keys,
            ),
        ]);
        let server_keys = vec![sig_pk.clone()];
        let (client_pk, client_sk) = gen_sig_keys(&mut rng);
        let centralized_test_keys = CentralizedTestingKeys {
            params: dkg_params,
            client_pk,
            client_sk,
            server_keys,
            pub_fhe_keys: pub_fhe_map,
            centralized_kms_keys: CentralizedKmsKeys {
                key_info: key_info_map,
                sig_sk,
                sig_pk,
            },
        };
        assert!(write_element(key_path, &centralized_test_keys)
            .await
            .is_ok());
        centralized_test_keys
    }

    #[tokio::test]
    #[serial(default_keys)]
    async fn test_gen_keys() {
        let mut rng = AesRng::seed_from_u64(100);
        let domain = dummy_domain();
        let (_sig_pk, sig_sk) = gen_sig_keys(&mut rng);
        let key_id = RequestId::new_random(&mut rng);
        let preproc_id = RequestId::new_random(&mut rng);
        assert!(generate_fhe_keys(
            &sig_sk,
            DEFAULT_PARAM,
            StandardKeySetConfig::default(),
            None,
            &key_id,
            &preproc_id,
            None,
            &domain,
        )
        .is_ok());
    }

    #[tokio::test]
    #[serial(test_keys)]
    async fn multiple_test_keys_access() {
        let central_keys = get_test_keys().await;

        // try to get keys with the default handle
        let default_key = central_keys
            .centralized_kms_keys
            .key_info
            .get(&TEST_CENTRAL_KEY_ID);
        assert!(default_key.is_some());

        // try to get keys with the some other handle
        let some_key = central_keys
            .centralized_kms_keys
            .key_info
            .get(&OTHER_CENTRAL_TEST_ID);
        assert!(some_key.is_some());

        // try to get keys with a non-existent handle
        let wrong_key_handle = derive_request_id("wrongKeyHandle").unwrap();
        let no_key = central_keys
            .centralized_kms_keys
            .key_info
            .get(&wrong_key_handle);
        assert!(no_key.is_none());
    }

    #[tokio::test]
    #[serial(test_keys)]
    async fn sunshine_test_decrypt() {
        sunshine_decrypt(get_test_keys().await, &TEST_CENTRAL_KEY_ID).await;
    }

    #[tokio::test]
    #[serial(test_keys)]
    async fn decrypt_with_bad_client_key() {
        simulate_decrypt(
            SimulationType::BadFheKey,
            get_test_keys().await,
            &TEST_CENTRAL_KEY_ID,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial(default_keys)]
    async fn sunshine_default_decrypt() {
        sunshine_decrypt(get_default_keys().await, &DEFAULT_CENTRAL_KEY_ID).await;
    }

    #[tokio::test]
    #[serial(test_keys)]
    async fn multiple_test_keys_decrypt() {
        sunshine_decrypt(get_test_keys().await, &OTHER_CENTRAL_TEST_ID).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial(default_keys)]
    async fn multiple_default_keys_decrypt() {
        sunshine_decrypt(get_default_keys().await, &OTHER_CENTRAL_DEFAULT_ID).await;
    }

    async fn sunshine_decrypt(keys: &CentralizedTestingKeys, key_id: &RequestId) {
        simulate_decrypt(SimulationType::NoError, keys, key_id).await;
    }

    async fn simulate_decrypt(
        sim_type: SimulationType,
        keys: &CentralizedTestingKeys,
        key_id: &RequestId,
    ) {
        let msg = 523u64;
        let (ct, ct_format, fhe_type) = {
            let pub_keys = keys.pub_fhe_keys.get(key_id).unwrap();
            set_server_key(pub_keys.server_key.clone());
            compute_cipher(
                msg.into(),
                &pub_keys.public_key,
                None,
                EncryptionConfig {
                    compression: false,
                    precompute_sns: false,
                },
            )
        };
        let kms = {
            let (inner, _health_service) = RealCentralizedKms::new(
                new_pub_ram_storage_from_existing_keys(&keys.pub_fhe_keys)
                    .await
                    .unwrap(),
                new_priv_ram_storage_from_existing_keys(&keys.centralized_kms_keys)
                    .await
                    .unwrap(),
                None,
                None,
                keys.centralized_kms_keys.sig_sk.clone(),
                None,
            )
            .await
            .unwrap();
            if sim_type == SimulationType::BadFheKey {
                set_wrong_client_key(&inner, key_id, keys.params).await;
            }
            inner
        };
        let key_handle = kms
            .crypto_storage
            .read_cloned_centralized_fhe_keys_from_cache(key_id)
            .await
            .unwrap();
        let raw_plaintext = RealCentralizedKms::<FileStorage, FileStorage>::public_decrypt(
            &key_handle,
            &ct,
            fhe_type,
            ct_format,
        );
        // if bad FHE key is used, then it *might* panic
        let plaintext = if sim_type == SimulationType::BadFheKey {
            match raw_plaintext {
                Ok(x) => x,
                Err(e) => {
                    assert!(e.to_string().contains("decryption panicked"));
                    return;
                }
            }
        } else {
            raw_plaintext.unwrap()
        };
        if sim_type == SimulationType::BadFheKey {
            assert_ne!(plaintext.as_u64(), msg);
        } else {
            assert_eq!(plaintext.as_u64(), msg);
        }

        assert_eq!(plaintext.fhe_type().unwrap(), FheTypes::Uint64);
    }

    #[tokio::test]
    async fn sunshine_test_user_decrypt() {
        sunshine_user_decrypt(get_test_keys().await, &TEST_CENTRAL_KEY_ID).await;
    }

    #[tokio::test]
    async fn user_decrypt_with_bad_ephemeral_key() {
        simulate_user_decrypt(
            SimulationType::BadEphemeralKey,
            get_test_keys().await,
            &TEST_CENTRAL_KEY_ID,
        )
        .await
    }

    #[tokio::test]
    async fn user_decrypt_with_bad_sig_key() {
        simulate_user_decrypt(
            SimulationType::BadSigKey,
            get_test_keys().await,
            &TEST_CENTRAL_KEY_ID,
        )
        .await
    }

    #[tokio::test]
    async fn user_decrypt_with_bad_client_key() {
        simulate_user_decrypt(
            SimulationType::BadFheKey,
            get_test_keys().await,
            &TEST_CENTRAL_KEY_ID,
        )
        .await
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    async fn sunshine_default_user_decrypt() {
        sunshine_user_decrypt(get_default_keys().await, &DEFAULT_CENTRAL_KEY_ID).await;
    }

    #[tokio::test]
    #[serial]
    async fn multiple_test_keys_user_decrypt() {
        sunshine_user_decrypt(get_test_keys().await, &OTHER_CENTRAL_TEST_ID).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    async fn multiple_default_keys_user_decrypt() {
        sunshine_user_decrypt(get_default_keys().await, &OTHER_CENTRAL_DEFAULT_ID).await;
    }

    async fn sunshine_user_decrypt(keys: &CentralizedTestingKeys, key_handle: &RequestId) {
        simulate_user_decrypt(SimulationType::NoError, keys, key_handle).await
    }

    async fn set_wrong_client_key<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
    >(
        inner: &RealCentralizedKms<PubS, PrivS>,
        key_handle: &RequestId,
        params: DKGParams,
    ) {
        let pbs_params: ClassicPBSParameters = params
            .get_params_basics_handle()
            .to_classic_pbs_parameters();
        let config = ConfigBuilder::with_custom_parameters(pbs_params);
        let wrong_client_key = tfhe::ClientKey::generate(config);
        inner
            .crypto_storage
            .set_wrong_cached_client_key(key_handle, wrong_client_key)
            .await
            .unwrap();
    }

    async fn simulate_user_decrypt(
        sim_type: SimulationType,
        keys: &CentralizedTestingKeys,
        key_handle: &RequestId,
    ) {
        let msg = 42305u64;
        let mut rng = AesRng::seed_from_u64(1);
        let (ct, ct_format, fhe_type) = {
            let pub_keys = keys.pub_fhe_keys.get(key_handle).unwrap();
            set_server_key(pub_keys.server_key.clone());
            compute_cipher(
                msg.into(),
                &pub_keys.public_key,
                None,
                EncryptionConfig {
                    compression: false,
                    precompute_sns: false,
                },
            )
        };

        let kms = {
            let (inner, _health_service) = RealCentralizedKms::<RamStorage, RamStorage>::new(
                new_pub_ram_storage_from_existing_keys(&keys.pub_fhe_keys)
                    .await
                    .unwrap(),
                new_priv_ram_storage_from_existing_keys(&keys.centralized_kms_keys)
                    .await
                    .unwrap(),
                None,
                None,
                keys.centralized_kms_keys.sig_sk.clone(),
                None,
            )
            .await
            .unwrap();
            if sim_type == SimulationType::BadFheKey {
                set_wrong_client_key(&inner, key_handle, keys.params).await;
            }
            inner
        };
        let link = vec![42_u8, 42, 42];
        let (client_verf_key, _client_sig_key) = gen_sig_keys(&mut rng);
        let client_key_pair = {
            let mut keys = ephemeral_signcryption_key_generation(
                &mut rng,
                &client_verf_key.verf_key_id(),
                Some(kms.base_kms.sig_key.as_ref()),
            );
            if sim_type == SimulationType::BadEphemeralKey {
                let bad_keys = ephemeral_signcryption_key_generation(
                    &mut rng,
                    &client_verf_key.verf_key_id(),
                    Some(kms.base_kms.sig_key.as_ref()),
                );
                // Change the decryption key
                keys.designcryption_key.decryption_key =
                    bad_keys.designcryption_key.decryption_key.to_owned();
            }
            if sim_type == SimulationType::BadSigKey {
                // Change the signing key
                let (server_sig_pk, _server_sig_sk) = gen_sig_keys(&mut rng);
                keys.designcryption_key.sender_verf_key = server_sig_pk;
            }
            keys
        };
        let mut rng = kms.base_kms.new_rng().await;
        let raw_cipher = RealCentralizedKms::<FileStorage, FileStorage>::user_decrypt(
            &kms.crypto_storage
                .read_cloned_centralized_fhe_keys_from_cache(key_handle)
                .await
                .unwrap(),
            &kms.base_kms.sig_key,
            &mut rng,
            &ct,
            fhe_type,
            ct_format,
            &link,
            &client_key_pair.signcrypt_key.receiver_enc_key,
            &client_key_pair.signcrypt_key.receiver_id,
        );
        // if bad FHE key is used, then it *might* panic
        let raw_cipher = if sim_type == SimulationType::BadFheKey {
            match raw_cipher {
                Ok(x) => x,
                Err(e) => {
                    assert!(e.to_string().contains("decryption panicked"));
                    return;
                }
            }
        } else {
            raw_cipher.unwrap()
        };
        let decrypted = client_key_pair.designcryption_key.designcrypt_plaintext(
            &DSEP_USER_DECRYPTION,
            &raw_cipher,
            &link,
        );
        if sim_type == SimulationType::BadEphemeralKey {
            assert!(decrypted.is_err());
            assert!(matches!(
                decrypted.unwrap_err(),
                CryptographyError::AesGcmError(..)
            ));
            return;
        }
        if sim_type == SimulationType::BadSigKey {
            assert!(decrypted.is_err());
            return;
        }
        let decrypted = decrypted.unwrap();
        if sim_type == SimulationType::BadFheKey {
            assert_ne!(decrypted.plaintext.as_u64(), msg);
        } else {
            assert_eq!(decrypted.plaintext.as_u64(), msg);
        }
        assert_eq!(decrypted.plaintext.fhe_type().unwrap(), FheTypes::Uint64);
    }

    #[test]
    fn sanity_check_sns_compression_test_params() {
        use tfhe::prelude::{FheDecrypt, FheEncrypt, SquashNoise};
        let params = TEST_PARAM;
        let cks = crate::engine::centralized::central_kms::generate_client_fhe_key(
            params,
            tfhe::Tag::default(),
            None,
        );
        let sks = cks.generate_server_key();

        tfhe::set_server_key(sks);
        let pt = 12u32;
        let ct = tfhe::FheUint32::encrypt(pt, &cks);
        let large_ct = ct.squash_noise().unwrap();

        let compressed_large_ct = tfhe::CompressedSquashedNoiseCiphertextListBuilder::new()
            .push(large_ct)
            .build()
            .unwrap();
        let new_large_ct: tfhe::SquashedNoiseFheUint = compressed_large_ct.get(0).unwrap().unwrap();
        let actual_pt: u32 = new_large_ct.decrypt(&cks);
        assert_eq!(actual_pt, pt);
    }
}
