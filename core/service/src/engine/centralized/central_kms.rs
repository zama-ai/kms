use crate::consts::{DEC_CAPACITY, MIN_DEC_CACHE};
use crate::cryptography::decompression;
use crate::cryptography::internal_crypto_types::{PrivateSigKey, PublicEncKey, PublicSigKey};
use crate::cryptography::signcryption::signcrypt;
use crate::engine::base::{BaseKmsStruct, KmsFheKeyHandles};
use crate::engine::base::{DecCallValues, KeyGenCallValues, ReencCallValues};
use crate::engine::traits::{BaseKms, Kms};
use crate::engine::Shutdown;
#[cfg(feature = "non-wasm")]
use crate::util::key_setup::FhePublicKey;
use crate::util::meta_store::MetaStore;
use crate::util::rate_limiter::{RateLimiter, RateLimiterConfig};
#[cfg(feature = "non-wasm")]
use crate::vault::storage::Storage;
use crate::vault::storage::{
    crypto_material::CentralizedCryptoMaterialStorage, read_all_data_versioned,
    read_pk_at_request_id,
};
use crate::{anyhow_error_and_log, get_exactly_one};
use aes_prng::AesRng;
use bincode::serialize;
#[cfg(feature = "non-wasm")]
use distributed_decryption::execution::endpoints::keygen::FhePubKeySet;
#[cfg(feature = "non-wasm")]
use distributed_decryption::execution::keyset_config::KeySetCompressionConfig;
#[cfg(feature = "non-wasm")]
use distributed_decryption::execution::keyset_config::StandardKeySetConfig;
use distributed_decryption::execution::tfhe_internals::parameters::{Ciphertext128, DKGParams};
#[cfg(feature = "non-wasm")]
use distributed_decryption::execution::zk::ceremony::make_centralized_public_parameters;
use k256::ecdsa::SigningKey;
use kms_core_utils::thread_handles::ThreadHandleGroup;
#[cfg(feature = "non-wasm")]
use kms_grpc::kms::v1::KeySetAddedInfo;
#[cfg(feature = "non-wasm")]
use kms_grpc::kms::v1::RequestId;
#[cfg(feature = "non-wasm")]
use kms_grpc::kms::v1::TypedSigncryptedCiphertext;
use kms_grpc::kms::v1::{CiphertextFormat, FheType, TypedCiphertext, TypedPlaintext};
#[cfg(feature = "non-wasm")]
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
#[cfg(feature = "non-wasm")]
use kms_grpc::rpc_types::SignedPubDataHandleInternal;
use kms_grpc::rpc_types::{PrivDataType, SigncryptionPayload};
use rand::{CryptoRng, Rng, RngCore};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::{fmt, panic};
use tfhe::integer::compression_keys::DecompressionKey;
use tfhe::prelude::FheDecrypt;
use tfhe::safe_serialization::safe_deserialize;
#[cfg(feature = "non-wasm")]
use tfhe::shortint::ClassicPBSParameters;
#[cfg(feature = "non-wasm")]
use tfhe::zk::CompactPkeCrs;
#[cfg(feature = "non-wasm")]
use tfhe::Seed;
use tfhe::ServerKey;
use tfhe::{
    ClientKey, ConfigBuilder, FheBool, FheUint1024, FheUint128, FheUint16, FheUint160, FheUint2048,
    FheUint256, FheUint32, FheUint4, FheUint512, FheUint64, FheUint8,
};
use tokio::sync::RwLock;
#[cfg(feature = "non-wasm")]
use tokio_util::task::TaskTracker;
use tonic_health::pb::health_server::{Health, HealthServer};
use tonic_health::server::HealthReporter;

#[cfg(feature = "non-wasm")]
pub(crate) async fn async_generate_fhe_keys<PubS, PrivS, BackS>(
    sk: &PrivateSigKey,
    storage: CentralizedCryptoMaterialStorage<PubS, PrivS, BackS>,
    params: DKGParams,
    keyset_config: StandardKeySetConfig,
    keyset_added_info: Option<KeySetAddedInfo>,
    seed: Option<Seed>,
    eip712_domain: Option<&alloy_sol_types::Eip712Domain>,
) -> anyhow::Result<(FhePubKeySet, KmsFheKeyHandles)>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
    BackS: Storage + Sync + Send + 'static,
{
    let (send, recv) = tokio::sync::oneshot::channel();
    let sk_copy = sk.to_owned();
    let eip712_domain_copy = eip712_domain.cloned();

    let existing_key_handle = match keyset_added_info {
        Some(added_info) => match added_info.compression_keyset_id {
            Some(key_id) => {
                storage.refresh_centralized_fhe_keys(&key_id).await?;
                Some(
                    storage
                        .read_cloned_centralized_fhe_keys_from_cache(&key_id)
                        .await?,
                )
            }
            None => None,
        },
        None => None,
    };

    rayon::spawn_fifo(move || {
        let out = generate_fhe_keys(
            &sk_copy,
            params,
            keyset_config,
            existing_key_handle,
            seed,
            eip712_domain_copy.as_ref(),
        );
        let _ = send.send(out);
    });
    recv.await.map_err(|e| anyhow::anyhow!(e.to_string()))?
}

#[cfg(feature = "non-wasm")]
pub(crate) async fn async_generate_decompression_keys<PubS, PrivS, BackS>(
    storage: CentralizedCryptoMaterialStorage<PubS, PrivS, BackS>,
    keyset1_id: &RequestId,
    keyset2_id: &RequestId,
) -> anyhow::Result<DecompressionKey>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
    BackS: Storage + Sync + Send + 'static,
{
    storage.refresh_centralized_fhe_keys(keyset1_id).await?;
    storage.refresh_centralized_fhe_keys(keyset2_id).await?;

    // we need the private glwe key from keyset 2
    let (client_key_2, _, _, _) = storage
        .read_cloned_centralized_fhe_keys_from_cache(keyset2_id)
        .await?
        .client_key
        .into_raw_parts();
    // we need the private compression key from keyset 1
    let (_, _, compression_private_key_1, _) = storage
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
    rng: AesRng,
    params: DKGParams,
    max_num_bits: Option<u32>,
    eip712_domain: Option<&alloy_sol_types::Eip712Domain>,
) -> anyhow::Result<(CompactPkeCrs, SignedPubDataHandleInternal)> {
    let (send, recv) = tokio::sync::oneshot::channel();
    let sk_copy = sk.to_owned();
    let eip712_domain_copy = eip712_domain.cloned();

    rayon::spawn_fifo(move || {
        let out = gen_centralized_crs(
            &sk_copy,
            &params,
            max_num_bits,
            rng,
            eip712_domain_copy.as_ref(),
        );
        let _ = send.send(out);
    });
    recv.await?
}

#[cfg(feature = "non-wasm")]
pub fn generate_fhe_keys(
    sk: &PrivateSigKey,
    params: DKGParams,
    keyset_config: StandardKeySetConfig,
    existing_key_handle: Option<KmsFheKeyHandles>,
    seed: Option<Seed>,
    eip712_domain: Option<&alloy_sol_types::Eip712Domain>,
) -> anyhow::Result<(FhePubKeySet, KmsFheKeyHandles)> {
    use distributed_decryption::execution::tfhe_internals::{
        switch_and_squash::SwitchAndSquashKey, test_feature::generate_large_keys_from_seed,
    };

    let f = || -> anyhow::Result<(FhePubKeySet, KmsFheKeyHandles)> {
        let client_key = match keyset_config.compression_config {
            KeySetCompressionConfig::Generate => generate_client_fhe_key(params, seed),
            KeySetCompressionConfig::UseExisting => {
                match existing_key_handle {
                    Some(key_handle) => {
                        // we generate the client key as usual,
                        // but we replace the compression private key using an existing compression private key
                        let client_key = generate_client_fhe_key(params, seed);
                        let (client_key, dedicated_compact_private_key, _, tag) = client_key.into_raw_parts();
                        let (_, _, existing_compression_private_key, _) = key_handle.client_key.into_raw_parts();
                        ClientKey::from_raw_parts(client_key, dedicated_compact_private_key, existing_compression_private_key, tag)
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
        );
        let public_key = FhePublicKey::new(&client_key);
        let (sns_client_key, fbsk_out) = generate_large_keys_from_seed(params, &client_key, seed)?;
        let ksk = server_key.as_ref().as_ref().key_switching_key.clone();
        let pks = FhePubKeySet {
            public_key,
            server_key,
            sns_key: Some(SwitchAndSquashKey { fbsk_out, ksk }),
        };
        let handles = KmsFheKeyHandles::new(
            sk,
            client_key,
            sns_client_key,
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
pub fn generate_client_fhe_key(params: DKGParams, seed: Option<Seed>) -> ClientKey {
    let pbs_params: ClassicPBSParameters = params
        .get_params_basics_handle()
        .to_classic_pbs_parameters();
    let compression_params = params
        .get_params_basics_handle()
        .get_compression_decompression_params();
    let config = ConfigBuilder::with_custom_parameters(pbs_params);
    let config = if let Some(dedicated_pk_params) =
        params.get_params_basics_handle().get_dedicated_pk_params()
    {
        config.use_dedicated_compact_public_key_parameters(dedicated_pk_params)
    } else {
        config
    };
    let config = if let Some(params) = compression_params {
        config.enable_compression(params.raw_compression_parameters)
    } else {
        config
    };
    match seed {
        Some(seed) => ClientKey::generate_with_seed(config, seed),
        None => ClientKey::generate(config),
    }
}

/// compute the CRS in the centralized KMS.
#[cfg(feature = "non-wasm")]
pub(crate) fn gen_centralized_crs<R: Rng + CryptoRng>(
    sk: &PrivateSigKey,
    params: &DKGParams,
    max_num_bits: Option<u32>,
    mut rng: R,
    eip712_domain: Option<&alloy_sol_types::Eip712Domain>,
) -> anyhow::Result<(CompactPkeCrs, SignedPubDataHandleInternal)> {
    let internal_pp = make_centralized_public_parameters(
        &params
            .get_params_basics_handle()
            .get_compact_pk_enc_params(),
        max_num_bits.map(|x| x as usize),
        &mut rng,
    )?;
    let pke_params = params
        .get_params_basics_handle()
        .get_compact_pk_enc_params();
    let pp = internal_pp.try_into_tfhe_zk_pok_pp(&pke_params)?;
    let crs_info = crate::engine::base::compute_info(sk, &pp, eip712_domain)?;
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

/// Centralized KMS where keys are stored in a local file
/// Observe that the order of write access MUST be as follows to avoid dead locks:
/// PublicStorage -> PrivateStorage -> FheKeys/XXX_meta_map
#[cfg(feature = "non-wasm")]
pub struct RealCentralizedKms<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
> {
    pub(crate) base_kms: BaseKmsStruct,
    pub(crate) crypto_storage: CentralizedCryptoMaterialStorage<PubS, PrivS, BackS>,
    // Map storing ongoing key generation requests.
    pub(crate) key_meta_map: Arc<RwLock<MetaStore<KeyGenCallValues>>>,
    // Map storing ongoing decryption requests.
    pub(crate) dec_meta_store: Arc<RwLock<MetaStore<DecCallValues>>>,
    // Map storing ongoing reencryption requests.
    pub(crate) reenc_meta_map: Arc<RwLock<MetaStore<ReencCallValues>>>,
    // Map storing ongoing CRS generation requests.
    pub(crate) crs_meta_map: Arc<RwLock<MetaStore<SignedPubDataHandleInternal>>>,
    // Rate limiting
    pub(crate) rate_limiter: RateLimiter,
    // Health reporter for the the grpc server
    pub(crate) health_reporter: Arc<RwLock<HealthReporter>>,
    // Task tacker to ensure that we keep track of all ongoing operations and can cancel them if needed (e.g. during shutdown).
    pub(crate) tracker: Arc<TaskTracker>,
    pub(crate) thread_handles: Arc<RwLock<ThreadHandleGroup>>,
}

/// Perform asynchronous decryption and serialize the result
#[cfg(feature = "non-wasm")]
pub fn central_decrypt<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
    BackS: Storage + Sync + Send + 'static,
>(
    keys: &KmsFheKeyHandles,
    cts: &Vec<TypedCiphertext>,
    metric_tags: Vec<(&'static str, String)>,
) -> anyhow::Result<Vec<TypedPlaintext>> {
    use conf_trace::{
        metrics,
        metrics_names::{OP_DECRYPT_INNER, TAG_TFHE_TYPE},
    };
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

    tracing::info!("Decrypting list of cipher-texts");
    // run the decryption of each ct in the batch in parallel
    cts.par_iter()
        .map(|ct| {
            let inner_timer = metrics::METRICS
                .time_operation(OP_DECRYPT_INNER)
                .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
                .and_then(|b| {
                    b.tags(metric_tags.clone()).map_err(|e| {
                        tracing::warn!("Failed to a tag in party_id, key_id or request_id : {}", e)
                    })
                })
                .map(|b| b.start())
                .map_err(|e| tracing::warn!("Failed to start timer: {:?}", e))
                .ok();
            let fhe_type = ct.fhe_type();
            inner_timer.map(|mut b| b.tag(TAG_TFHE_TYPE, fhe_type.as_str_name()));
            RealCentralizedKms::<PubS, PrivS, BackS>::decrypt(
                keys,
                &ct.ciphertext,
                fhe_type,
                ct.ciphertext_format(),
            )
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Perform asynchronous reencryption and serialize the result
#[cfg(feature = "non-wasm")]
#[allow(clippy::too_many_arguments)]
pub async fn async_reencrypt<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
    BackS: Storage + Sync + Send + 'static,
>(
    keys: &KmsFheKeyHandles,
    sig_key: &PrivateSigKey,
    rng: &mut (impl CryptoRng + RngCore),
    typed_ciphertexts: &[TypedCiphertext],
    req_digest: &[u8],
    client_enc_key: &PublicEncKey,
    client_address: &alloy_primitives::Address,
    domain: &alloy_sol_types::Eip712Domain,
    metric_tags: Vec<(&'static str, String)>,
) -> anyhow::Result<(Vec<TypedSigncryptedCiphertext>, Vec<u8>)> {
    use conf_trace::{
        metrics,
        metrics_names::{OP_REENCRYPT_INNER, TAG_TFHE_TYPE},
    };

    use crate::engine::base::compute_external_reenc_signature;

    let mut all_signcrypted_cts = vec![];
    for typed_ciphertext in typed_ciphertexts {
        let inner_timer = metrics::METRICS
            .time_operation(OP_REENCRYPT_INNER)
            .map_err(|e| tracing::warn!("Failed to create metric: {}", e))
            .and_then(|b| {
                b.tags(metric_tags.clone()).map_err(|e| {
                    tracing::warn!("Failed to a tag in party_id, key_id or request_id : {}", e)
                })
            })
            .map(|b| b.start())
            .map_err(|e| tracing::warn!("Failed to start timer: {:?}", e))
            .ok();
        let high_level_ct = &typed_ciphertext.ciphertext;
        let fhe_type = typed_ciphertext.fhe_type();
        inner_timer.map(|mut b| b.tag(TAG_TFHE_TYPE, fhe_type.as_str_name()));
        let ct_format = typed_ciphertext.ciphertext_format();
        let external_handle = typed_ciphertext.external_handle.clone();
        let signcrypted_ciphertext = RealCentralizedKms::<PubS, PrivS, BackS>::reencrypt(
            keys,
            sig_key,
            rng,
            high_level_ct,
            fhe_type,
            ct_format,
            req_digest,
            client_enc_key,
            client_address,
        )?;
        all_signcrypted_cts.push(TypedSigncryptedCiphertext {
            fhe_type: fhe_type.into(),
            signcrypted_ciphertext,
            external_handle,
        });
    }

    let external_signature =
        compute_external_reenc_signature(sig_key, &all_signcrypted_cts, domain, client_enc_key)?;
    Ok((all_signcrypted_cts, external_signature))
}

// impl fmt::Debug for CentralizedKms, we don't want to include the decryption key in the debug output
#[cfg(feature = "non-wasm")]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    > fmt::Debug for RealCentralizedKms<PubS, PrivS, BackS>
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
        BackS: Storage + Sync + Send + 'static,
    > BaseKms for RealCentralizedKms<PubS, PrivS, BackS>
{
    fn verify_sig<T: Serialize + AsRef<[u8]>>(
        payload: &T,
        signature: &crate::cryptography::internal_crypto_types::Signature,
        verification_key: &PublicSigKey,
    ) -> anyhow::Result<()> {
        BaseKmsStruct::verify_sig(payload, signature, verification_key)
    }

    fn sign<T: Serialize + AsRef<[u8]>>(
        &self,
        msg: &T,
    ) -> anyhow::Result<crate::cryptography::internal_crypto_types::Signature> {
        self.base_kms.sign(msg)
    }

    fn get_serialized_verf_key(&self) -> Vec<u8> {
        self.base_kms.get_serialized_verf_key()
    }

    fn digest<T: ?Sized + AsRef<[u8]>>(msg: &T) -> anyhow::Result<Vec<u8>> {
        BaseKmsStruct::digest(&msg)
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
                            .ok_or(anyhow::anyhow!("missing decompression key"))?,
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
                anyhow::bail!("big compressed ciphertexts are not supported yet");
            }
            CiphertextFormat::BigExpanded => {
                let r = safe_deserialize::<Ciphertext128>(
                    std::io::Cursor::new($serialized_high_level),
                    kms_grpc::rpc_types::SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let raw_res = $keys.sns_client_key.decrypt(&r);
                $fout(raw_res)
            }
        }
    }};
}

fn unsafe_decrypt(
    keys: &KmsFheKeyHandles,
    serialized_high_level: &[u8],
    fhe_type: FheType,
    ct_format: CiphertextFormat,
) -> anyhow::Result<TypedPlaintext> {
    let res = match fhe_type {
        FheType::Ebool => match ct_format {
            CiphertextFormat::SmallCompressed => {
                let hl_ct: FheBool = decompression::tfhe_safe_deserialize_and_uncompress::<FheBool>(
                    keys.decompression_key
                        .as_ref()
                        .ok_or(anyhow::anyhow!("missing decompression key"))?,
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
                anyhow::bail!("big compressed ciphertexts are not supported yet");
            }
            CiphertextFormat::BigExpanded => {
                let r = safe_deserialize::<Ciphertext128>(
                    std::io::Cursor::new(serialized_high_level),
                    kms_grpc::rpc_types::SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let raw_res = keys.sns_client_key.decrypt_128(&r);
                TypedPlaintext::from_bool(if raw_res == 0 {
                    false
                } else if raw_res == 1 {
                    true
                } else {
                    anyhow::bail!("decrypted result is not boolean")
                })
            }
        },
        FheType::Euint4 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint4,
                TypedPlaintext::from_u4,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheType::Euint8 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint8,
                TypedPlaintext::from_u8,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheType::Euint16 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint16,
                TypedPlaintext::from_u16,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheType::Euint32 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint32,
                TypedPlaintext::from_u32,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheType::Euint64 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint64,
                TypedPlaintext::from_u64,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheType::Euint128 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint128,
                TypedPlaintext::from_u128,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheType::Euint160 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint160,
                TypedPlaintext::from_u160,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheType::Euint256 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint256,
                TypedPlaintext::from_u256,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheType::Euint512 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint512,
                TypedPlaintext::from_u512,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheType::Euint1024 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint1024,
                TypedPlaintext::from_u1024,
                ct_format,
                serialized_high_level,
                keys
            )
        }
        FheType::Euint2048 => {
            deserialize_to_low_level_and_decrypt_helper!(
                FheUint2048,
                TypedPlaintext::from_u2048,
                ct_format,
                serialized_high_level,
                keys
            )
        }
    };
    Ok(res)
}

#[cfg(feature = "non-wasm")]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    > Kms for RealCentralizedKms<PubS, PrivS, BackS>
{
    fn decrypt(
        keys: &KmsFheKeyHandles,
        high_level_ct: &[u8],
        fhe_type: FheType,
        ct_format: CiphertextFormat,
    ) -> anyhow::Result<TypedPlaintext> {
        match panic::catch_unwind(|| unsafe_decrypt(keys, high_level_ct, fhe_type, ct_format)) {
            Ok(x) => x,
            Err(_) => Err(anyhow_error_and_log("decryption panicked".to_string())),
        }
    }

    fn reencrypt(
        keys: &KmsFheKeyHandles,
        sig_key: &PrivateSigKey,
        rng: &mut (impl CryptoRng + RngCore),
        ct: &[u8],
        fhe_type: FheType,
        ct_format: CiphertextFormat,
        link: &[u8],
        client_enc_key: &PublicEncKey,
        client_address: &alloy_primitives::Address,
    ) -> anyhow::Result<Vec<u8>> {
        let plaintext = Self::decrypt(keys, ct, fhe_type, ct_format)?;
        // Observe that we encrypt the plaintext itself, this is different from the threshold case
        // where it is first mapped to a Vec<ResiduePolyF4Z128> element
        let signcryption_msg = SigncryptionPayload {
            plaintext,
            link: link.to_vec(),
        };

        let enc_res = signcrypt(
            rng,
            &serialize(&signcryption_msg)?,
            client_enc_key,
            client_address,
            sig_key,
        )?;
        let res = serialize(&enc_res)?;
        tracing::info!("Completed reencryption of ciphertext");

        Ok(res)
    }
}

#[cfg(feature = "non-wasm")]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    > RealCentralizedKms<PubS, PrivS, BackS>
{
    pub async fn new(
        public_storage: PubS,
        private_storage: PrivS,
        backup_storage: Option<BackS>,
        rate_limiter_conf: Option<RateLimiterConfig>,
    ) -> anyhow::Result<(Self, HealthServer<impl Health>)> {
        let sks: HashMap<RequestId, PrivateSigKey> =
            read_all_data_versioned(&private_storage, &PrivDataType::SigningKey.to_string())
                .await?;
        let sk = get_exactly_one(sks).inspect_err(|_e| {
            tracing::error!("signing key hashmap is not exactly 1");
        })?;

        // compute corresponding public key and derive address from private sig key
        let pk = SigningKey::verifying_key(sk.sk());
        tracing::info!(
            "Public address is {}",
            alloy_signer::utils::public_key_to_address(pk)
        );

        let key_info: HashMap<RequestId, KmsFheKeyHandles> =
            read_all_data_versioned(&private_storage, &PrivDataType::FheKeyInfo.to_string())
                .await?;
        let mut pk_map = HashMap::new();
        for id in key_info.keys() {
            let public_key = read_pk_at_request_id(&public_storage, id).await?;
            pk_map.insert(id.clone(), public_key);
        }
        tracing::info!(
            "loaded key_info with key_ids: {:?}",
            key_info
                .keys()
                .map(|rid| &rid.request_id)
                .collect::<Vec<_>>()
        );
        let public_key_info = key_info
            .iter()
            .map(|(id, info)| (id.to_owned(), info.public_key_info.to_owned()))
            .collect();
        let crs_info: HashMap<RequestId, SignedPubDataHandleInternal> =
            read_all_data_versioned(&private_storage, &PrivDataType::CrsInfo.to_string()).await?;

        let crypto_storage = CentralizedCryptoMaterialStorage::new(
            public_storage,
            private_storage,
            backup_storage,
            pk_map,
            key_info,
        );

        let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
        // We will serve as soon as the server is started
        health_reporter
            .set_serving::<CoreServiceEndpointServer<RealCentralizedKms<PubS, PrivS, PrivS>>>()
            .await;
        Ok((
            RealCentralizedKms {
                base_kms: BaseKmsStruct::new(sk)?,
                crypto_storage,
                key_meta_map: Arc::new(RwLock::new(MetaStore::new_from_map(public_key_info))),
                dec_meta_store: Arc::new(RwLock::new(MetaStore::new(DEC_CAPACITY, MIN_DEC_CACHE))),
                reenc_meta_map: Arc::new(RwLock::new(MetaStore::new(DEC_CAPACITY, MIN_DEC_CACHE))),
                crs_meta_map: Arc::new(RwLock::new(MetaStore::new_from_map(crs_info))),
                rate_limiter: RateLimiter::new(rate_limiter_conf.unwrap_or_default()),
                health_reporter: Arc::new(RwLock::new(health_reporter)),
                tracker: Arc::new(TaskTracker::new()),
                thread_handles: Arc::new(RwLock::new(ThreadHandleGroup::new())),
            },
            health_service,
        ))
    }
}

#[tonic::async_trait]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    > Shutdown for RealCentralizedKms<PubS, PrivS, BackS>
{
    async fn shutdown(&self) -> anyhow::Result<()> {
        self.health_reporter
            .write()
            .await
            .set_not_serving::<CoreServiceEndpointServer<Self>>()
            .await;
        self.tracker.close();
        self.tracker.wait().await;
        tracing::info!("Central core service endpoint server shutdown complete.");
        Ok(())
    }
}

#[allow(clippy::let_underscore_future)]
#[cfg(feature = "non-wasm")]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    > Drop for RealCentralizedKms<PubS, PrivS, BackS>
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
    use super::{
        generate_fhe_keys, CentralizedKmsKeys, CentralizedTestingKeys, RealCentralizedKms, Storage,
    };
    #[cfg(feature = "slow_tests")]
    use crate::consts::{
        DEFAULT_CENTRAL_KEYS_PATH, DEFAULT_CENTRAL_KEY_ID, OTHER_CENTRAL_DEFAULT_ID,
    };
    use crate::consts::{DEFAULT_PARAM, OTHER_CENTRAL_TEST_ID, TEST_CENTRAL_KEY_ID};
    use crate::consts::{TEST_CENTRAL_KEYS_PATH, TEST_PARAM};
    use crate::cryptography::internal_crypto_types::PrivateSigKey;
    use crate::cryptography::signcryption::{
        decrypt_signcryption, ephemeral_signcryption_key_generation,
    };
    use crate::engine::base::{compute_handle, compute_info, gen_sig_keys};
    use crate::engine::traits::Kms;
    use crate::util::file_handling::read_element;
    use crate::util::file_handling::write_element;
    use crate::util::key_setup::test_tools::{compute_cipher, EncryptionConfig};
    use crate::vault::storage::{file::FileStorage, ram::RamStorage};
    use crate::vault::storage::{
        store_pk_at_request_id, store_versioned_at_request_id, StorageReader, StorageType,
    };
    use aes_prng::AesRng;
    use distributed_decryption::execution::keyset_config::StandardKeySetConfig;
    use distributed_decryption::execution::tfhe_internals::parameters::DKGParams;
    use kms_grpc::kms::v1::{FheType, RequestId};
    use kms_grpc::rpc_types::{PrivDataType, WrappedPublicKey};
    use rand::{RngCore, SeedableRng};
    use serde::{Deserialize, Serialize};
    use serial_test::serial;
    use std::collections::HashMap;
    use std::{path::Path, sync::Arc};
    use tfhe::named::Named;
    use tfhe::set_server_key;
    use tfhe::Versionize;
    use tfhe::{shortint::ClassicPBSParameters, ConfigBuilder, Seed};
    use tfhe_versionable::VersionsDispatch;
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

    // Construct a storage for private keys
    pub(crate) async fn new_priv_ram_storage_from_existing_keys(
        keys: &CentralizedKmsKeys,
    ) -> anyhow::Result<RamStorage> {
        let mut ram_storage = RamStorage::new(StorageType::PRIV);
        for (cur_req_id, cur_keys) in &keys.key_info {
            store_versioned_at_request_id(
                &mut ram_storage,
                cur_req_id,
                cur_keys,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await?;
        }
        let sk_handle = compute_handle(&keys.sig_pk)?;
        ram_storage
            .store_data(
                &keys.sig_sk,
                &ram_storage.compute_url(&sk_handle, &PrivDataType::SigningKey.to_string())?,
            )
            .await?;
        Ok(ram_storage)
    }

    pub(crate) async fn new_pub_ram_storage_from_existing_keys(
        keys: &HashMap<
            kms_grpc::kms::v1::RequestId,
            distributed_decryption::execution::endpoints::keygen::FhePubKeySet,
        >,
    ) -> anyhow::Result<RamStorage> {
        let mut ram_storage = RamStorage::new(StorageType::PUB);
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
        // below are only used for reencryption
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

        let mut rng = AesRng::seed_from_u64(100);
        let seed = Some(Seed(42));
        let (sig_pk, sig_sk) = gen_sig_keys(&mut rng);
        let (pub_fhe_keys, key_info) = generate_fhe_keys(
            &sig_sk,
            dkg_params,
            StandardKeySetConfig::default(),
            None,
            seed,
            None,
        )
        .unwrap();
        assert!(pub_fhe_keys.sns_key.is_some());
        // check that key_info contains
        let mut key_info_map = HashMap::from([(key_id.to_string().try_into().unwrap(), key_info)]);

        let (other_pub_fhe_keys, other_key_info) = generate_fhe_keys(
            &sig_sk,
            dkg_params,
            StandardKeySetConfig::default(),
            None,
            seed,
            None,
        )
        .unwrap();
        assert!(other_pub_fhe_keys.sns_key.is_some());

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
        let (_sig_pk, sig_sk) = gen_sig_keys(&mut rng);
        assert!(generate_fhe_keys(
            &sig_sk,
            DEFAULT_PARAM,
            StandardKeySetConfig::default(),
            None,
            None,
            None
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
        let wrong_key_handle = RequestId::derive("wrongKeyHandle").unwrap();
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
                None as Option<RamStorage>,
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
        let raw_plaintext = RealCentralizedKms::<FileStorage, FileStorage, FileStorage>::decrypt(
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

        assert_eq!(plaintext.fhe_type(), FheType::Euint64);
    }

    #[tokio::test]
    async fn sunshine_test_reencrypt() {
        sunshine_reencrypt(get_test_keys().await, &TEST_CENTRAL_KEY_ID).await;
    }

    #[tokio::test]
    async fn reencrypt_with_bad_ephemeral_key() {
        simulate_reencrypt(
            SimulationType::BadEphemeralKey,
            get_test_keys().await,
            &TEST_CENTRAL_KEY_ID,
        )
        .await
    }

    #[tokio::test]
    async fn reencrypt_with_bad_sig_key() {
        simulate_reencrypt(
            SimulationType::BadSigKey,
            get_test_keys().await,
            &TEST_CENTRAL_KEY_ID,
        )
        .await
    }

    #[tokio::test]
    async fn reencrypt_with_bad_client_key() {
        simulate_reencrypt(
            SimulationType::BadFheKey,
            get_test_keys().await,
            &TEST_CENTRAL_KEY_ID,
        )
        .await
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    async fn sunshine_default_reencrypt() {
        sunshine_reencrypt(get_default_keys().await, &DEFAULT_CENTRAL_KEY_ID).await;
    }

    #[tokio::test]
    #[serial]
    async fn multiple_test_keys_reencrypt() {
        sunshine_reencrypt(get_test_keys().await, &OTHER_CENTRAL_TEST_ID).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    async fn multiple_default_keys_reencrypt() {
        sunshine_reencrypt(get_default_keys().await, &OTHER_CENTRAL_DEFAULT_ID).await;
    }

    async fn sunshine_reencrypt(keys: &CentralizedTestingKeys, key_handle: &RequestId) {
        simulate_reencrypt(SimulationType::NoError, keys, key_handle).await
    }

    async fn set_wrong_client_key<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    >(
        inner: &RealCentralizedKms<PubS, PrivS, BackS>,
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

    fn set_wrong_sig_key<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    >(
        inner: &mut RealCentralizedKms<PubS, PrivS, BackS>,
        rng: &mut AesRng,
    ) {
        // move to the next state so ensure we're generating a different ecdsa key
        _ = rng.next_u64();
        let wrong_ecdsa_key = k256::ecdsa::SigningKey::random(rng);
        assert_ne!(&wrong_ecdsa_key, inner.base_kms.sig_key.sk());
        inner.base_kms.sig_key = Arc::new(PrivateSigKey::new(wrong_ecdsa_key));
    }

    async fn simulate_reencrypt(
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
                None,
                EncryptionConfig {
                    compression: false,
                    precompute_sns: false,
                },
            )
        };

        let kms = {
            let (mut inner, _health_service) = RealCentralizedKms::new(
                new_pub_ram_storage_from_existing_keys(&keys.pub_fhe_keys)
                    .await
                    .unwrap(),
                new_priv_ram_storage_from_existing_keys(&keys.centralized_kms_keys)
                    .await
                    .unwrap(),
                None as Option<RamStorage>,
                None,
            )
            .await
            .unwrap();
            if sim_type == SimulationType::BadFheKey {
                set_wrong_client_key(&inner, key_handle, keys.params).await;
            }
            if sim_type == SimulationType::BadSigKey {
                set_wrong_sig_key(&mut inner, &mut rng);
            }
            inner
        };
        let link = vec![42_u8, 42, 42];
        let (_client_verf_key, client_sig_key) = gen_sig_keys(&mut rng);
        let client_keys = {
            let mut keys = ephemeral_signcryption_key_generation(&mut rng, &client_sig_key);
            if sim_type == SimulationType::BadEphemeralKey {
                let bad_keys = ephemeral_signcryption_key_generation(&mut rng, &client_sig_key);
                keys.sk = bad_keys.sk;
            }
            keys
        };
        let mut rng = kms.base_kms.new_rng().await;
        let raw_cipher = RealCentralizedKms::<FileStorage, FileStorage, FileStorage>::reencrypt(
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
            &client_keys.pk.enc_key,
            &client_keys.pk.client_address,
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
        let decrypted = decrypt_signcryption(
            &raw_cipher,
            &link,
            &client_keys,
            &keys.centralized_kms_keys.sig_pk,
        );
        if sim_type == SimulationType::BadEphemeralKey {
            assert!(decrypted.is_err());
            assert!(decrypted
                .unwrap_err()
                .to_string()
                .contains("Could not decrypt message"));
            return;
        }
        if sim_type == SimulationType::BadSigKey {
            assert!(decrypted.is_err());
            return;
        }
        let plaintext = decrypted.unwrap();
        if sim_type == SimulationType::BadFheKey {
            assert_ne!(plaintext.as_u64(), msg);
        } else {
            assert_eq!(plaintext.as_u64(), msg);
        }
        assert_eq!(plaintext.fhe_type(), FheType::Euint64);
    }

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug, VersionsDispatch)]
    enum TestTypeVersioned {
        V0(TestType),
    }

    impl Named for TestType {
        const NAME: &'static str = "TestType";
    }

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Versionize)]
    #[versionize(TestTypeVersioned)]
    struct TestType {
        i: u32,
    }

    #[tokio::test]
    async fn ensure_compute_info_consistency() {
        // we need compute info to work without calling the sign function from KMS,
        // i.e., only using a signing key
        // this test makes sure the output is consistent
        let keys = get_test_keys().await;
        let (kms, _health_service) = {
            RealCentralizedKms::new(
                new_pub_ram_storage_from_existing_keys(&keys.pub_fhe_keys)
                    .await
                    .unwrap(),
                new_priv_ram_storage_from_existing_keys(&keys.centralized_kms_keys)
                    .await
                    .unwrap(),
                None as Option<RamStorage>,
                None,
            )
            .await
            .unwrap()
        };

        let value = TestType { i: 32 };
        let expected = compute_info(&kms.base_kms.sig_key, &value, None).unwrap();
        let actual = compute_info(&kms.base_kms.sig_key, &value, None).unwrap();
        assert_eq!(expected, actual);
    }
}
