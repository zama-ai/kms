#![allow(unused_imports)]

use crate::{
    consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT},
    engine::{
        base::{
            compute_info_standard_keygen, retrieve_parameters, BaseKmsStruct, KeyGenMetadata,
            DSEP_PUBDATA_KEY,
        },
        threshold::service::{session::ImmutableSessionMaker, PublicKeyMaterial, ThresholdFheKeys},
        utils::MetricedError,
        validation::{parse_grpc_request_id, parse_optional_grpc_request_id, RequestIdParsingErr},
    },
    util::{meta_store::MetaStore, rate_limiter::RateLimiter},
    vault::storage::{
        crypto_material::ThresholdCryptoMaterialStorage,
        read_context_at_id,
        s3::{
            build_anonymous_s3_client, ReadOnlyS3Storage, ReadOnlyS3StorageGetter,
            RealReadOnlyS3StorageGetter,
        },
        Storage, StorageExt, StorageReader, StorageType,
    },
};
use itertools::Itertools;
use kms_grpc::{
    kms::v1::{Empty, EpochResultResponse, KeyDigest, NewMpcEpochRequest},
    rpc_types::{optional_protobuf_to_alloy_domain, PubDataType},
    ContextId, EpochId, IdentifierError, RequestId,
};
use observability::metrics_names::OP_NEW_EPOCH;
use std::{collections::HashMap, sync::Arc};
use tfhe::ServerKey;
use threshold_fhe::{
    execution::{
        endpoints::reshare_sk::{
            ResharePreprocRequired, ReshareSecretKeys, SecureReshareSecretKeys,
        },
        runtime::sessions::session_parameters::GenericParameterHandles,
        small_execution::offline::{Preprocessing, SecureSmallPreprocessing},
        tfhe_internals::public_keysets::FhePubKeySet,
    },
    hashing::hash_element,
    networking::NetworkMode,
};
use tokio::sync::RwLock;
use tokio_util::task::TaskTracker;
use tonic::{Request, Response, Status};

const ERR_SERVER_KEY_DIGEST_MISMATCH: &str = "Server key digest mismatch";
const ERR_PUBLIC_KEY_DIGEST_MISMATCH: &str = "Public key digest mismatch";
const ERR_FAILED_TO_FETCH_PUBLIC_MATERIALS: &str = "Failed to fetch public materials";

/// Verify key digests using raw bytes from storage.
/// This avoids re-serializing the keys, which would produce different bytes
/// if there was a version upgrade since the original digest was computed.
fn verify_key_digest_from_bytes(
    server_key_bytes: &[u8],
    public_key_bytes: &[u8],
    expected_server_key_digest: &[u8],
    expected_public_key_digest: &[u8],
) -> anyhow::Result<()> {
    let actual_server_key_digest = hash_element(&DSEP_PUBDATA_KEY, server_key_bytes);
    let actual_public_key_digest = hash_element(&DSEP_PUBDATA_KEY, public_key_bytes);

    if actual_server_key_digest != expected_server_key_digest {
        anyhow::bail!(ERR_SERVER_KEY_DIGEST_MISMATCH);
    }
    if actual_public_key_digest != expected_public_key_digest {
        anyhow::bail!(ERR_PUBLIC_KEY_DIGEST_MISMATCH);
    }

    Ok(())
}

fn bucket_from_domain(url: &url::Url) -> anyhow::Result<String> {
    let Some(domain) = url.domain() else {
        anyhow::bail!("Cannot deduce the bucket name from url {:?}", url);
    };
    let domain_parts = domain.split('.').collect::<Vec<&str>>();
    if domain_parts.len() < 2 {
        tracing::warn!(
            "Cannot deduce the bucket name from url {:?}. Returning default bucket used in testing",
            url
        );
        Ok("kms".to_owned())
    } else {
        Ok(domain_parts[0].to_owned())
    }
}

/// Find the AWS region from an S3 bucket URL.
/// For example:
/// The URL https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/ will return "eu-west-1".
pub(crate) fn find_region_from_s3_url(s3_bucket_url: &String) -> anyhow::Result<String> {
    let parsed_url = url::Url::parse(s3_bucket_url.as_str())?;
    let domain = parsed_url
        .domain()
        .ok_or(anyhow::anyhow!("Cannot parse domain from URL"))?;
    let domain_parts: Vec<&str> = domain.split('.').collect();
    if domain_parts.len() < 4 {
        tracing::warn!(
            "Cannot deduce the region from url {:?}. Using default us-east-1",
            s3_bucket_url
        );
        return Ok("us-east-1".to_owned()); // default region
    }
    let dot_com_pos = domain_parts.len() - 1;
    let expected_s3_pos = dot_com_pos - 3;
    let expected_region_pos = dot_com_pos - 2;
    // e.g s3.eu-west-1.amazonaws.com
    if domain_parts[expected_s3_pos] == "s3" {
        Ok(domain_parts[expected_region_pos].to_owned())
    } else {
        tracing::warn!(
            "Cannot deduce the region from url {:?}. Using default us-east-1",
            s3_bucket_url
        );
        Ok("us-east-1".to_owned()) // default region
    }
}

/// Split an S3 URL into its base URL and bucket name.
/// For example:
/// The URL https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/ will be split into
/// https://s3.eu-west-1.amazonaws.com and zama-zws-dev-tkms-b6q87
/// where the first part is the URL and the second part is the bucket name.
///
/// Code is adapted from
/// https://github.com/zama-ai/fhevm/blob/dac153662361758c9a563e766473692f8acf1074/coprocessor/fhevm-engine/gw-listener/src/aws_s3.rs#L140C1-L174C1
fn split_url(s3_bucket_url: &String) -> anyhow::Result<(String, String)> {
    // e.g BBBBBB.s3.bla.bli.amazonaws.blu, the bucket is part of the domain
    tracing::info!("Splitting S3 url: {}", s3_bucket_url);
    let parsed_url_and_bucket = url::Url::parse(s3_bucket_url.as_str())?;
    let mut bucket = parsed_url_and_bucket
        .path()
        .trim_start_matches('/')
        .to_owned();

    if bucket.is_empty() {
        tracing::warn!(
            "Bucket is empty, attempting to deduce from domain {:?}",
            parsed_url_and_bucket
        );
        // e.g BBBBBB.s3.eu-west-1.amazonaws.com, the bucket is part of the domain
        bucket = bucket_from_domain(&parsed_url_and_bucket)?;
        let url = s3_bucket_url
            .replace(&(bucket.clone() + "."), "")
            .trim_end_matches('/')
            .to_owned();
        tracing::info!(s3_bucket_url, url, bucket, "Bucket from domain");
        Ok((url, bucket))
    } else {
        let url = s3_bucket_url
            .replace(&bucket, "")
            .trim_end_matches('/')
            .to_owned();
        tracing::info!(s3_bucket_url, url, bucket, "Parsed S3 url");
        Ok((url, bucket))
    }
}

async fn fetch_public_materials_from_peers<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
    G: ReadOnlyS3StorageGetter<R>,
    R: StorageReader,
>(
    crypto_storage: &ThresholdCryptoMaterialStorage<PubS, PrivS>,
    key_id: &RequestId,
    context_id: &ContextId,
    key_digests: &HashMap<PubDataType, Vec<u8>>,
    ro_storage_getter: &G,
) -> anyhow::Result<FhePubKeySet> {
    // obtain the digests
    let expected_public_key_digest = key_digests
        .get(&PubDataType::PublicKey)
        .ok_or_else(|| anyhow::anyhow!("missing digest for public key"))?;

    let expected_server_key_digest = key_digests
        .get(&PubDataType::ServerKey)
        .ok_or_else(|| anyhow::anyhow!("missing digest for server key"))?;

    // fetch the context info
    let context = {
        let priv_storage = crypto_storage.get_private_storage();
        let guard_storage = priv_storage.lock().await;
        read_context_at_id(&(*guard_storage), context_id).await?
    };

    let mut errors = Vec::new();
    for node in context.mpc_nodes {
        // so simplify logic, it's ok to iterate over myself too
        //
        // the public storage URL consists of the bucket name and the URL
        // we need to parse this information accordingly
        let (url, bucket) = split_url(&node.public_storage_url)?;
        let region = find_region_from_s3_url(&node.public_storage_url)?;

        // this is not an operation that is frequently used, so we can create a new s3 client each time
        let s3_client = build_anonymous_s3_client(url::Url::parse(&url)?, region).await?;
        let pub_storage = ro_storage_getter.get_storage(
            s3_client,
            bucket,
            StorageType::PUB,
            node.public_storage_prefix.as_deref(),
            None,
        )?;

        // Load raw bytes from storage to verify digests before deserializing.
        // This avoids issues with version upgrades where re-serialization produces different bytes.
        let public_key_bytes = pub_storage
            .load_bytes(key_id, &PubDataType::PublicKey.to_string())
            .await;

        let server_key_bytes = pub_storage
            .load_bytes(key_id, &PubDataType::ServerKey.to_string())
            .await;

        match (public_key_bytes, server_key_bytes) {
            (Ok(public_key_bytes), Ok(server_key_bytes)) => {
                // Verify digests using raw bytes
                match verify_key_digest_from_bytes(
                    &server_key_bytes,
                    &public_key_bytes,
                    expected_server_key_digest,
                    expected_public_key_digest,
                ) {
                    Ok(()) => {
                        // Only deserialize after digest verification passes
                        let public_key: tfhe::CompactPublicKey =
                            tfhe::safe_serialization::safe_deserialize(
                                std::io::Cursor::new(&public_key_bytes),
                                crate::consts::SAFE_SER_SIZE_LIMIT,
                            )
                            .map_err(|e| {
                                anyhow::anyhow!("Failed to deserialize public key: {}", e)
                            })?;

                        let server_key: ServerKey = tfhe::safe_serialization::safe_deserialize(
                            std::io::Cursor::new(&server_key_bytes),
                            crate::consts::SAFE_SER_SIZE_LIMIT,
                        )
                        .map_err(|e| anyhow::anyhow!("Failed to deserialize server key: {}", e))?;

                        return Ok(FhePubKeySet {
                            public_key,
                            server_key,
                        });
                    }
                    Err(e) => {
                        let msg = format!("Verification failed from peer {}: {}", node.party_id, e);
                        tracing::warn!(msg);
                        errors.push(msg);
                        continue;
                    }
                }
            }
            (Err(e), _) => {
                let msg = format!(
                    "{} from peer {}: {e:?}",
                    ERR_FAILED_TO_FETCH_PUBLIC_MATERIALS, node.party_id
                );
                tracing::warn!(msg);
                errors.push(msg);
            }
            (_, Err(e)) => {
                let msg = format!(
                    "{} from peer {}: {e:?}",
                    ERR_FAILED_TO_FETCH_PUBLIC_MATERIALS, node.party_id
                );
                tracing::warn!(msg);
                errors.push(msg);
            }
        }
    }

    anyhow::bail!(
        "Failed to fetch valid public materials from any peer, error count: {}, first error: {:?}, last error: {:?}",
        errors.len(),
        errors[0],
        errors[errors.len() - 1],
    );
}

// TODO(https://github.com/zama-ai/kms-internal/issues/2881) for now we do not support compressed keys
/// Attempt to get and verify the public materials needed for resharing.
pub(crate) async fn get_verified_public_materials<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
    G: ReadOnlyS3StorageGetter<R>,
    R: StorageReader,
>(
    crypto_storage: &ThresholdCryptoMaterialStorage<PubS, PrivS>,
    request_id: &RequestId,
    key_id: &RequestId,
    context_id: &ContextId,
    key_digests: &HashMap<PubDataType, Vec<u8>>,
    ro_storage_getter: &G,
) -> Result<FhePubKeySet, MetricedError> {
    // obtain the digests
    let expected_public_key_digest = key_digests.get(&PubDataType::PublicKey).ok_or_else(|| {
        MetricedError::new(
            OP_NEW_EPOCH,
            Some(*request_id),
            anyhow::anyhow!("missing digest for public key"),
            tonic::Code::Internal,
        )
    })?;

    let expected_server_key_digest = key_digests.get(&PubDataType::ServerKey).ok_or_else(|| {
        MetricedError::new(
            OP_NEW_EPOCH,
            Some(*request_id),
            anyhow::anyhow!("missing digest for server key"),
            tonic::Code::Internal,
        )
    })?;

    // Load raw bytes from own public storage to verify digests before deserializing.
    // This avoids issues with version upgrades where re-serialization produces different bytes.
    let (public_key_bytes_res, server_key_bytes_res): (
        anyhow::Result<Vec<u8>>,
        anyhow::Result<Vec<u8>>,
    ) = {
        let pub_storage = crypto_storage.inner.get_public_storage();
        let guard_storage = pub_storage.lock().await;

        let public_key_bytes = guard_storage
            .load_bytes(key_id, &PubDataType::PublicKey.to_string())
            .await;

        let server_key_bytes = guard_storage
            .load_bytes(key_id, &PubDataType::ServerKey.to_string())
            .await;

        (public_key_bytes, server_key_bytes)
    };

    match (public_key_bytes_res, server_key_bytes_res) {
        (Ok(public_key_bytes), Ok(server_key_bytes)) => {
            // Verify digests using raw bytes
            verify_key_digest_from_bytes(
                &server_key_bytes,
                &public_key_bytes,
                expected_server_key_digest,
                expected_public_key_digest,
            )
            .map_err(|e| {
                MetricedError::new(
                    OP_NEW_EPOCH,
                    Some(*request_id),
                    anyhow::anyhow!("Key digest verification failed: {}", e),
                    tonic::Code::Internal,
                )
            })?;

            // Only deserialize after digest verification passes
            let public_key: tfhe::CompactPublicKey = tfhe::safe_serialization::safe_deserialize(
                std::io::Cursor::new(&public_key_bytes),
                crate::consts::SAFE_SER_SIZE_LIMIT,
            )
            .map_err(|e| {
                MetricedError::new(
                    OP_NEW_EPOCH,
                    Some(*request_id),
                    anyhow::anyhow!("Failed to deserialize public key: {}", e),
                    tonic::Code::Internal,
                )
            })?;

            let server_key: ServerKey = tfhe::safe_serialization::safe_deserialize(
                std::io::Cursor::new(&server_key_bytes),
                crate::consts::SAFE_SER_SIZE_LIMIT,
            )
            .map_err(|e| {
                MetricedError::new(
                    OP_NEW_EPOCH,
                    Some(*request_id),
                    anyhow::anyhow!("Failed to deserialize server key: {}", e),
                    tonic::Code::Internal,
                )
            })?;

            Ok(FhePubKeySet {
                public_key,
                server_key,
            })
        }
        _ => {
            // if local retrieval fails, attempt to fetch from s3 of another party
            fetch_public_materials_from_peers::<_, _, G, R>(
                crypto_storage,
                key_id,
                context_id,
                key_digests,
                ro_storage_getter,
            )
            .await
            .map_err(|e| {
                MetricedError::new(
                    OP_NEW_EPOCH,
                    Some(*request_id),
                    anyhow::anyhow!("Failed to fetch public materials from peers: {}", e),
                    tonic::Code::Internal,
                )
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::collections::HashMap;

    use crate::engine::base::safe_serialize_hash_element_versioned;
    use crate::engine::context::ContextInfo;
    use crate::engine::context::NodeInfo;
    use crate::engine::context::SoftwareVersion;
    use crate::engine::threshold::service::reshare_utils::fetch_public_materials_from_peers;
    use crate::engine::threshold::service::reshare_utils::get_verified_public_materials;
    use crate::engine::threshold::service::reshare_utils::ERR_FAILED_TO_FETCH_PUBLIC_MATERIALS;
    use crate::engine::threshold::service::reshare_utils::ERR_SERVER_KEY_DIGEST_MISMATCH;
    use crate::vault::storage::crypto_material::ThresholdCryptoMaterialStorage;
    use crate::vault::storage::ram::RamStorage;
    use crate::vault::storage::s3::DummyReadOnlyS3Storage;
    use crate::vault::storage::s3::DummyReadOnlyS3StorageGetter;
    use crate::vault::storage::store_versioned_at_request_id;
    use aes_prng::AesRng;
    use kms_grpc::rpc_types::PubDataType;
    use kms_grpc::ContextId;
    use kms_grpc::RequestId;
    use rand::SeedableRng;
    use tfhe::shortint::ClassicPBSParameters;
    use tfhe::CompactPublicKey;
    use tfhe::ServerKey;

    #[test]
    fn test_split_devnet_url() {
        let (url, bucket) = super::split_url(
            &"https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/".to_string(),
        )
        .unwrap();
        assert_eq!(url.as_str(), "https://s3.eu-west-1.amazonaws.com");
        assert_eq!(bucket.as_str(), "zama-zws-dev-tkms-b6q87");
    }

    async fn setup_public_materials_test(
        key_id: RequestId,
        context_id: ContextId,
        two_nodes: bool,
    ) -> (
        ThresholdCryptoMaterialStorage<RamStorage, RamStorage>,
        HashMap<PubDataType, Vec<u8>>,
        DummyReadOnlyS3StorageGetter,
        (ServerKey, CompactPublicKey),
    ) {
        // create memory storage that contains a public key and server key
        let mut ram_storage = RamStorage::new();

        // generate the keys
        let params = crate::consts::TEST_PARAM;
        let pbs_params: ClassicPBSParameters = params
            .get_params_basics_handle()
            .to_classic_pbs_parameters();
        let config = tfhe::ConfigBuilder::with_custom_parameters(pbs_params);
        let client_key = tfhe::ClientKey::generate(config);
        let server_key = client_key.generate_server_key();
        let public_key = CompactPublicKey::new(&client_key);

        // generate digests
        let server_key_digest = safe_serialize_hash_element_versioned(
            &crate::engine::base::DSEP_PUBDATA_KEY,
            &server_key,
        )
        .unwrap();
        let public_key_digest = safe_serialize_hash_element_versioned(
            &crate::engine::base::DSEP_PUBDATA_KEY,
            &public_key,
        )
        .unwrap();
        let key_digests: HashMap<PubDataType, Vec<u8>> = HashMap::from_iter([
            (PubDataType::ServerKey, server_key_digest),
            (PubDataType::PublicKey, public_key_digest),
        ]);

        // store the keys in ram storage
        store_versioned_at_request_id(
            &mut ram_storage,
            &key_id,
            &public_key,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();

        store_versioned_at_request_id(
            &mut ram_storage,
            &key_id,
            &server_key,
            &PubDataType::ServerKey.to_string(),
        )
        .await
        .unwrap();

        // create dummy crypto storage
        let crypto_storage = ThresholdCryptoMaterialStorage::new(
            RamStorage::new(),
            RamStorage::new(),
            None,
            HashMap::new(),
        );

        let context_info = ContextInfo {
            mpc_nodes: [
                vec![NodeInfo {
                    mpc_identity: "Node1".to_string(),
                    party_id: 1,
                    verification_key: None,
                    external_url: "http://localhost:12345".to_string(),
                    ca_cert: None,
                    // the storage url does not matter as we're using the mock
                    public_storage_url:
                        "https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/".to_string(),
                    public_storage_prefix: None,
                    extra_verification_keys: vec![],
                }],
                if two_nodes {
                    vec![NodeInfo {
                        mpc_identity: "Node2".to_string(),
                        party_id: 2,
                        verification_key: None,
                        external_url: "http://localhost:12345".to_string(),
                        ca_cert: None,
                        // the storage url does not matter as we're using the mock
                        public_storage_url:
                            "https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/"
                                .to_string(),
                        public_storage_prefix: None,
                        extra_verification_keys: vec![],
                    }]
                } else {
                    vec![]
                },
            ]
            .concat(),
            context_id,
            software_version: SoftwareVersion {
                major: 0,
                minor: 1,
                patch: 0,
                tag: None,
                digests: BTreeSet::from([hex::decode("00112233445566778899aabbccddeeff").unwrap()]),
            },
            threshold: 0,
            pcr_values: vec![],
        };

        crypto_storage
            .inner
            .write_context_info(&context_id, &context_info)
            .await
            .unwrap();

        let ro_storage_getter = DummyReadOnlyS3StorageGetter {
            counter: RefCell::new(0),
            ram_storages: vec![ram_storage],
        };

        (
            crypto_storage,
            key_digests,
            ro_storage_getter,
            (server_key, public_key),
        )
    }

    #[tokio::test]
    async fn empty_storage_fetch_public_materials_from_peers() {
        let mut rng = AesRng::seed_from_u64(2332);
        let key_id = RequestId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng);
        let (crypto_storage, key_digests, _ro_storage_getter, _) =
            setup_public_materials_test(key_id, context_id, false).await;
        {
            // negative test
            // use empty storage to trigger error
            let ro_storage_getter = DummyReadOnlyS3StorageGetter {
                counter: RefCell::new(0),
                ram_storages: vec![RamStorage::new()],
            };
            let err = fetch_public_materials_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
                &crypto_storage,
                &key_id,
                &context_id,
                &key_digests,
                &ro_storage_getter,
            )
            .await
            .unwrap_err();
            assert!(err
                .to_string()
                .contains(ERR_FAILED_TO_FETCH_PUBLIC_MATERIALS));
        }
    }

    #[tokio::test]
    async fn wrong_digest_fetch_public_materials_from_peers() {
        let mut rng = AesRng::seed_from_u64(2332);
        let key_id = RequestId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng);
        let (crypto_storage, _key_digests, ro_storage_getter, _) =
            setup_public_materials_test(key_id, context_id, false).await;
        {
            // negative test
            // use wrong digests to trigger error
            let wrong_key_digests: HashMap<PubDataType, Vec<u8>> = HashMap::from_iter([
                (PubDataType::ServerKey, vec![0, 1, 2, 4]),
                (PubDataType::PublicKey, vec![3, 4, 5, 6]),
            ]);
            let err = fetch_public_materials_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
                &crypto_storage,
                &key_id,
                &context_id,
                &wrong_key_digests,
                &ro_storage_getter,
            )
            .await
            .unwrap_err();
            assert!(err.to_string().contains(ERR_SERVER_KEY_DIGEST_MISMATCH));
        }
    }

    #[tokio::test]
    async fn sunshine_fetch_public_materials_from_peers() {
        let mut rng = AesRng::seed_from_u64(2332);
        let key_id = RequestId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng);
        let (crypto_storage, key_digests, ro_storage_getter, _) =
            setup_public_materials_test(key_id, context_id, true).await;

        {
            // sunshine
            // use the dummy s3 storage to fetch the keys from ram storage
            let _keyset = fetch_public_materials_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
                &crypto_storage,
                &key_id,
                &context_id,
                &key_digests,
                &ro_storage_getter,
            )
            .await
            .unwrap();

            // we should've used the read-only storage, so counter should be 1
            assert_eq!(*ro_storage_getter.counter.borrow(), 1);
        }
        {
            // sunshine
            // use two dummy s3 storage, where the first one is broken, so ro_storage_getter should be called twice
            let two_ro_storage_getter = DummyReadOnlyS3StorageGetter {
                counter: RefCell::new(0),
                ram_storages: vec![RamStorage::new(), ro_storage_getter.ram_storages[0].clone()],
            };

            let _keyset = fetch_public_materials_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
                &crypto_storage,
                &key_id,
                &context_id,
                &key_digests,
                &two_ro_storage_getter,
            )
            .await
            .unwrap();

            // the first storage should've failed, the second one should work, so counter should be 2
            assert_eq!(*two_ro_storage_getter.counter.borrow(), 2);
        }
    }

    #[tokio::test]
    async fn bad_digests_get_verified_public_materials() {
        let mut rng = AesRng::seed_from_u64(2332);
        let req_id = RequestId::new_random(&mut rng);
        let key_id = RequestId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng);
        let (crypto_storage, _key_digests, ro_storage_getter, (server_key, public_key)) =
            setup_public_materials_test(key_id, context_id, false).await;

        {
            // we make sure that keys are present in my own public storage
            let public_storage = crypto_storage.inner.get_public_storage();
            {
                let mut guard_storage = public_storage.lock().await;
                store_versioned_at_request_id(
                    &mut (*guard_storage),
                    &key_id,
                    &public_key,
                    &PubDataType::PublicKey.to_string(),
                )
                .await
                .unwrap();
                store_versioned_at_request_id(
                    &mut (*guard_storage),
                    &key_id,
                    &server_key,
                    &PubDataType::ServerKey.to_string(),
                )
                .await
                .unwrap();
            }

            let bad_key_digests: HashMap<PubDataType, Vec<u8>> = HashMap::from_iter([
                (PubDataType::ServerKey, vec![9, 8, 7, 6]),
                (PubDataType::PublicKey, vec![5, 4, 3, 2]),
            ]);
            let err = get_verified_public_materials(
                &crypto_storage,
                &req_id,
                &key_id,
                &context_id,
                &bad_key_digests,
                &ro_storage_getter,
            )
            .await
            .unwrap_err();

            assert!(format!("{err:?}").contains(ERR_SERVER_KEY_DIGEST_MISMATCH));

            // we should've used the public storage directly, so the counter here should be 0
            assert_eq!(*ro_storage_getter.counter.borrow(), 0);
        }
    }

    #[tokio::test]
    async fn sunshine_get_verified_public_materials() {
        let mut rng = AesRng::seed_from_u64(2332);
        let req_id = RequestId::new_random(&mut rng);
        let key_id = RequestId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng);
        let (crypto_storage, key_digests, ro_storage_getter, (server_key, public_key)) =
            setup_public_materials_test(key_id, context_id, false).await;

        {
            // sunshine
            // if key materials are present locally, we expect giving an empty RO storage getter
            // and an empty key_digests to still work
            let public_storage = crypto_storage.inner.get_public_storage();
            {
                let mut guard_storage = public_storage.lock().await;
                store_versioned_at_request_id(
                    &mut (*guard_storage),
                    &key_id,
                    &public_key,
                    &PubDataType::PublicKey.to_string(),
                )
                .await
                .unwrap();
                store_versioned_at_request_id(
                    &mut (*guard_storage),
                    &key_id,
                    &server_key,
                    &PubDataType::ServerKey.to_string(),
                )
                .await
                .unwrap();
            }

            let _key = get_verified_public_materials(
                &crypto_storage,
                &req_id,
                &key_id,
                &context_id,
                &key_digests,
                &ro_storage_getter,
            )
            .await
            .unwrap();

            // we should've used the public storage directly, so the counter here should be 0
            assert_eq!(*ro_storage_getter.counter.borrow(), 0);
        }
    }

    #[test]
    fn test_find_region() {
        let url = "https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/".to_string();
        let region = super::find_region_from_s3_url(&url).unwrap();
        assert_eq!(region.as_str(), "eu-west-1");

        let url = "https://s3.us-west-1.amazonaws.com/zama-zws-dev-tkms-b6q87/".to_string();
        let region = super::find_region_from_s3_url(&url).unwrap();
        assert_eq!(region.as_str(), "us-west-1");

        let url = "https://s3.amazonaws.com/zama-zws-dev-tkms-b6q87/".to_string();
        let region = super::find_region_from_s3_url(&url).unwrap();
        assert_eq!(region.as_str(), "us-east-1");

        let url = "http://dev-s3-mock:9000".to_string();
        let region = super::find_region_from_s3_url(&url).unwrap();
        assert_eq!(region.as_str(), "us-east-1");
    }
}
