use crate::{
    engine::{
        context::ContextInfo,
        utils::{
            MetricedError, verify_compressed_key_digest_from_bytes, verify_crs_digest_from_bytes,
            verify_key_digest_from_bytes, verify_public_key_digest_from_bytes,
        },
    },
    vault::storage::{
        Storage, StorageExt, StorageReader, StorageType, StoreWriteOutcome,
        crypto_material::ThresholdCryptoMaterialStorage,
        read_context_at_id,
        s3::{
            ReadOnlyS3StorageGetter, build_anonymous_s3_client, find_region_from_s3_url, split_url,
        },
    },
};
use kms_grpc::{ContextId, RequestId, rpc_types::PubDataType};
use observability::metrics_names::OP_NEW_EPOCH;
use std::collections::HashMap;
use tfhe::{ServerKey, xof_key_set::CompressedXofKeySet, zk::CompactPkeCrs};
use threshold_execution::tfhe_internals::public_keysets::FhePubKeySet;

const ERR_FAILED_TO_FETCH_PUBLIC_MATERIALS: &str = "Failed to fetch public materials";

/// Enum to represent verified public keys that can be either uncompressed or compressed.
/// This allows resharing to work with both standard keys (ServerKey + PublicKey) and
/// compressed keys (CompressedXofKeySet).
// It's ok to have a big enum here since the way this type is used is only temporary.
#[expect(clippy::large_enum_variant)]
pub(crate) enum VerifiedFheKeys {
    /// Standard uncompressed keyset with server key and public key
    Uncompressed(FhePubKeySet),
    /// Compressed keyset
    Compressed(CompressedXofKeySet),
}

impl std::fmt::Debug for VerifiedFheKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifiedFheKeys::Uncompressed(_) => {
                write!(f, "VerifiedPublicKeys::Uncompressed(...)")
            }
            VerifiedFheKeys::Compressed(_) => {
                write!(f, "VerifiedPublicKeys::Compressed(...)")
            }
        }
    }
}

/// The public keys of a key that is reshared, verified against the digests in the request.
///
/// A party that joins in the new epoch starts without the public material of the reshared keys,
/// but must hold it once the epoch exists. Such a party fetches the material from a peer, and
/// then also keeps the raw bytes it verified, so that they can be stored as-is: our public
/// storage then holds exactly the bytes the digests were computed from.
pub(crate) struct VerifiedPublicMaterial {
    keys: VerifiedFheKeys,
    /// Raw bytes per public data type, if the material was fetched from a peer. Empty if it was
    /// loaded from our own public storage.
    peer_bytes: Vec<(PubDataType, Vec<u8>)>,
}

impl std::fmt::Debug for VerifiedPublicMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedPublicMaterial")
            .field("keys", &self.keys)
            .field(
                "peer_bytes",
                &self
                    .peer_bytes
                    .iter()
                    .map(|(data_type, bytes)| (data_type, bytes.len()))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl VerifiedPublicMaterial {
    /// Material loaded from our own public storage, which needs not be stored again.
    pub(crate) fn from_own_storage(keys: VerifiedFheKeys) -> Self {
        Self {
            keys,
            peer_bytes: vec![],
        }
    }

    /// Material fetched from a peer, together with the verified raw bytes it was deserialized from.
    pub(crate) fn from_peer(
        keys: VerifiedFheKeys,
        peer_bytes: Vec<(PubDataType, Vec<u8>)>,
    ) -> Self {
        Self { keys, peer_bytes }
    }

    /// The verified public keys.
    #[cfg(test)]
    pub(crate) fn keys(&self) -> &VerifiedFheKeys {
        &self.keys
    }

    /// The raw bytes fetched from a peer, per public data type. Empty if the material was loaded
    /// from our own public storage.
    #[cfg(test)]
    pub(crate) fn peer_bytes(&self) -> &[(PubDataType, Vec<u8>)] {
        &self.peer_bytes
    }

    /// Split into the verified public keys and the raw bytes fetched from a peer.
    pub(crate) fn into_parts(self) -> (VerifiedFheKeys, Vec<(PubDataType, Vec<u8>)>) {
        (self.keys, self.peer_bytes)
    }

    pub(crate) fn has_oprf_key(&self) -> bool {
        match &self.keys {
            VerifiedFheKeys::Uncompressed(fhe_pubkeys) => fhe_pubkeys.server_key.has_oprf_key(),
            VerifiedFheKeys::Compressed(compressed_keyset) => compressed_keyset.has_oprf_key(),
        }
    }
}

/// Store `entries` of raw public bytes fetched from peers in `pub_storage`.
///
/// An entry that already exists is kept only if its bytes exactly match the fetched bytes.
/// Returns the entries created by this call, so that a failed reshare can delete them again,
/// together with the outcome of the writes. The writes stop at the first error. An entry whose
/// write failed is returned too, since a backend may apply a write and still report an error.
pub(crate) async fn store_peer_public_bytes<PubS: Storage>(
    pub_storage: &mut PubS,
    entries: &[(RequestId, PubDataType, Vec<u8>)],
) -> (Vec<(RequestId, PubDataType)>, anyhow::Result<()>) {
    let mut created = Vec::new();
    for (data_id, data_type, bytes) in entries {
        let data_type_str = data_type.to_string();
        created.push((*data_id, *data_type));
        match pub_storage
            .store_bytes(bytes, data_id, &data_type_str)
            .await
        {
            Ok(StoreWriteOutcome::Created) => {}
            Ok(StoreWriteOutcome::SkippedExisting) => {
                // The existing entry is not ours to delete if this reshare later fails.
                created.pop();
                match pub_storage.load_bytes(data_id, &data_type_str).await {
                    Ok(existing_bytes) if existing_bytes == *bytes => {}
                    Ok(_) => {
                        return (
                            created,
                            Err(anyhow::anyhow!(
                                "Existing {data_type} of {data_id} differs from the bytes fetched from a peer"
                            )),
                        );
                    }
                    Err(e) => {
                        return (
                            created,
                            Err(e.context(format!(
                                "Failed to verify existing {data_type} of {data_id} against the bytes fetched from a peer"
                            ))),
                        );
                    }
                }
            }
            Err(e) => {
                return (
                    created,
                    Err(e.context(format!(
                        "Failed to store {data_type} of {data_id} fetched from a peer"
                    ))),
                );
            }
        }
    }
    (created, Ok(()))
}

async fn fetch_context_from_storage<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
>(
    crypto_storage: &ThresholdCryptoMaterialStorage<PubS, PrivS>,
    context_id: &ContextId,
) -> anyhow::Result<ContextInfo> {
    let priv_storage = crypto_storage.get_private_storage();
    let guard_storage = priv_storage.lock().await;
    read_context_at_id(&(*guard_storage), context_id).await
}

async fn fetch_public_fhe_materials_from_peers<
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
) -> anyhow::Result<VerifiedPublicMaterial> {
    // Determine if we're dealing with compressed or uncompressed keys
    let is_compressed = key_digests.contains_key(&PubDataType::CompressedXofKeySet);

    // fetch the context info
    let context = fetch_context_from_storage(crypto_storage, context_id).await?;

    let mut errors = Vec::new();
    for node in context.mpc_nodes {
        // so simplify logic, it's ok to iterate over myself too
        //
        // the public storage URL consists of the bucket name and the URL
        // we need to parse this information accordingly
        let (protocol, domain, bucket) = split_url(&node.public_storage_url)?;
        let url = format!("{protocol}{domain}");
        let region = find_region_from_s3_url(&node.public_storage_url)?;

        // this is not an operation that is frequently used, so we can create a new s3 client each time
        let s3_client = build_anonymous_s3_client(&url, region).await?;
        let pub_storage = ro_storage_getter.get_storage(
            s3_client,
            bucket,
            StorageType::PUB,
            node.public_storage_prefix.as_deref(),
        )?;

        if is_compressed {
            // Handle compressed keys
            let expected_compressed_digest = key_digests
                .get(&PubDataType::CompressedXofKeySet)
                .ok_or_else(|| anyhow::anyhow!("missing digest for compressed xof keyset"))?;
            let expected_public_key_digest = key_digests
                .get(&PubDataType::PublicKey)
                .ok_or_else(|| anyhow::anyhow!("missing digest for public key"))?;

            let compressed_keyset_bytes = pub_storage
                .load_bytes(key_id, &PubDataType::CompressedXofKeySet.to_string())
                .await;

            // The public key is not needed for resharing, but its digest is signed for the new
            // epoch, so it must match the bytes in storage.
            let public_key_bytes = pub_storage
                .load_bytes(key_id, &PubDataType::PublicKey.to_string())
                .await;

            match (compressed_keyset_bytes, public_key_bytes) {
                (Ok(compressed_keyset_bytes), Ok(public_key_bytes)) => {
                    match verify_compressed_key_digest_from_bytes(
                        &compressed_keyset_bytes,
                        expected_compressed_digest,
                    )
                    .and_then(|()| {
                        verify_public_key_digest_from_bytes(
                            &public_key_bytes,
                            expected_public_key_digest,
                        )
                    }) {
                        Ok(()) => {
                            let compressed_keyset: CompressedXofKeySet =
                                tfhe::safe_serialization::safe_deserialize(
                                    std::io::Cursor::new(&compressed_keyset_bytes),
                                    crate::consts::SAFE_SER_SIZE_LIMIT,
                                )
                                .map_err(|e| {
                                    anyhow::anyhow!(
                                        "Failed to deserialize compressed xof keyset: {}",
                                        e
                                    )
                                })?;

                            return Ok(VerifiedPublicMaterial::from_peer(
                                VerifiedFheKeys::Compressed(compressed_keyset),
                                vec![
                                    (PubDataType::CompressedXofKeySet, compressed_keyset_bytes),
                                    (PubDataType::PublicKey, public_key_bytes),
                                ],
                            ));
                        }
                        Err(e) => {
                            let msg =
                                format!("Verification failed from peer {}: {}", node.party_id, e);
                            tracing::warn!(msg);
                            errors.push(msg);
                            continue;
                        }
                    }
                }
                (Err(e), _) | (_, Err(e)) => {
                    let msg = format!(
                        "{} from peer {}: {e:?}",
                        ERR_FAILED_TO_FETCH_PUBLIC_MATERIALS, node.party_id
                    );
                    tracing::warn!(msg);
                    errors.push(msg);
                }
            }
        } else {
            // Handle uncompressed keys
            let expected_public_key_digest = key_digests
                .get(&PubDataType::PublicKey)
                .ok_or_else(|| anyhow::anyhow!("missing digest for public key"))?;

            let expected_server_key_digest = key_digests
                .get(&PubDataType::ServerKey)
                .ok_or_else(|| anyhow::anyhow!("missing digest for server key"))?;

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
                            .map_err(|e| {
                                anyhow::anyhow!("Failed to deserialize server key: {}", e)
                            })?;

                            return Ok(VerifiedPublicMaterial::from_peer(
                                VerifiedFheKeys::Uncompressed(FhePubKeySet {
                                    public_key,
                                    server_key,
                                }),
                                vec![
                                    (PubDataType::ServerKey, server_key_bytes),
                                    (PubDataType::PublicKey, public_key_bytes),
                                ],
                            ));
                        }
                        Err(e) => {
                            let msg =
                                format!("Verification failed from peer {}: {}", node.party_id, e);
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
    }

    anyhow::bail!(
        "Failed to fetch valid public materials from any peer, error count: {}, first error: {:?}, last error: {:?}",
        errors.len(),
        errors[0],
        errors[errors.len() - 1],
    );
}

/// Attempt to get and verify the public materials needed for resharing.
/// Supports both compressed (CompressedXofKeySet) and uncompressed (FhePubKeySet) keys.
///
/// The material is read from our own public storage, or fetched from the peers of `context_id`
/// if it is missing there. In the latter case the verified raw bytes are kept in the result (see
/// [`VerifiedPublicMaterial::into_parts`]), so that they can be stored once the reshare succeeds.
pub(crate) async fn get_verified_fhe_public_materials<
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
) -> Result<VerifiedPublicMaterial, MetricedError> {
    // Determine if we're dealing with compressed or uncompressed keys
    let is_compressed = key_digests.contains_key(&PubDataType::CompressedXofKeySet);

    if is_compressed {
        // Handle compressed keys
        let expected_compressed_digest = key_digests
            .get(&PubDataType::CompressedXofKeySet)
            .ok_or_else(|| {
                MetricedError::new(
                    OP_NEW_EPOCH,
                    Some(*request_id),
                    anyhow::anyhow!("missing digest for compressed xof keyset"),
                    tonic::Code::Internal,
                )
            })?;
        let expected_public_key_digest =
            key_digests.get(&PubDataType::PublicKey).ok_or_else(|| {
                MetricedError::new(
                    OP_NEW_EPOCH,
                    Some(*request_id),
                    anyhow::anyhow!("missing digest for public key"),
                    tonic::Code::InvalidArgument,
                )
            })?;

        // Load raw bytes from own public storage.
        // The public key is not needed for resharing, but its digest is signed for the new
        // epoch, so it must match the bytes in storage.
        let (compressed_keyset_bytes_res, public_key_bytes_res): (
            anyhow::Result<Vec<u8>>,
            anyhow::Result<Vec<u8>>,
        ) = {
            let pub_storage = crypto_storage.inner.get_public_storage();
            let guard_storage = pub_storage.lock().await;
            let compressed_keyset_bytes = guard_storage
                .load_bytes(key_id, &PubDataType::CompressedXofKeySet.to_string())
                .await;
            let public_key_bytes = guard_storage
                .load_bytes(key_id, &PubDataType::PublicKey.to_string())
                .await;
            (compressed_keyset_bytes, public_key_bytes)
        };

        match (compressed_keyset_bytes_res, public_key_bytes_res) {
            (Ok(compressed_keyset_bytes), Ok(public_key_bytes)) => {
                verify_compressed_key_digest_from_bytes(
                    &compressed_keyset_bytes,
                    expected_compressed_digest,
                )
                .and_then(|()| {
                    verify_public_key_digest_from_bytes(
                        &public_key_bytes,
                        expected_public_key_digest,
                    )
                })
                .map_err(|e| {
                    MetricedError::new(
                        OP_NEW_EPOCH,
                        Some(*request_id),
                        anyhow::anyhow!("Compressed key digest verification failed: {}", e),
                        tonic::Code::Internal,
                    )
                })?;

                let compressed_keyset: CompressedXofKeySet =
                    tfhe::safe_serialization::safe_deserialize(
                        std::io::Cursor::new(&compressed_keyset_bytes),
                        crate::consts::SAFE_SER_SIZE_LIMIT,
                    )
                    .map_err(|e| {
                        MetricedError::new(
                            OP_NEW_EPOCH,
                            Some(*request_id),
                            anyhow::anyhow!("Failed to deserialize compressed xof keyset: {}", e),
                            tonic::Code::Internal,
                        )
                    })?;

                Ok(VerifiedPublicMaterial::from_own_storage(
                    VerifiedFheKeys::Compressed(compressed_keyset),
                ))
            }
            _ => {
                // If local retrieval fails, attempt to fetch from s3 of another party
                fetch_public_fhe_materials_from_peers::<_, _, G, R>(
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
    } else {
        // Handle uncompressed keys
        let expected_public_key_digest =
            key_digests.get(&PubDataType::PublicKey).ok_or_else(|| {
                MetricedError::new(
                    OP_NEW_EPOCH,
                    Some(*request_id),
                    anyhow::anyhow!("missing digest for public key"),
                    tonic::Code::Internal,
                )
            })?;

        let expected_server_key_digest =
            key_digests.get(&PubDataType::ServerKey).ok_or_else(|| {
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
                let public_key: tfhe::CompactPublicKey =
                    tfhe::safe_serialization::safe_deserialize(
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

                Ok(VerifiedPublicMaterial::from_own_storage(
                    VerifiedFheKeys::Uncompressed(FhePubKeySet {
                        public_key,
                        server_key,
                    }),
                ))
            }
            _ => {
                // if local retrieval fails, attempt to fetch from s3 of another party
                fetch_public_fhe_materials_from_peers::<_, _, G, R>(
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
}

async fn fetch_public_crs_materials_from_peers<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
    G: ReadOnlyS3StorageGetter<R>,
    R: StorageReader,
>(
    crypto_storage: &ThresholdCryptoMaterialStorage<PubS, PrivS>,
    crs_id: &RequestId,
    context_id: &ContextId,
    crs_digests: &[u8],
    ro_storage_getter: &G,
) -> anyhow::Result<(CompactPkeCrs, Vec<u8>)> {
    // fetch the context info
    let context = fetch_context_from_storage(crypto_storage, context_id).await?;

    let mut errors = Vec::new();
    for node in context.mpc_nodes {
        // to simplify logic, it's ok to iterate over myself too
        //
        // the public storage URL consists of the bucket name and the URL
        // we need to parse this information accordingly
        let (protocol, domain, bucket) = split_url(&node.public_storage_url)?;
        let url = format!("{protocol}{domain}");
        let region = find_region_from_s3_url(&node.public_storage_url)?;

        // this is not an operation that is frequently used, so we can create a new s3 client each time
        let s3_client = build_anonymous_s3_client(&url, region).await?;
        let pub_storage = ro_storage_getter.get_storage(
            s3_client,
            bucket,
            StorageType::PUB,
            node.public_storage_prefix.as_deref(),
        )?;

        let crs_bytes = pub_storage
            .load_bytes(crs_id, &PubDataType::CRS.to_string())
            .await;
        match crs_bytes {
            Ok(crs_bytes) => match verify_crs_digest_from_bytes(&crs_bytes, crs_digests) {
                Ok(()) => {
                    // Assumes that if the digest match deserialize will either succeed or fail for all peers,
                    // so it's ok to error out if this fails
                    let crs = tfhe::safe_serialization::safe_deserialize(
                        std::io::Cursor::new(&crs_bytes),
                        crate::consts::SAFE_SER_SIZE_LIMIT,
                    )
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize CRS: {}", e))?;
                    return Ok((crs, crs_bytes));
                }
                Err(e) => {
                    let msg = format!(
                        "CRS digest verification failed from peer {}: {}",
                        node.party_id, e
                    );
                    tracing::warn!(msg);
                    errors.push(msg);
                }
            },
            Err(e) => {
                let msg = format!(
                    "{} from peer {}: {e:?}",
                    ERR_FAILED_TO_FETCH_PUBLIC_MATERIALS, node.party_id
                );
                tracing::error!(msg);
                errors.push(msg);
            }
        }
    }

    anyhow::bail!(
        "Failed to fetch valid crs materials from any peer, error count: {}, first error: {:?}, last error: {:?}",
        errors.len(),
        errors[0],
        errors[errors.len() - 1],
    );
}

/// Attempt to get and verify the CRS for resharing.
///
/// The CRS is read from our own public storage, or fetched from the peers of `context_id` if it
/// is missing there. In the latter case the verified raw bytes are returned as well, so that they
/// can be stored once the reshare succeeds; they are `None` otherwise.
pub(crate) async fn get_verified_crs_material<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
    G: ReadOnlyS3StorageGetter<R>,
    R: StorageReader,
>(
    crypto_storage: &ThresholdCryptoMaterialStorage<PubS, PrivS>,
    request_id: &RequestId,
    crs_id: &RequestId,
    context_id: &ContextId,
    crs_digest: &[u8],
    ro_storage_getter: &G,
) -> Result<(CompactPkeCrs, Option<Vec<u8>>), MetricedError> {
    // Load raw bytes from own public storage
    let crs_bytes_res: anyhow::Result<Vec<u8>> = {
        let pub_storage = crypto_storage.inner.get_public_storage();
        let guard_storage = pub_storage.lock().await;
        guard_storage
            .load_bytes(crs_id, &PubDataType::CRS.to_string())
            .await
    };

    match crs_bytes_res {
        Ok(crs_bytes) => {
            verify_crs_digest_from_bytes(&crs_bytes, crs_digest).map_err(|e| {
                MetricedError::new(
                    OP_NEW_EPOCH,
                    Some(*request_id),
                    anyhow::anyhow!("CRS digest verification failed: {}", e),
                    tonic::Code::Internal,
                )
            })?;

            let crs = tfhe::safe_serialization::safe_deserialize(
                std::io::Cursor::new(&crs_bytes),
                crate::consts::SAFE_SER_SIZE_LIMIT,
            )
            .map_err(|e| {
                MetricedError::new(
                    OP_NEW_EPOCH,
                    Some(*request_id),
                    anyhow::anyhow!("Failed to deserialize CRS: {}", e),
                    tonic::Code::Internal,
                )
            })?;
            Ok((crs, None))
        }
        Err(_) => fetch_public_crs_materials_from_peers::<_, _, G, R>(
            crypto_storage,
            crs_id,
            context_id,
            crs_digest,
            ro_storage_getter,
        )
        .await
        .map(|(crs, crs_bytes)| (crs, Some(crs_bytes)))
        .map_err(|e| {
            MetricedError::new(
                OP_NEW_EPOCH,
                Some(*request_id),
                anyhow::anyhow!("Failed to fetch CRS materials from peers: {}", e),
                tonic::Code::Internal,
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use crate::engine::context::ContextInfo;
    use crate::engine::context::NodeInfo;
    use crate::engine::context::SoftwareVersion;
    use crate::engine::threshold::service::reshare_utils::ERR_FAILED_TO_FETCH_PUBLIC_MATERIALS;
    use crate::engine::threshold::service::reshare_utils::fetch_public_fhe_materials_from_peers;
    use crate::engine::threshold::service::reshare_utils::get_verified_fhe_public_materials;
    use crate::engine::threshold::service::reshare_utils::{
        get_verified_crs_material, store_peer_public_bytes,
    };
    use crate::engine::utils::ERR_SERVER_KEY_DIGEST_MISMATCH;
    use crate::vault::storage::crypto_material::ThresholdCryptoMaterialStorage;
    use crate::vault::storage::ram::RamStorage;
    use crate::vault::storage::s3::DummyReadOnlyS3Storage;
    use crate::vault::storage::s3::DummyReadOnlyS3StorageGetter;
    use crate::vault::storage::store_versioned_at_request_id;

    use crate::vault::storage::{Storage, StorageReader};
    use aes_prng::AesRng;
    use hashing::hash_versioned;
    use kms_grpc::ContextId;
    use kms_grpc::RequestId;
    use kms_grpc::rpc_types::PubDataType;
    use observability::metrics_names::OP_NEW_MPC_CONTEXT;
    use rand::SeedableRng;
    use tfhe::CompactPublicKey;
    use tfhe::ServerKey;
    use tfhe::shortint::ClassicPBSParameters;
    use tfhe::zk::CompactPkeCrs;

    #[test]
    fn test_split_url() {
        // Virtual-hosted style: bucket is a subdomain
        let (protocol, domain, bucket) = super::split_url(
            &"https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/".to_string(),
        )
        .unwrap();
        assert_eq!(protocol.as_str(), "https://");
        assert_eq!(domain.as_str(), "s3.eu-west-1.amazonaws.com");
        assert_eq!(bucket.as_str(), "zama-zws-dev-tkms-b6q87");

        // Path-style: bucket is in the URL path
        let (protocol, domain, bucket) =
            super::split_url(&"http://localhost:9000/kms".to_string()).unwrap();
        assert_eq!(protocol.as_str(), "http://");
        assert_eq!(domain.as_str(), "localhost:9000");
        assert_eq!(bucket.as_str(), "kms");

        // MinIO mock endpoint with path bucket
        let (protocol, domain, bucket) =
            super::split_url(&"http://dev-s3-mock:9000/kms".to_string()).unwrap();
        assert_eq!(protocol.as_str(), "http://");
        assert_eq!(domain.as_str(), "dev-s3-mock:9000");
        assert_eq!(bucket.as_str(), "kms");

        // file:// URL (used in isolated tests)
        let (protocol, domain, bucket) =
            super::split_url(&"file:///tmp/test-material".to_string()).unwrap();
        assert_eq!(protocol.as_str(), "file://");
        assert_eq!(domain.as_str(), "");
        assert_eq!(bucket.as_str(), "/tmp/test-material");

        // Path-style S3 with region
        let (protocol, domain, bucket) = super::split_url(
            &"https://s3.us-west-1.amazonaws.com/zama-zws-dev-tkms-b6q87/".to_string(),
        )
        .unwrap();
        assert_eq!(protocol.as_str(), "https://");
        assert_eq!(domain.as_str(), "s3.us-west-1.amazonaws.com");
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
        let pbs_params: ClassicPBSParameters = params.classic_pbs();
        let config = tfhe::ConfigBuilder::with_custom_parameters(pbs_params);
        let client_key = tfhe::ClientKey::generate(config);
        let server_key = client_key.generate_server_key();
        let public_key = CompactPublicKey::new(&client_key);

        // generate digests
        let server_key_digest =
            hash_versioned(&crate::engine::base::DSEP_PUBDATA_KEY, &server_key).unwrap();
        let public_key_digest =
            hash_versioned(&crate::engine::base::DSEP_PUBDATA_KEY, &public_key).unwrap();
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
                    signer_address: None,
                    external_url: "http://localhost:12345".to_string(),
                    ca_cert: None,
                    // the storage url does not matter as we're using the mock
                    public_storage_url:
                        "https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/".to_string(),
                    public_storage_prefix: None,
                    extra_signer_addresses: vec![],
                }],
                if two_nodes {
                    vec![NodeInfo {
                        mpc_identity: "Node2".to_string(),
                        party_id: 2,
                        signer_address: None,
                        external_url: "http://localhost:12345".to_string(),
                        ca_cert: None,
                        // the storage url does not matter as we're using the mock
                        public_storage_url:
                            "https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/"
                                .to_string(),
                        public_storage_prefix: None,
                        extra_signer_addresses: vec![],
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
            },
            threshold: 0,
            pcr_values: vec![],
        };

        crypto_storage
            .inner
            .write_context_info(&context_id, &context_info, OP_NEW_MPC_CONTEXT)
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
            let err = fetch_public_fhe_materials_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
                &crypto_storage,
                &key_id,
                &context_id,
                &key_digests,
                &ro_storage_getter,
            )
            .await
            .unwrap_err();
            assert!(
                err.to_string()
                    .contains(ERR_FAILED_TO_FETCH_PUBLIC_MATERIALS)
            );
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
            let err = fetch_public_fhe_materials_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
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
            let verified_material =
                fetch_public_fhe_materials_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
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

            // the returned bytes must be exactly the ones in the peer's storage
            assert_peer_bytes_match(
                verified_material.peer_bytes(),
                &ro_storage_getter.ram_storages[0],
                &key_id,
                &[PubDataType::ServerKey, PubDataType::PublicKey],
            )
            .await;
        }
        {
            // sunshine
            // use two dummy s3 storage, where the first one is broken, so ro_storage_getter should be called twice
            let two_ro_storage_getter = DummyReadOnlyS3StorageGetter {
                counter: RefCell::new(0),
                ram_storages: vec![RamStorage::new(), ro_storage_getter.ram_storages[0].clone()],
            };

            let _verified_material =
                fetch_public_fhe_materials_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
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
            let err = get_verified_fhe_public_materials(
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

            let verified_material = get_verified_fhe_public_materials(
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
            // and there is nothing that needs to be stored
            assert!(verified_material.peer_bytes().is_empty());
        }
    }

    // ==================== Compressed Key Tests ====================
    use super::VerifiedFheKeys;
    use crate::engine::utils::{
        ERR_COMPRESSED_KEYSET_DIGEST_MISMATCH, ERR_PUBLIC_KEY_DIGEST_MISMATCH,
    };
    use tfhe::core_crypto::prelude::NormalizedHammingWeightBound;
    use tfhe::xof_key_set::CompressedXofKeySet;

    async fn setup_public_materials_test_compressed(
        key_id: RequestId,
        context_id: ContextId,
        two_nodes: bool,
    ) -> (
        ThresholdCryptoMaterialStorage<RamStorage, RamStorage>,
        HashMap<PubDataType, Vec<u8>>,
        DummyReadOnlyS3StorageGetter,
        (CompressedXofKeySet, CompactPublicKey),
    ) {
        // create memory storage that contains a compressed keyset and its public key
        let mut ram_storage = RamStorage::new();

        // generate the compressed keyset using to_tfhe_config() which includes
        // dedicated compact public key parameters required for compressed keys
        let params = crate::consts::TEST_PARAM;
        let config = params.to_tfhe_config();
        // if the pmax value is not set, e.g., for test parameters, we do not do the HW check
        // and use a pmax=1 which should allow for any HW.
        let max_norm_hwt = params.sk_deviations().map(|x| x.pmax).unwrap_or(1.0);
        let max_norm_hwt = NormalizedHammingWeightBound::new(max_norm_hwt).unwrap();
        let tag = (&key_id).into();

        let (_client_key, compressed_keyset) =
            CompressedXofKeySet::generate(config, vec![42, 43, 44, 45], 128, max_norm_hwt, tag)
                .unwrap();

        let public_key = compressed_keyset.decompress().unwrap().into_raw_parts().0;

        // generate digests
        let compressed_keyset_digest =
            hash_versioned(&crate::engine::base::DSEP_PUBDATA_KEY, &compressed_keyset).unwrap();
        let public_key_digest =
            hash_versioned(&crate::engine::base::DSEP_PUBDATA_KEY, &public_key).unwrap();
        let key_digests: HashMap<PubDataType, Vec<u8>> = HashMap::from_iter([
            (PubDataType::CompressedXofKeySet, compressed_keyset_digest),
            (PubDataType::PublicKey, public_key_digest),
        ]);

        // store the compressed keyset and the public key in ram storage
        store_compressed_materials(&mut ram_storage, &key_id, &compressed_keyset, &public_key)
            .await;

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
                    signer_address: None,
                    external_url: "http://localhost:12345".to_string(),
                    ca_cert: None,
                    // the storage url does not matter as we're using the mock
                    public_storage_url:
                        "https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/".to_string(),
                    public_storage_prefix: None,
                    extra_signer_addresses: vec![],
                }],
                if two_nodes {
                    vec![NodeInfo {
                        mpc_identity: "Node2".to_string(),
                        party_id: 2,
                        signer_address: None,
                        external_url: "http://localhost:12345".to_string(),
                        ca_cert: None,
                        // the storage url does not matter as we're using the mock
                        public_storage_url:
                            "https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/"
                                .to_string(),
                        public_storage_prefix: None,
                        extra_signer_addresses: vec![],
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
            },
            threshold: 0,
            pcr_values: vec![],
        };

        crypto_storage
            .inner
            .write_context_info(&context_id, &context_info, OP_NEW_MPC_CONTEXT)
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
            (compressed_keyset, public_key),
        )
    }

    async fn store_compressed_materials(
        storage: &mut RamStorage,
        key_id: &RequestId,
        compressed_keyset: &CompressedXofKeySet,
        public_key: &CompactPublicKey,
    ) {
        store_versioned_at_request_id(
            storage,
            key_id,
            compressed_keyset,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await
        .unwrap();
        store_versioned_at_request_id(
            storage,
            key_id,
            public_key,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn sunshine_fetch_public_materials_from_peers_compressed() {
        let mut rng = AesRng::seed_from_u64(2333);
        let key_id = RequestId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng);
        let (crypto_storage, key_digests, ro_storage_getter, _) =
            setup_public_materials_test_compressed(key_id, context_id, true).await;

        let verified_material =
            fetch_public_fhe_materials_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
                &crypto_storage,
                &key_id,
                &context_id,
                &key_digests,
                &ro_storage_getter,
            )
            .await
            .unwrap();

        assert!(matches!(
            verified_material.keys(),
            VerifiedFheKeys::Compressed(_)
        ));
        assert_eq!(*ro_storage_getter.counter.borrow(), 1);
        assert_peer_bytes_match(
            verified_material.peer_bytes(),
            &ro_storage_getter.ram_storages[0],
            &key_id,
            &[PubDataType::CompressedXofKeySet, PubDataType::PublicKey],
        )
        .await;
    }

    #[tokio::test]
    async fn wrong_digest_fetch_public_materials_from_peers_compressed() {
        let mut rng = AesRng::seed_from_u64(2333);
        let key_id = RequestId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng);
        let (crypto_storage, key_digests, ro_storage_getter, _) =
            setup_public_materials_test_compressed(key_id, context_id, false).await;

        // use wrong digests to trigger error
        let mut wrong_key_digests = key_digests.clone();
        wrong_key_digests.insert(PubDataType::CompressedXofKeySet, vec![0, 1, 2, 4]);
        let err = fetch_public_fhe_materials_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
            &crypto_storage,
            &key_id,
            &context_id,
            &wrong_key_digests,
            &ro_storage_getter,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string()
                .contains(ERR_COMPRESSED_KEYSET_DIGEST_MISMATCH)
        );
    }

    #[tokio::test]
    async fn sunshine_get_verified_public_materials_compressed() {
        let mut rng = AesRng::seed_from_u64(2334);
        let req_id = RequestId::new_random(&mut rng);
        let key_id = RequestId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng);
        let (crypto_storage, key_digests, ro_storage_getter, (compressed_keyset, public_key)) =
            setup_public_materials_test_compressed(key_id, context_id, false).await;

        // store compressed keyset and public key in own public storage
        let public_storage = crypto_storage.inner.get_public_storage();
        {
            let mut guard_storage = public_storage.lock().await;
            store_compressed_materials(
                &mut guard_storage,
                &key_id,
                &compressed_keyset,
                &public_key,
            )
            .await;
        }

        let verified_material = get_verified_fhe_public_materials(
            &crypto_storage,
            &req_id,
            &key_id,
            &context_id,
            &key_digests,
            &ro_storage_getter,
        )
        .await
        .unwrap();

        assert!(matches!(
            verified_material.keys(),
            VerifiedFheKeys::Compressed(_)
        ));
        // we should've used my own storage directly, so the counter here should be 0
        assert_eq!(*ro_storage_getter.counter.borrow(), 0);
        // and there is nothing that needs to be stored
        assert!(verified_material.peer_bytes().is_empty());
    }

    #[tokio::test]
    async fn bad_digests_get_verified_public_materials_compressed() {
        let mut rng = AesRng::seed_from_u64(2334);
        let req_id = RequestId::new_random(&mut rng);
        let key_id = RequestId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng);
        let (crypto_storage, key_digests, ro_storage_getter, (compressed_keyset, public_key)) =
            setup_public_materials_test_compressed(key_id, context_id, false).await;

        // store compressed keyset and public key in own public storage
        let public_storage = crypto_storage.inner.get_public_storage();
        {
            let mut guard_storage = public_storage.lock().await;
            store_compressed_materials(
                &mut guard_storage,
                &key_id,
                &compressed_keyset,
                &public_key,
            )
            .await;
        }

        let mut bad_key_digests = key_digests.clone();
        bad_key_digests.insert(PubDataType::CompressedXofKeySet, vec![9, 8, 7, 6]);
        let err = get_verified_fhe_public_materials(
            &crypto_storage,
            &req_id,
            &key_id,
            &context_id,
            &bad_key_digests,
            &ro_storage_getter,
        )
        .await
        .unwrap_err();
        assert!(format!("{err:?}").contains(ERR_COMPRESSED_KEYSET_DIGEST_MISMATCH));

        // The public key digest is signed for the new epoch, so it must be verified too.
        let mut bad_key_digests = key_digests.clone();
        bad_key_digests.insert(PubDataType::PublicKey, vec![9, 8, 7, 6]);
        let err = get_verified_fhe_public_materials(
            &crypto_storage,
            &req_id,
            &key_id,
            &context_id,
            &bad_key_digests,
            &ro_storage_getter,
        )
        .await
        .unwrap_err();
        assert!(format!("{err:?}").contains(ERR_PUBLIC_KEY_DIGEST_MISMATCH));

        // we should've used the public storage directly, so the counter here should be 0
        assert_eq!(*ro_storage_getter.counter.borrow(), 0);
    }

    #[tokio::test]
    async fn missing_public_key_digest_get_verified_public_materials_compressed() {
        let mut rng = AesRng::seed_from_u64(2335);
        let req_id = RequestId::new_random(&mut rng);
        let key_id = RequestId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng);
        let (crypto_storage, mut key_digests, ro_storage_getter, _) =
            setup_public_materials_test_compressed(key_id, context_id, false).await;
        key_digests.remove(&PubDataType::PublicKey);

        let err = get_verified_fhe_public_materials(
            &crypto_storage,
            &req_id,
            &key_id,
            &context_id,
            &key_digests,
            &ro_storage_getter,
        )
        .await
        .unwrap_err();
        assert!(format!("{err:?}").contains("missing digest for public key"));

        let err = fetch_public_fhe_materials_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
            &crypto_storage,
            &key_id,
            &context_id,
            &key_digests,
            &ro_storage_getter,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("missing digest for public key"));
    }

    #[tokio::test]
    async fn wrong_public_key_fetch_public_materials_from_peers_compressed() {
        let mut rng = AesRng::seed_from_u64(2336);
        let key_id = RequestId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng);
        let (crypto_storage, mut key_digests, ro_storage_getter, _) =
            setup_public_materials_test_compressed(key_id, context_id, false).await;
        key_digests.insert(PubDataType::PublicKey, vec![0, 1, 2, 4]);

        let err = fetch_public_fhe_materials_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
            &crypto_storage,
            &key_id,
            &context_id,
            &key_digests,
            &ro_storage_getter,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains(ERR_PUBLIC_KEY_DIGEST_MISMATCH));
    }

    /// Assert that `peer_bytes` holds, for each of `data_types` in order, exactly the bytes that
    /// `peer_storage` holds for `data_id`.
    async fn assert_peer_bytes_match(
        peer_bytes: &[(PubDataType, Vec<u8>)],
        peer_storage: &RamStorage,
        data_id: &RequestId,
        data_types: &[PubDataType],
    ) {
        assert_eq!(peer_bytes.len(), data_types.len());
        for ((entry_type, bytes), data_type) in peer_bytes.iter().zip(data_types) {
            assert_eq!(entry_type, data_type);
            let stored = peer_storage
                .load_bytes(data_id, &data_type.to_string())
                .await
                .unwrap();
            assert_eq!(bytes, &stored, "{data_type} bytes differ from the peer's");
        }
    }

    #[tokio::test]
    async fn sunshine_get_verified_crs_material_from_peers() {
        let mut rng = AesRng::seed_from_u64(2337);
        let req_id = RequestId::new_random(&mut rng);
        let key_id = RequestId::new_random(&mut rng);
        let crs_id = RequestId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng);
        let (crypto_storage, _key_digests, mut ro_storage_getter, _) =
            setup_public_materials_test(key_id, context_id, false).await;

        let params = crate::consts::TEST_PARAM;
        let crs_config = tfhe::ConfigBuilder::with_custom_parameters(params.classic_pbs())
            .use_dedicated_compact_public_key_parameters(params.dedicated_pk_params().unwrap())
            .build();
        let crs = CompactPkeCrs::from_config(crs_config, 256).unwrap();
        let crs_digest = hash_versioned(&crate::engine::base::DSEP_PUBDATA_CRS, &crs).unwrap();
        store_versioned_at_request_id(
            &mut ro_storage_getter.ram_storages[0],
            &crs_id,
            &crs,
            &PubDataType::CRS.to_string(),
        )
        .await
        .unwrap();

        // the CRS is missing from my own storage, so it is fetched from the peer
        let (_crs, crs_bytes) = get_verified_crs_material(
            &crypto_storage,
            &req_id,
            &crs_id,
            &context_id,
            &crs_digest,
            &ro_storage_getter,
        )
        .await
        .unwrap();
        assert_eq!(*ro_storage_getter.counter.borrow(), 1);
        assert_peer_bytes_match(
            &[(
                PubDataType::CRS,
                crs_bytes.expect("the CRS was fetched from the peer"),
            )],
            &ro_storage_getter.ram_storages[0],
            &crs_id,
            &[PubDataType::CRS],
        )
        .await;
    }

    #[tokio::test]
    async fn store_peer_public_bytes_keeps_matching_existing_entries() {
        let mut rng = AesRng::seed_from_u64(2338);
        let existing_id = RequestId::new_random(&mut rng);
        let missing_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();
        storage
            .store_bytes(b"from peer", &existing_id, &PubDataType::CRS.to_string())
            .await
            .unwrap();

        let (created, res) = store_peer_public_bytes(
            &mut storage,
            &[
                (existing_id, PubDataType::CRS, b"from peer".to_vec()),
                (missing_id, PubDataType::ServerKey, b"server key".to_vec()),
            ],
        )
        .await;
        res.unwrap();

        // Only the missing entry is reported as created, and the matching existing one is kept.
        assert_eq!(created, vec![(missing_id, PubDataType::ServerKey)]);
        assert_eq!(
            storage
                .load_bytes(&existing_id, &PubDataType::CRS.to_string())
                .await
                .unwrap(),
            b"from peer"
        );
        assert_eq!(
            storage
                .load_bytes(&missing_id, &PubDataType::ServerKey.to_string())
                .await
                .unwrap(),
            b"server key"
        );
    }

    #[tokio::test]
    async fn store_peer_public_bytes_rejects_mismatched_partial_storage() {
        let mut rng = AesRng::seed_from_u64(2339);
        let existing_id = RequestId::new_random(&mut rng);
        let missing_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();
        storage
            .store_bytes(b"existing", &existing_id, &PubDataType::CRS.to_string())
            .await
            .unwrap();

        let (created, res) = store_peer_public_bytes(
            &mut storage,
            &[
                (missing_id, PubDataType::ServerKey, b"server key".to_vec()),
                (existing_id, PubDataType::CRS, b"from peer".to_vec()),
            ],
        )
        .await;

        assert_eq!(created, vec![(missing_id, PubDataType::ServerKey)]);
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("differs from the bytes fetched from a peer")
        );
        assert_eq!(
            storage
                .load_bytes(&missing_id, &PubDataType::ServerKey.to_string())
                .await
                .unwrap(),
            b"server key",
            "the newly created entry must be returned for caller rollback"
        );
        assert_eq!(
            storage
                .load_bytes(&existing_id, &PubDataType::CRS.to_string())
                .await
                .unwrap(),
            b"existing",
            "the mismatched existing entry must not be overwritten"
        );
    }
}
