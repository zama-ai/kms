use crate::{
    engine::{
        context::ContextInfo,
        material_integrity::{
            verify_compressed_key_digest_from_bytes, verify_crs_digest_from_bytes,
            verify_key_digest_from_bytes, verify_public_key_digest_from_bytes,
        },
        public_material_sync::fetch_verified_public_bytes_from_peers,
        utils::MetricedError,
    },
    vault::storage::{
        Storage, StorageExt, StorageReader, StoreWriteOutcome,
        crypto_material::ThresholdCryptoMaterialStorage, read_context_at_id,
        s3::ReadOnlyS3StorageGetter,
    },
};
use kms_grpc::{ContextId, RequestId, rpc_types::PubDataType};
use observability::metrics_names::OP_NEW_EPOCH;
use std::collections::{BTreeMap, HashMap};
use tfhe::{ServerKey, xof_key_set::CompressedXofKeySet, zk::CompactPkeCrs};
use threshold_execution::tfhe_internals::public_keysets::FhePubKeySet;

/// Public-key representation selected by the validated digest fields of a reshare request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FheKeyDigestMode {
    /// A `ServerKey` and `PublicKey` pair.
    Uncompressed,
    /// A `CompressedXofKeySet` and `PublicKey` pair.
    Compressed,
}

impl FheKeyDigestMode {
    /// Validates the digest shape and returns its unambiguous public-key representation.
    pub(crate) fn from_digests(
        key_digests: &HashMap<PubDataType, Vec<u8>>,
    ) -> anyhow::Result<Self> {
        let public_key_digest = key_digests
            .get(&PubDataType::PublicKey)
            .ok_or_else(|| anyhow::anyhow!("missing digest for public key"))?;
        if public_key_digest.is_empty() {
            anyhow::bail!("{} digest must not be empty", PubDataType::PublicKey);
        }

        let server_key_digest = key_digests.get(&PubDataType::ServerKey);
        let compressed_keyset_digest = key_digests.get(&PubDataType::CompressedXofKeySet);
        match (server_key_digest, compressed_keyset_digest) {
            (Some(_), Some(_)) => anyhow::bail!(
                "key digests must contain exactly one of {} or {}, not both",
                PubDataType::ServerKey,
                PubDataType::CompressedXofKeySet
            ),
            (Some(digest), None) if !digest.is_empty() => Ok(Self::Uncompressed),
            (None, Some(digest)) if !digest.is_empty() => Ok(Self::Compressed),
            (Some(_), None) => {
                anyhow::bail!("{} digest must not be empty", PubDataType::ServerKey)
            }
            (None, Some(_)) => anyhow::bail!(
                "{} digest must not be empty",
                PubDataType::CompressedXofKeySet
            ),
            (None, None) => anyhow::bail!(
                "missing {} or {} digest",
                PubDataType::ServerKey,
                PubDataType::CompressedXofKeySet
            ),
        }
    }
}

/// The public keys of a reshared key, verified against the digests in the request.
///
/// The raw bytes let the storage phase restore material after it acquires the reshare lock.
/// This closes a gap in which a concurrent failed reshare deletes locally verified material.
// It's ok to have a big enum here since the way this type is used is only temporary.
#[expect(clippy::large_enum_variant)]
pub(crate) enum VerifiedPublicMaterial {
    /// Standard public keys and the exact bytes that passed digest verification.
    Uncompressed {
        keys: FhePubKeySet,
        server_key_bytes: Vec<u8>,
        public_key_bytes: Vec<u8>,
    },
    /// A compressed keyset and the exact bytes that passed digest verification.
    Compressed {
        keyset: CompressedXofKeySet,
        compressed_keyset_bytes: Vec<u8>,
        public_key_bytes: Vec<u8>,
    },
}

impl std::fmt::Debug for VerifiedPublicMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uncompressed {
                server_key_bytes,
                public_key_bytes,
                ..
            } => f
                .debug_struct("VerifiedPublicMaterial::Uncompressed")
                .field("server_key_bytes", &server_key_bytes.len())
                .field("public_key_bytes", &public_key_bytes.len())
                .finish(),
            Self::Compressed {
                compressed_keyset_bytes,
                public_key_bytes,
                ..
            } => f
                .debug_struct("VerifiedPublicMaterial::Compressed")
                .field("compressed_keyset_bytes", &compressed_keyset_bytes.len())
                .field("public_key_bytes", &public_key_bytes.len())
                .finish(),
        }
    }
}

impl VerifiedPublicMaterial {
    /// Creates standard public keys with the exact bytes that passed digest verification.
    pub(crate) fn new_uncompressed(
        keys: FhePubKeySet,
        server_key_bytes: Vec<u8>,
        public_key_bytes: Vec<u8>,
    ) -> Self {
        Self::Uncompressed {
            keys,
            server_key_bytes,
            public_key_bytes,
        }
    }

    /// Creates a compressed keyset with the exact bytes that passed digest verification.
    pub(crate) fn new_compressed(
        keyset: CompressedXofKeySet,
        compressed_keyset_bytes: Vec<u8>,
        public_key_bytes: Vec<u8>,
    ) -> Self {
        Self::Compressed {
            keyset,
            compressed_keyset_bytes,
            public_key_bytes,
        }
    }

    /// Returns the verified raw bytes for each public data type.
    #[cfg(test)]
    pub(crate) fn verified_bytes(&self) -> Vec<(PubDataType, Vec<u8>)> {
        match self {
            Self::Uncompressed {
                server_key_bytes,
                public_key_bytes,
                ..
            } => vec![
                (PubDataType::ServerKey, server_key_bytes.clone()),
                (PubDataType::PublicKey, public_key_bytes.clone()),
            ],
            Self::Compressed {
                compressed_keyset_bytes,
                public_key_bytes,
                ..
            } => vec![
                (
                    PubDataType::CompressedXofKeySet,
                    compressed_keyset_bytes.clone(),
                ),
                (PubDataType::PublicKey, public_key_bytes.clone()),
            ],
        }
    }

    pub(crate) fn has_oprf_key(&self) -> bool {
        match self {
            Self::Uncompressed { keys, .. } => keys.server_key.has_oprf_key(),
            Self::Compressed { keyset, .. } => keyset.has_oprf_key(),
        }
    }

    /// Whether the public material carries a transciphering server key.
    pub(crate) fn has_transciphering_key(&self) -> bool {
        match self {
            Self::Uncompressed { keys, .. } => keys.server_key.has_transciphering_key(),
            Self::Compressed { keyset, .. } => keyset.has_transciphering_key(),
        }
    }
}

/// A CRS together with the exact bytes that passed digest verification.
pub(crate) struct VerifiedCrsMaterial {
    crs: CompactPkeCrs,
    bytes: Vec<u8>,
}

impl VerifiedCrsMaterial {
    pub(crate) fn new(crs: CompactPkeCrs, bytes: Vec<u8>) -> Self {
        Self { crs, bytes }
    }

    pub(crate) fn into_parts(self) -> (CompactPkeCrs, Vec<u8>) {
        (self.crs, self.bytes)
    }
}

/// Ensures that the verified raw public `entries` are present in `pub_storage`.
///
/// An existing entry is kept only when its bytes match. The returned entries were created by this
/// call, so a failed reshare can delete them. Writes stop at the first error.
pub(crate) async fn ensure_verified_reshare_public_bytes<PubS: Storage>(
    pub_storage: &mut PubS,
    entries: &[(RequestId, PubDataType, Vec<u8>)],
) -> (Vec<(RequestId, PubDataType)>, anyhow::Result<()>) {
    let mut created = Vec::new();
    for (data_id, data_type, bytes) in entries {
        let data_type_str = data_type.to_string();
        let exists = match pub_storage.data_exists(data_id, &data_type_str).await {
            Ok(exists) => exists,
            Err(e) => {
                return (
                    created,
                    Err(e.context(format!(
                        "Failed to check whether {data_type} of {data_id} exists before storing the verified bytes"
                    ))),
                );
            }
        };
        if !exists {
            created.push((*data_id, *data_type));
            match pub_storage
                .store_bytes(bytes, data_id, &data_type_str)
                .await
            {
                Ok(StoreWriteOutcome::Created) => continue,
                Ok(StoreWriteOutcome::SkippedExisting) => {
                    // Another writer owns an entry created after the existence check.
                    created.pop();
                }
                Err(e) => {
                    return (
                        created,
                        Err(e.context(format!("Failed to store verified {data_type} of {data_id}"))),
                    );
                }
            }
        }
        match pub_storage.load_bytes(data_id, &data_type_str).await {
            Ok(existing_bytes) if existing_bytes == *bytes => {}
            Ok(_) => {
                return (
                    created,
                    Err(anyhow::anyhow!(
                        "Existing {data_type} of {data_id} differs from the verified bytes"
                    )),
                );
            }
            Err(e) => {
                return (
                    created,
                    Err(e.context(format!(
                        "Failed to verify existing {data_type} of {data_id} against the verified bytes"
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
    let key_digest_mode = FheKeyDigestMode::from_digests(key_digests)?;

    // fetch the context info
    let context = fetch_context_from_storage(crypto_storage, context_id).await?;

    // For compressed keys the public key is not needed for resharing, but its digest is signed
    // for the new epoch, so it must match the bytes in storage.
    let wanted_types: &[PubDataType] = if key_digest_mode == FheKeyDigestMode::Compressed {
        &[PubDataType::CompressedXofKeySet, PubDataType::PublicKey]
    } else {
        &[PubDataType::PublicKey, PubDataType::ServerKey]
    };
    let mut expected_digests = BTreeMap::new();
    for data_type in wanted_types {
        let digest = key_digests
            .get(data_type)
            .ok_or_else(|| anyhow::anyhow!("missing digest for {data_type}"))?;
        expected_digests.insert(*data_type, digest.clone());
    }

    let mut verified = fetch_verified_public_bytes_from_peers(
        &context.mpc_nodes,
        key_id,
        &expected_digests,
        ro_storage_getter,
    )
    .await?;

    // Only deserialize bytes whose digest already verified. Assumes that if the digest matches,
    // deserialization will either succeed or fail for all peers, so it's ok to error out here.
    // The expect calls cannot fire: the fetcher returns exactly the requested entries.
    if key_digest_mode == FheKeyDigestMode::Compressed {
        let compressed_keyset_bytes = verified
            .remove(&PubDataType::CompressedXofKeySet)
            .expect("fetcher returns every requested entry");
        let compressed_keyset: CompressedXofKeySet = tfhe::safe_serialization::safe_deserialize(
            std::io::Cursor::new(&compressed_keyset_bytes),
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .map_err(|e| anyhow::anyhow!("Failed to deserialize compressed xof keyset: {}", e))?;

        let public_key_bytes = verified
            .remove(&PubDataType::PublicKey)
            .expect("fetcher returns every requested entry");
        Ok(VerifiedPublicMaterial::new_compressed(
            compressed_keyset,
            compressed_keyset_bytes,
            public_key_bytes,
        ))
    } else {
        let public_key_bytes = verified
            .remove(&PubDataType::PublicKey)
            .expect("fetcher returns every requested entry");
        let server_key_bytes = verified
            .remove(&PubDataType::ServerKey)
            .expect("fetcher returns every requested entry");

        let public_key: tfhe::CompactPublicKey = tfhe::safe_serialization::safe_deserialize(
            std::io::Cursor::new(&public_key_bytes),
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .map_err(|e| anyhow::anyhow!("Failed to deserialize public key: {}", e))?;

        let server_key: ServerKey = tfhe::safe_serialization::safe_deserialize(
            std::io::Cursor::new(&server_key_bytes),
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .map_err(|e| anyhow::anyhow!("Failed to deserialize server key: {}", e))?;

        Ok(VerifiedPublicMaterial::new_uncompressed(
            FhePubKeySet {
                public_key,
                server_key,
            },
            server_key_bytes,
            public_key_bytes,
        ))
    }
}

/// Attempt to get and verify the public materials needed for resharing.
/// Supports both compressed (CompressedXofKeySet) and uncompressed (FhePubKeySet) keys.
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
    let key_digest_mode = FheKeyDigestMode::from_digests(key_digests).map_err(|e| {
        MetricedError::new(
            OP_NEW_EPOCH,
            Some(*request_id),
            e,
            tonic::Code::InvalidArgument,
        )
    })?;

    if key_digest_mode == FheKeyDigestMode::Compressed {
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

                Ok(VerifiedPublicMaterial::new_compressed(
                    compressed_keyset,
                    compressed_keyset_bytes,
                    public_key_bytes,
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

                Ok(VerifiedPublicMaterial::new_uncompressed(
                    FhePubKeySet {
                        public_key,
                        server_key,
                    },
                    server_key_bytes,
                    public_key_bytes,
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
) -> anyhow::Result<VerifiedCrsMaterial> {
    // fetch the context info
    let context = fetch_context_from_storage(crypto_storage, context_id).await?;

    let expected_digests = BTreeMap::from([(PubDataType::CRS, crs_digests.to_vec())]);
    let mut verified = fetch_verified_public_bytes_from_peers(
        &context.mpc_nodes,
        crs_id,
        &expected_digests,
        ro_storage_getter,
    )
    .await?;

    // Assumes that if the digest match deserialize will either succeed or fail for all peers,
    // so it's ok to error out if this fails. The expect cannot fire: the fetcher returns
    // exactly the requested entries.
    let crs_bytes = verified
        .remove(&PubDataType::CRS)
        .expect("fetcher returns every requested entry");
    let crs = tfhe::safe_serialization::safe_deserialize(
        std::io::Cursor::new(&crs_bytes),
        crate::consts::SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|e| anyhow::anyhow!("Failed to deserialize CRS: {}", e))?;
    Ok(VerifiedCrsMaterial::new(crs, crs_bytes))
}

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
) -> Result<VerifiedCrsMaterial, MetricedError> {
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
            Ok(VerifiedCrsMaterial::new(crs, crs_bytes))
        }
        Err(_) => fetch_public_crs_materials_from_peers::<_, _, G, R>(
            crypto_storage,
            crs_id,
            context_id,
            crs_digest,
            ro_storage_getter,
        )
        .await
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
    use crate::engine::context::SoftwareVersion;
    use crate::engine::context::{NodeInfo, SchemeDigests};
    use crate::engine::material_integrity::ERR_SERVER_KEY_DIGEST_MISMATCH;
    use crate::engine::public_material_sync::ERR_FAILED_TO_FETCH_PUBLIC_MATERIALS;
    use crate::engine::threshold::service::reshare_utils::ensure_verified_reshare_public_bytes;
    use crate::engine::threshold::service::reshare_utils::fetch_public_fhe_materials_from_peers;
    use crate::engine::threshold::service::reshare_utils::get_verified_crs_material;
    use crate::engine::threshold::service::reshare_utils::get_verified_fhe_public_materials;
    use crate::vault::storage::crypto_material::ThresholdCryptoMaterialStorage;
    use crate::vault::storage::ram::{FailingRamStorage, RamStorage};
    use crate::vault::storage::s3::DummyReadOnlyS3Storage;
    use crate::vault::storage::s3::DummyReadOnlyS3StorageGetter;
    use crate::vault::storage::store_versioned_at_request_id;
    use crate::vault::storage::test_support::StorageEntry;
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

    use crate::vault::storage::s3::split_url;

    #[test]
    fn test_split_url() {
        // Virtual-hosted style: bucket is a subdomain
        let (protocol, domain, bucket) =
            split_url(&"https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/".to_string())
                .unwrap();
        assert_eq!(protocol.as_str(), "https://");
        assert_eq!(domain.as_str(), "s3.eu-west-1.amazonaws.com");
        assert_eq!(bucket.as_str(), "zama-zws-dev-tkms-b6q87");

        // Path-style: bucket is in the URL path
        let (protocol, domain, bucket) =
            split_url(&"http://localhost:9000/kms".to_string()).unwrap();
        assert_eq!(protocol.as_str(), "http://");
        assert_eq!(domain.as_str(), "localhost:9000");
        assert_eq!(bucket.as_str(), "kms");

        // MinIO mock endpoint with path bucket
        let (protocol, domain, bucket) =
            split_url(&"http://dev-s3-mock:9000/kms".to_string()).unwrap();
        assert_eq!(protocol.as_str(), "http://");
        assert_eq!(domain.as_str(), "dev-s3-mock:9000");
        assert_eq!(bucket.as_str(), "kms");

        // file:// URL (used in isolated tests)
        let (protocol, domain, bucket) =
            split_url(&"file:///tmp/test-material".to_string()).unwrap();
        assert_eq!(protocol.as_str(), "file://");
        assert_eq!(domain.as_str(), "");
        assert_eq!(bucket.as_str(), "/tmp/test-material");

        // Path-style S3 with region
        let (protocol, domain, bucket) =
            split_url(&"https://s3.us-west-1.amazonaws.com/zama-zws-dev-tkms-b6q87/".to_string())
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
                    external_url: "http://localhost:12345".to_string(),
                    ca_cert: None,
                    // the storage url does not matter as we're using the mock
                    public_storage_url:
                        "https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/".to_string(),
                    public_storage_prefix: None,
                    extra_signer_addresses: vec![],
                    scheme_digests: SchemeDigests::new(),
                }],
                if two_nodes {
                    vec![NodeInfo {
                        mpc_identity: "Node2".to_string(),
                        party_id: 2,
                        external_url: "http://localhost:12345".to_string(),
                        ca_cert: None,
                        // the storage url does not matter as we're using the mock
                        public_storage_url:
                            "https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/"
                                .to_string(),
                        public_storage_prefix: None,
                        extra_signer_addresses: vec![],
                        scheme_digests: SchemeDigests::new(),
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
            assert_verified_bytes_match(
                &verified_material.verified_bytes(),
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

            let _keyset = fetch_public_fhe_materials_from_peers::<_, _, _, DummyReadOnlyS3Storage>(
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
            assert_verified_bytes_match(
                &verified_material.verified_bytes(),
                &*public_storage.lock().await,
                &key_id,
                &[PubDataType::ServerKey, PubDataType::PublicKey],
            )
            .await;
        }
    }

    #[tokio::test]
    async fn retained_local_bytes_restore_material_deleted_before_storage() {
        let mut rng = AesRng::seed_from_u64(2341);
        let req_id = RequestId::new_random(&mut rng);
        let key_id = RequestId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng);
        let (crypto_storage, key_digests, ro_storage_getter, (server_key, public_key)) =
            setup_public_materials_test(key_id, context_id, false).await;
        let public_storage = crypto_storage.inner.get_public_storage();

        {
            let mut storage = public_storage.lock().await;
            store_versioned_at_request_id(
                &mut *storage,
                &key_id,
                &server_key,
                &PubDataType::ServerKey.to_string(),
            )
            .await
            .unwrap();
            store_versioned_at_request_id(
                &mut *storage,
                &key_id,
                &public_key,
                &PubDataType::PublicKey.to_string(),
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
        let verified_bytes = verified_material.verified_bytes();

        let mut storage = public_storage.lock().await;
        for data_type in [PubDataType::ServerKey, PubDataType::PublicKey] {
            storage
                .delete_data(&key_id, &data_type.to_string())
                .await
                .unwrap();
        }
        let entries = verified_bytes
            .iter()
            .map(|(data_type, bytes)| (key_id, *data_type, bytes.clone()))
            .collect::<Vec<_>>();
        let (created, result) = ensure_verified_reshare_public_bytes(&mut *storage, &entries).await;

        result.unwrap();
        assert_eq!(
            created,
            vec![
                (key_id, PubDataType::ServerKey),
                (key_id, PubDataType::PublicKey),
            ]
        );
        assert_verified_bytes_match(
            &verified_bytes,
            &storage,
            &key_id,
            &[PubDataType::ServerKey, PubDataType::PublicKey],
        )
        .await;
    }

    // ==================== Compressed Key Tests ====================
    use super::VerifiedPublicMaterial;
    use crate::engine::material_integrity::{
        ERR_COMPRESSED_KEYSET_DIGEST_MISMATCH, ERR_PUBLIC_KEY_DIGEST_MISMATCH,
    };
    use tfhe::core_crypto::prelude::NormalizedHammingWeightBound;
    use tfhe::xof_key_set::CompressedXofKeySet;
    use threshold_execution::tfhe_internals::parameters::DKGParams;

    /// Generates a compressed keyset under `params`, so tests can vary the parameter set (e.g. to
    /// turn transciphering off) without repeating the config and Hamming-weight-bound plumbing.
    fn generate_compressed_keyset(params: DKGParams, key_id: &RequestId) -> CompressedXofKeySet {
        // use to_tfhe_config() which includes dedicated compact public key parameters
        // required for compressed keys
        let config = params.to_tfhe_config();
        // if the pmax value is not set, e.g., for test parameters, we do not do the HW check
        // and use a pmax=1 which should allow for any HW.
        let max_norm_hwt = params.sk_deviations().map(|x| x.pmax).unwrap_or(1.0);
        let max_norm_hwt = NormalizedHammingWeightBound::new(max_norm_hwt).unwrap();
        let tag = key_id.into();

        let (_client_key, compressed_keyset) =
            CompressedXofKeySet::generate(config, vec![42, 43, 44, 45], 128, max_norm_hwt, tag)
                .unwrap();
        compressed_keyset
    }

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

        let compressed_keyset = generate_compressed_keyset(crate::consts::TEST_PARAM, &key_id);

        let public_key = compressed_keyset.decompress().into_raw_parts().0;

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
                    external_url: "http://localhost:12345".to_string(),
                    ca_cert: None,
                    // the storage url does not matter as we're using the mock
                    public_storage_url:
                        "https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/".to_string(),
                    public_storage_prefix: None,
                    extra_signer_addresses: vec![],
                    scheme_digests: SchemeDigests::new(),
                }],
                if two_nodes {
                    vec![NodeInfo {
                        mpc_identity: "Node2".to_string(),
                        party_id: 2,
                        external_url: "http://localhost:12345".to_string(),
                        ca_cert: None,
                        // the storage url does not matter as we're using the mock
                        public_storage_url:
                            "https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/"
                                .to_string(),
                        public_storage_prefix: None,
                        extra_signer_addresses: vec![],
                        scheme_digests: SchemeDigests::new(),
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

    /// The flags read off compressed public material drive `ResharePreprocRequired` on the Set 2
    /// reshare path, which has no private share to read them from, so both must follow the keyset
    /// rather than a constant or each other.
    #[test]
    fn compressed_material_key_flags_follow_the_keyset() {
        let mut rng = AesRng::seed_from_u64(2334);
        let key_id = RequestId::new_random(&mut rng);

        let transciphering_params = crate::consts::TEST_PARAM;
        assert!(
            transciphering_params.transciphering_params().is_some(),
            "TEST_PARAM is expected to enable transciphering"
        );
        let with_transciphering = VerifiedPublicMaterial::new_compressed(
            generate_compressed_keyset(transciphering_params, &key_id),
            vec![],
            vec![],
        );
        assert!(with_transciphering.has_transciphering_key());
        assert!(with_transciphering.has_oprf_key());

        let mut no_transciphering_params = transciphering_params;
        no_transciphering_params.meta.transciphering_parameters = None;
        let without_transciphering = VerifiedPublicMaterial::new_compressed(
            generate_compressed_keyset(no_transciphering_params, &key_id),
            vec![],
            vec![],
        );
        assert!(!without_transciphering.has_transciphering_key());
        // the dedicated OPRF key is enabled independently of transciphering
        assert!(without_transciphering.has_oprf_key());
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
            &verified_material,
            VerifiedPublicMaterial::Compressed { .. }
        ));
        assert_verified_bytes_match(
            &verified_material.verified_bytes(),
            &ro_storage_getter.ram_storages[0],
            &key_id,
            &[PubDataType::CompressedXofKeySet, PubDataType::PublicKey],
        )
        .await;
        assert_eq!(*ro_storage_getter.counter.borrow(), 1);
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
            &verified_material,
            VerifiedPublicMaterial::Compressed { .. }
        ));
        assert_verified_bytes_match(
            &verified_material.verified_bytes(),
            &*public_storage.lock().await,
            &key_id,
            &[PubDataType::CompressedXofKeySet, PubDataType::PublicKey],
        )
        .await;
        // we should've used my own storage directly, so the counter here should be 0
        assert_eq!(*ro_storage_getter.counter.borrow(), 0);
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

    #[tokio::test]
    async fn verified_crs_material_retains_peer_and_local_bytes() {
        let mut rng = AesRng::seed_from_u64(2337);
        let req_id = RequestId::new_random(&mut rng);
        let key_id = RequestId::new_random(&mut rng);
        let crs_id = RequestId::new_random(&mut rng);
        let context_id = ContextId::new_random(&mut rng);
        let (crypto_storage, _, mut ro_storage_getter, _) =
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

        let (_, crs_bytes) = get_verified_crs_material(
            &crypto_storage,
            &req_id,
            &crs_id,
            &context_id,
            &crs_digest,
            &ro_storage_getter,
        )
        .await
        .unwrap()
        .into_parts();
        assert_eq!(*ro_storage_getter.counter.borrow(), 1);
        assert_verified_bytes_match(
            &[(PubDataType::CRS, crs_bytes.clone())],
            &ro_storage_getter.ram_storages[0],
            &crs_id,
            &[PubDataType::CRS],
        )
        .await;

        let public_storage = crypto_storage.inner.get_public_storage();
        public_storage
            .lock()
            .await
            .store_bytes(&crs_bytes, &crs_id, &PubDataType::CRS.to_string())
            .await
            .unwrap();
        let (_, local_crs_bytes) = get_verified_crs_material(
            &crypto_storage,
            &req_id,
            &crs_id,
            &context_id,
            &crs_digest,
            &ro_storage_getter,
        )
        .await
        .unwrap()
        .into_parts();
        assert_eq!(*ro_storage_getter.counter.borrow(), 1);
        assert_eq!(local_crs_bytes, crs_bytes);
    }

    /// Checks that `verified_bytes` contains the exact bytes from `storage` in `data_types` order.
    async fn assert_verified_bytes_match(
        verified_bytes: &[(PubDataType, Vec<u8>)],
        storage: &RamStorage,
        data_id: &RequestId,
        data_types: &[PubDataType],
    ) {
        assert_eq!(verified_bytes.len(), data_types.len());
        for ((entry_type, bytes), data_type) in verified_bytes.iter().zip(data_types) {
            assert_eq!(entry_type, data_type);
            let stored = storage
                .load_bytes(data_id, &data_type.to_string())
                .await
                .unwrap();
            assert_eq!(bytes, &stored, "{data_type} bytes differ from storage");
        }
    }

    #[tokio::test]
    async fn ensure_verified_reshare_public_bytes_keeps_matching_existing_entries() {
        let mut rng = AesRng::seed_from_u64(2338);
        let existing_id = RequestId::new_random(&mut rng);
        let missing_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();
        storage
            .store_bytes(b"from peer", &existing_id, &PubDataType::CRS.to_string())
            .await
            .unwrap();

        let (created, res) = ensure_verified_reshare_public_bytes(
            &mut storage,
            &[
                (existing_id, PubDataType::CRS, b"from peer".to_vec()),
                (missing_id, PubDataType::ServerKey, b"server key".to_vec()),
            ],
        )
        .await;
        res.unwrap();

        assert_eq!(created, vec![(missing_id, PubDataType::ServerKey)]);
        assert_eq!(
            storage
                .load_bytes(&existing_id, &PubDataType::CRS.to_string())
                .await
                .unwrap(),
            b"from peer"
        );
    }

    #[tokio::test]
    async fn ensure_verified_reshare_public_bytes_rejects_mismatched_partial_storage() {
        let mut rng = AesRng::seed_from_u64(2339);
        let existing_id = RequestId::new_random(&mut rng);
        let missing_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();
        storage
            .store_bytes(b"existing", &existing_id, &PubDataType::CRS.to_string())
            .await
            .unwrap();

        let (created, res) = ensure_verified_reshare_public_bytes(
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
                .contains("differs from the verified bytes")
        );
        assert_eq!(
            storage
                .load_bytes(&existing_id, &PubDataType::CRS.to_string())
                .await
                .unwrap(),
            b"existing"
        );
    }

    #[tokio::test]
    async fn ensure_verified_reshare_public_bytes_does_not_claim_an_entry_after_a_read_error() {
        let mut rng = AesRng::seed_from_u64(2340);
        let existing_id = RequestId::new_random(&mut rng);
        let entry = StorageEntry::new(existing_id, None, PubDataType::CRS.to_string());
        let mut storage = FailingRamStorage::new();
        storage
            .store_bytes(b"from peer", &existing_id, &PubDataType::CRS.to_string())
            .await
            .unwrap();
        storage.set_fail_data_exists_at(entry);

        let (created, res) = ensure_verified_reshare_public_bytes(
            &mut storage,
            &[(existing_id, PubDataType::CRS, b"from peer".to_vec())],
        )
        .await;

        assert!(
            res.unwrap_err()
                .to_string()
                .contains("Failed to check whether CRS")
        );
        assert!(created.is_empty());
        assert_eq!(
            storage
                .load_bytes(&existing_id, &PubDataType::CRS.to_string())
                .await
                .unwrap(),
            b"from peer"
        );
    }
}
