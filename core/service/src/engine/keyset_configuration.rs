use anyhow::anyhow;
use kms_grpc::kms::v1::{KeySetAddedInfo, KeySetType};
#[cfg(feature = "non-wasm")]
use kms_grpc::utils::tonic_result::BoxedStatus;
use kms_grpc::RequestId;
use threshold_fhe::execution::keyset_config::{self as ddec_keyset_config};

use crate::engine::validation::{parse_grpc_request_id, RequestIdParsingErr};

pub(crate) struct WrappedKeySetConfig(kms_grpc::kms::v1::KeySetConfig);

impl TryFrom<WrappedKeySetConfig> for ddec_keyset_config::KeySetConfig {
    type Error = anyhow::Error;

    fn try_from(value: WrappedKeySetConfig) -> Result<Self, Self::Error> {
        let keyset_type = kms_grpc::kms::v1::KeySetType::try_from(value.0.keyset_type)?;
        match keyset_type {
            kms_grpc::kms::v1::KeySetType::Standard => {
                let inner_config = value
                    .0
                    .standard_keyset_config
                    .ok_or_else(|| anyhow::anyhow!("missing StandardKeySetConfig"))?;
                let compute_key_type =
                    kms_grpc::kms::v1::ComputeKeyType::try_from(inner_config.compute_key_type)?;
                let compression_type = kms_grpc::kms::v1::KeySetCompressionConfig::try_from(
                    inner_config.keyset_compression_config,
                )?;
                Ok(ddec_keyset_config::KeySetConfig::Standard(
                    ddec_keyset_config::StandardKeySetConfig {
                        computation_key_type: WrappedComputeKeyType(compute_key_type).into(),
                        compression_config: WrappedCompressionConfig(compression_type).into(),
                        compressed_key_config: WrappedCompressedKeyConfig(
                            inner_config.compressed_key_config,
                        )
                        .into(),
                    },
                ))
            }
            kms_grpc::kms::v1::KeySetType::DecompressionOnly => {
                Ok(ddec_keyset_config::KeySetConfig::DecompressionOnly)
            }
        }
    }
}

pub(crate) struct WrappedComputeKeyType(kms_grpc::kms::v1::ComputeKeyType);

impl From<WrappedComputeKeyType> for ddec_keyset_config::ComputeKeyType {
    fn from(value: WrappedComputeKeyType) -> Self {
        match value.0 {
            kms_grpc::kms::v1::ComputeKeyType::Cpu => ddec_keyset_config::ComputeKeyType::Cpu,
        }
    }
}

pub(crate) struct WrappedCompressionConfig(kms_grpc::kms::v1::KeySetCompressionConfig);

impl From<WrappedCompressionConfig> for ddec_keyset_config::KeySetCompressionConfig {
    fn from(value: WrappedCompressionConfig) -> Self {
        match value.0 {
            kms_grpc::kms::v1::KeySetCompressionConfig::Generate => {
                ddec_keyset_config::KeySetCompressionConfig::Generate
            }
            kms_grpc::kms::v1::KeySetCompressionConfig::UseExisting => {
                ddec_keyset_config::KeySetCompressionConfig::UseExisting
            }
        }
    }
}

/// Wrapper for parsing CompressedKeyConfig from gRPC proto.
pub(crate) struct WrappedCompressedKeyConfig(i32);

impl From<WrappedCompressedKeyConfig> for ddec_keyset_config::CompressedKeyConfig {
    fn from(value: WrappedCompressedKeyConfig) -> Self {
        match value.0 {
            1 => ddec_keyset_config::CompressedKeyConfig::All,
            _ => ddec_keyset_config::CompressedKeyConfig::None, // 0 or invalid defaults to None
        }
    }
}

/// Helper structure to represent a valid keyset configuration.
/// This is used to conviently parse and sanity-check gRPC arugments and for internal function parsing.
pub struct InternalKeySetConfig {
    keyset_config: ddec_keyset_config::KeySetConfig,
    keyset_added_info: Option<KeySetAddedInfo>,
}

impl InternalKeySetConfig {
    /// Creates a new `InternalKeySetConfig` instance.
    ///
    /// If `keyset_config` is `None`, it defaults to [`KeySetConfig::Standard`].
    /// If `keyset_config` is set to `DecompressionOnly`, `keyset_added_info` must be provided.
    ///     Furthermore, within `keyset_added_info` the `from_keyset_id_decompression_only` and `to_keyset_id_decompression_only` must be set.
    /// If `keyset_config` is set to `Standard` with `KeySetCompressionConfig::UseExisting` compression,
    ///     then `keyset_added_info` must be provided and must have `compression_keyset_id` set.
    ///
    /// # Arguments
    /// * `keyset_config` - Optional keyset configuration.
    /// * `keyset_added_info` - Optional additional information for the keyset.
    ///
    /// # Returns
    /// - `Ok(InternalKeySetConfig)` on success.
    /// - `Err(anyhow::Error)` if the configuration is invalid.
    pub fn new(
        keyset_config: Option<kms_grpc::kms::v1::KeySetConfig>,
        keyset_added_info: Option<KeySetAddedInfo>,
    ) -> anyhow::Result<Self> {
        // Ensure a fail-fast approach
        match keyset_config {
            Some(inner) => {
                match inner.keyset_type() {
                    KeySetType::Standard => {
                        match &inner.standard_keyset_config {
                            Some(config) => {
                                if kms_grpc::kms::v1::KeySetCompressionConfig::try_from(
                                    config.keyset_compression_config,
                                ) == Ok(kms_grpc::kms::v1::KeySetCompressionConfig::UseExisting)
                                {
                                    match &keyset_added_info {
                                        Some(inner_key_set_added_info) => {
                                            // If compression is set to UseExisting, we need the added info
                                            if inner_key_set_added_info
                                                .compression_keyset_id
                                                .is_none()
                                            {
                                                return Err(anyhow!(
                                                    "`keyset_added_info` must contain `compression_keyset_id` when `keyset_config` is set to `Standard` with `UseExisting` compression",
                                                ));
                                            }
                                        }
                                        None => {
                                            // If compression is set to UseExisting, we need the added info
                                            return Err(anyhow!(
                                                "`keyset_added_info` must be provided when `keyset_config` is set to `Standard` with `UseExisting` compression",
                                            ));
                                        }
                                    }
                                }
                            }
                            None => {
                                return Err(anyhow!(
                                    "`standard_keyset_config` must be provided for Standard KeySetConfig",
                                ));
                            }
                        }
                    }
                    KeySetType::DecompressionOnly => {
                        match &keyset_added_info {
                            Some(inner_added_info) => {
                                // If keyset_config is set to DecompressionOnly, we need the added info
                                if inner_added_info.from_keyset_id_decompression_only.is_none()
                                    || inner_added_info.to_keyset_id_decompression_only.is_none()
                                {
                                    return Err(anyhow!(
                                        "`keyset_added_info` must contain `from_keyset_id_decompression_only` and `to_keyset_id_decompression_only` when `keyset_config` is set to `DecompressionOnly`",
                                    ));
                                }
                            }
                            None => {
                                return Err(anyhow!(
                                "`keyset_added_info` must be provided when `keyset_config` is set to `DecompressionOnly`",
                            ));
                            }
                        }
                    }
                }
            }
            None => {
                // Default to Standard KeySetConfig
                tracing::info!("No keyset config provided, defaulting to Standard KeySetConfig");
            }
        }
        Ok(Self {
            keyset_config: preproc_proto_to_keyset_config(&keyset_config)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?,
            keyset_added_info,
        })
    }

    pub fn keyset_config(&self) -> &ddec_keyset_config::KeySetConfig {
        &self.keyset_config
    }

    pub fn keyset_added_info(&self) -> Option<&KeySetAddedInfo> {
        self.keyset_added_info.as_ref()
    }

    /// Retrieves the `from` and `to` keyset IDs from the added info.
    /// This will never return an error if the `keyset_added_info` is set to `DecompressionOnly`,
    pub fn get_from_and_to(&self) -> anyhow::Result<(RequestId, RequestId)> {
        Ok(match &self.keyset_added_info {
            Some(added_info) => {
                match (
                    added_info.from_keyset_id_decompression_only.to_owned(),
                    added_info.to_keyset_id_decompression_only.to_owned(),
                ) {
                    (Some(from), Some(to)) => (
                        parse_grpc_request_id(
                            &from,
                            RequestIdParsingErr::Other("invalid from ID".to_string()),
                        )
                        .map_err(|e| anyhow::anyhow!("Failed to parse from ID: {}", e))?,
                        parse_grpc_request_id(
                            &to,
                            RequestIdParsingErr::Other("invalid to ID".to_string()),
                        )
                        .map_err(|e| anyhow::anyhow!("Failed to parse to ID: {}", e))?,
                    ),
                    _ => anyhow::bail!("Missing from and to keyset information"),
                }
            }
            None => {
                anyhow::bail!("Added info is required when only generating a decompression key")
            }
        })
    }

    /// Retrieves the compression keyset ID from the added info.
    /// Will always return Some request ID if [`KeySetCofig::Standard`] is used with the [`KeySetCompressionConfig::UseExisting`] setting.
    pub fn get_compression_id(&self) -> anyhow::Result<Option<RequestId>> {
        if let Some(inner) = self
            .keyset_added_info
            .as_ref()
            .and_then(|info| info.compression_keyset_id.clone())
        {
            let key_id = parse_grpc_request_id(
                &inner,
                RequestIdParsingErr::Other("invalid compression keyset ID".to_string()),
            )?;
            Ok(Some(key_id))
        } else {
            Ok(None)
        }
    }
}

#[cfg(feature = "non-wasm")]
pub(crate) fn preproc_proto_to_keyset_config(
    keyset_config: &Option<kms_grpc::kms::v1::KeySetConfig>,
) -> Result<ddec_keyset_config::KeySetConfig, BoxedStatus> {
    match keyset_config {
        None => Ok(ddec_keyset_config::KeySetConfig::default()),
        Some(inner) => Ok(WrappedKeySetConfig(*inner).try_into().map_err(|e| {
            tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Failed to parse KeySetConfig: {e}"),
            )
        })?),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::engine::keyset_configuration::InternalKeySetConfig;
    use kms_grpc::kms::v1::{
        KeySetAddedInfo, KeySetCompressionConfig, KeySetConfig, KeySetType, StandardKeySetConfig,
    };

    #[test]
    fn test_internal_keyset_config_standard_default() {
        // Standard config with Generate compression, no added info needed, should be valid
        let keyset_config = KeySetConfig {
            keyset_type: KeySetType::Standard as i32,
            standard_keyset_config: Some(StandardKeySetConfig {
                compute_key_type: 0,
                keyset_compression_config: KeySetCompressionConfig::Generate as i32,
                compressed_key_config: 0,
            }),
        };
        let result = InternalKeySetConfig::new(Some(keyset_config), None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_internal_keyset_config_standard_use_existing_missing_added_info() {
        // Standard config with UseExisting compression, missing added info, should be invalid
        let keyset_config = KeySetConfig {
            keyset_type: KeySetType::Standard as i32,
            standard_keyset_config: Some(StandardKeySetConfig {
                compute_key_type: 0,
                keyset_compression_config: KeySetCompressionConfig::UseExisting as i32,
                compressed_key_config: 0,
            }),
        };
        let result = InternalKeySetConfig::new(Some(keyset_config), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_internal_keyset_config_standard_use_existing_with_added_info_missing_id() {
        // Standard config with UseExisting compression, the added info is present but missing compression_keyset_id, hence the config should be invalid
        let keyset_config = KeySetConfig {
            keyset_type: KeySetType::Standard as i32,
            standard_keyset_config: Some(StandardKeySetConfig {
                compute_key_type: 0,
                keyset_compression_config: KeySetCompressionConfig::UseExisting as i32,
                compressed_key_config: 0,
            }),
        };
        let keyset_added_info = KeySetAddedInfo {
            compression_keyset_id: None,
            from_keyset_id_decompression_only: None,
            to_keyset_id_decompression_only: None,
        };
        let result = InternalKeySetConfig::new(Some(keyset_config), Some(keyset_added_info));
        assert!(result.is_err());
    }

    #[test]
    fn test_internal_keyset_config_standard_use_existing_with_added_info_with_id() {
        // Standard config with UseExisting compression, added info is present, and so is compression_keyset_id, so the config should be valid
        let keyset_config = KeySetConfig {
            keyset_type: KeySetType::Standard as i32,
            standard_keyset_config: Some(StandardKeySetConfig {
                compute_key_type: 0,
                keyset_compression_config: KeySetCompressionConfig::UseExisting as i32,
                compressed_key_config: 0,
            }),
        };
        let keyset_added_info = KeySetAddedInfo {
            compression_keyset_id: Some(kms_grpc::kms::v1::RequestId {
                request_id: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                    .to_string(),
            }),
            ..Default::default()
        };
        let result = InternalKeySetConfig::new(Some(keyset_config), Some(keyset_added_info));
        assert!(result.is_ok());
    }

    #[test]
    fn test_internal_keyset_config_decompression_only_missing_added_info() {
        // DecompressionOnly config, missing added info, should be invalid
        let keyset_config = KeySetConfig {
            keyset_type: KeySetType::DecompressionOnly as i32,
            standard_keyset_config: None,
        };
        let result = InternalKeySetConfig::new(Some(keyset_config), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_internal_keyset_config_decompression_only_with_added_info_missing_ids() {
        // DecompressionOnly config, added info is present but missing from/to ids, should be invalid
        let keyset_config = KeySetConfig {
            keyset_type: KeySetType::DecompressionOnly as i32,
            standard_keyset_config: None,
        };
        let keyset_added_info = KeySetAddedInfo {
            from_keyset_id_decompression_only: None,
            to_keyset_id_decompression_only: None,
            ..Default::default()
        };
        let result = InternalKeySetConfig::new(Some(keyset_config), Some(keyset_added_info));
        assert!(result.is_err());
    }

    #[test]
    fn test_internal_keyset_config_decompression_only_with_added_info_with_ids() {
        // DecompressionOnly config, added info is present with from/to ids set
        let keyset_config = KeySetConfig {
            keyset_type: KeySetType::DecompressionOnly as i32,
            standard_keyset_config: None,
        };
        let keyset_added_info = KeySetAddedInfo {
            from_keyset_id_decompression_only: Some(kms_grpc::kms::v1::RequestId {
                request_id: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                    .to_string(),
            }),
            to_keyset_id_decompression_only: Some(kms_grpc::kms::v1::RequestId {
                request_id: "1112030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                    .to_string(),
            }),
            ..Default::default()
        };
        let result = InternalKeySetConfig::new(Some(keyset_config), Some(keyset_added_info));
        assert!(result.is_ok());
    }

    #[test]
    fn test_internal_keyset_config_none_defaults_to_standard() {
        // None config should default to Standard
        let result = InternalKeySetConfig::new(None, None);
        assert!(result.is_ok());
    }
}
