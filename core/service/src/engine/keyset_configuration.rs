use anyhow::anyhow;
use kms_grpc::identifiers::EpochId;
use kms_grpc::kms::v1::KeySetAddedInfo;
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
                let compression_type = kms_grpc::kms::v1::KeyGenSecretKeyConfig::try_from(
                    inner_config.secret_key_config,
                )?;
                Ok(ddec_keyset_config::KeySetConfig::Standard(
                    ddec_keyset_config::StandardKeySetConfig {
                        computation_key_type: WrappedComputeKeyType(compute_key_type).into(),
                        secret_key_config: WrappedCompressionConfig(compression_type).into(),
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

pub(crate) struct WrappedCompressionConfig(kms_grpc::kms::v1::KeyGenSecretKeyConfig);

impl From<WrappedCompressionConfig> for ddec_keyset_config::KeyGenSecretKeyConfig {
    fn from(value: WrappedCompressionConfig) -> Self {
        match value.0 {
            kms_grpc::kms::v1::KeyGenSecretKeyConfig::GenerateAll => {
                ddec_keyset_config::KeyGenSecretKeyConfig::GenerateAll
            }
            kms_grpc::kms::v1::KeyGenSecretKeyConfig::UseExistingCompressionSecretKey => {
                ddec_keyset_config::KeyGenSecretKeyConfig::UseExistingCompressionSecretKey
            }
            kms_grpc::kms::v1::KeyGenSecretKeyConfig::UseExisting => {
                ddec_keyset_config::KeyGenSecretKeyConfig::UseExisting
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
    /// Runs [`Self::validate`] to ensure all required fields are present and parseable.
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
        if keyset_config.is_none() {
            tracing::info!("No keyset config provided, defaulting to Standard KeySetConfig");
        }
        let result = Self {
            keyset_config: preproc_proto_to_keyset_config(&keyset_config)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?,
            keyset_added_info,
        };
        result.validate()?;
        Ok(result)
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
    /// Will always return Some request ID if [`KeySetCofig::Standard`] is used with the [`KeyGenSecretKeyConfig::UseExistingCompressionSecretKey`] setting.
    pub fn get_existing_compression_key_id(&self) -> anyhow::Result<Option<RequestId>> {
        if let Some(inner) = self
            .keyset_added_info
            .as_ref()
            .and_then(|info| info.existing_compression_keyset_id.clone())
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

    /// Retrieves the existing keyset ID and epoch ID from the added info.
    /// Will always return Ok if [`KeySetConfig::Standard`] is used with the [`KeyGenSecretKeyConfig::UseExisting`] setting
    /// and validation passed in [`InternalKeySetConfig::new`].
    pub fn get_existing_keyset_id(&self) -> anyhow::Result<RequestId> {
        let added_info = self
            .keyset_added_info
            .as_ref()
            .ok_or_else(|| anyhow!("keyset_added_info is required for UseExisting"))
            .map_err(|e| anyhow::anyhow!("Failed to parse keyset_added_info: {}", e))?;
        let keyset_id = parse_grpc_request_id(
            added_info
                .existing_keyset_id
                .as_ref()
                .ok_or_else(|| anyhow!("missing existing_keyset_id"))?,
            RequestIdParsingErr::Other("invalid existing keyset ID".to_string()),
        )
        .map_err(|e| anyhow::anyhow!("Failed to parse existing keyset ID: {}", e))?;
        Ok(keyset_id)
    }

    pub fn get_existing_compression_epoch_id(&self) -> anyhow::Result<Option<EpochId>> {
        let added_info = self.keyset_added_info.as_ref().ok_or_else(|| {
            anyhow!("keyset_added_info is required for UseExistingCompressionSecretKey")
        })?;
        let epoch_id: Option<EpochId> = added_info
            .compression_epoch_id
            .as_ref()
            .map(|inner| {
                parse_grpc_request_id(
                    inner,
                    RequestIdParsingErr::Other("invalid compression epoch ID".to_string()),
                )
            })
            .transpose()?;
        Ok(epoch_id)
    }

    pub fn get_existing_epoch_id(&self) -> anyhow::Result<Option<EpochId>> {
        let added_info = self
            .keyset_added_info
            .as_ref()
            .ok_or_else(|| anyhow!("keyset_added_info is required for UseExisting"))?;
        let epoch_id: Option<EpochId> = added_info
            .existing_epoch_id
            .as_ref()
            .map(|inner| {
                parse_grpc_request_id(
                    inner,
                    RequestIdParsingErr::Other("invalid existing keyset ID".to_string()),
                )
            })
            .transpose()?;
        Ok(epoch_id)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        match &self.keyset_config {
            ddec_keyset_config::KeySetConfig::Standard(inner) => match inner.secret_key_config {
                ddec_keyset_config::KeyGenSecretKeyConfig::GenerateAll => {}
                ddec_keyset_config::KeyGenSecretKeyConfig::UseExistingCompressionSecretKey => {
                    // Must have a parseable compression key ID
                    let id = self.get_existing_compression_key_id()?;
                    anyhow::ensure!(
                        id.is_some(),
                        "existing_compression_keyset_id must be set for UseExistingCompressionSecretKey"
                    );
                    // Optional compression epoch ID must be parseable if set
                    self.get_existing_compression_epoch_id()?;
                }
                ddec_keyset_config::KeyGenSecretKeyConfig::UseExisting => {
                    // Must have a parseable existing keyset ID
                    self.get_existing_keyset_id()?;
                    // Optional existing epoch ID must be parseable if set
                    self.get_existing_epoch_id()?;
                }
            },
            ddec_keyset_config::KeySetConfig::DecompressionOnly => {
                self.get_from_and_to()?;
            }
        }
        Ok(())
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
        KeyGenSecretKeyConfig, KeySetAddedInfo, KeySetConfig, KeySetType, StandardKeySetConfig,
    };

    #[test]
    fn test_internal_keyset_config_standard_default() {
        // Standard config with Generate compression, no added info needed, should be valid
        let keyset_config = KeySetConfig {
            keyset_type: KeySetType::Standard as i32,
            standard_keyset_config: Some(StandardKeySetConfig {
                compute_key_type: 0,
                secret_key_config: KeyGenSecretKeyConfig::GenerateAll as i32,
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
                secret_key_config: KeyGenSecretKeyConfig::UseExisting as i32,
                compressed_key_config: 0,
            }),
        };
        let result = InternalKeySetConfig::new(Some(keyset_config), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_internal_keyset_config_standard_use_existing_with_added_info_missing_ids() {
        // Standard config with UseExisting, the added info is present but missing existing_keyset_id and/or existing_epoch_id
        let keyset_config = KeySetConfig {
            keyset_type: KeySetType::Standard as i32,
            standard_keyset_config: Some(StandardKeySetConfig {
                compute_key_type: 0,
                secret_key_config: KeyGenSecretKeyConfig::UseExisting as i32,
                compressed_key_config: 0,
            }),
        };
        {
            let keyset_added_info = KeySetAddedInfo {
                existing_keyset_id: None,
                existing_epoch_id: None,
                ..Default::default()
            };
            let result = InternalKeySetConfig::new(Some(keyset_config), Some(keyset_added_info));
            assert!(result.is_err());
        }
        {
            let keyset_added_info = KeySetAddedInfo {
                existing_keyset_id: Some(kms_grpc::kms::v1::RequestId {
                    request_id: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                        .to_string(),
                }),
                existing_epoch_id: None,
                ..Default::default()
            };
            let result = InternalKeySetConfig::new(Some(keyset_config), Some(keyset_added_info));
            assert!(result.is_ok());
        }
        {
            let keyset_added_info = KeySetAddedInfo {
                existing_keyset_id: None,
                existing_epoch_id: Some(kms_grpc::kms::v1::RequestId {
                    request_id: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                        .to_string(),
                }),
                ..Default::default()
            };
            let result = InternalKeySetConfig::new(Some(keyset_config), Some(keyset_added_info));
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_internal_keyset_config_standard_use_existing_with_added_info_with_ids() {
        // Standard config with UseExisting, added info is present with both existing_keyset_id and existing_epoch_id
        let keyset_config = KeySetConfig {
            keyset_type: KeySetType::Standard as i32,
            standard_keyset_config: Some(StandardKeySetConfig {
                compute_key_type: 0,
                secret_key_config: KeyGenSecretKeyConfig::UseExisting as i32,
                compressed_key_config: 0,
            }),
        };
        let keyset_added_info = KeySetAddedInfo {
            existing_keyset_id: Some(kms_grpc::kms::v1::RequestId {
                request_id: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                    .to_string(),
            }),
            existing_epoch_id: Some(kms_grpc::kms::v1::RequestId {
                request_id: "1112030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
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

    const VALID_ID: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const VALID_ID_2: &str = "1112030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const INVALID_ID: &str = "not-a-valid-hex-id";

    fn request_id(id: &str) -> kms_grpc::kms::v1::RequestId {
        kms_grpc::kms::v1::RequestId {
            request_id: id.to_string(),
        }
    }

    #[test]
    fn test_new_use_existing_unparseable_epoch_id() {
        // Valid keyset ID but unparseable epoch ID should be rejected
        let result = InternalKeySetConfig::new(
            Some(KeySetConfig {
                keyset_type: KeySetType::Standard as i32,
                standard_keyset_config: Some(StandardKeySetConfig {
                    compute_key_type: 0,
                    secret_key_config: KeyGenSecretKeyConfig::UseExisting as i32,
                    compressed_key_config: 0,
                }),
            }),
            Some(KeySetAddedInfo {
                existing_keyset_id: Some(request_id(VALID_ID)),
                existing_epoch_id: Some(request_id(INVALID_ID)),
                ..Default::default()
            }),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_new_use_existing_compression_sk_valid() {
        // Valid compression keyset ID, no epoch
        let result = InternalKeySetConfig::new(
            Some(KeySetConfig {
                keyset_type: KeySetType::Standard as i32,
                standard_keyset_config: Some(StandardKeySetConfig {
                    compute_key_type: 0,
                    secret_key_config: KeyGenSecretKeyConfig::UseExistingCompressionSecretKey
                        as i32,
                    compressed_key_config: 0,
                }),
            }),
            Some(KeySetAddedInfo {
                existing_compression_keyset_id: Some(request_id(VALID_ID)),
                compression_epoch_id: None,
                ..Default::default()
            }),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_new_use_existing_compression_sk_with_epoch() {
        // Valid compression keyset ID and epoch
        let result = InternalKeySetConfig::new(
            Some(KeySetConfig {
                keyset_type: KeySetType::Standard as i32,
                standard_keyset_config: Some(StandardKeySetConfig {
                    compute_key_type: 0,
                    secret_key_config: KeyGenSecretKeyConfig::UseExistingCompressionSecretKey
                        as i32,
                    compressed_key_config: 0,
                }),
            }),
            Some(KeySetAddedInfo {
                existing_compression_keyset_id: Some(request_id(VALID_ID)),
                compression_epoch_id: Some(request_id(VALID_ID_2)),
                ..Default::default()
            }),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_new_use_existing_compression_sk_unparseable_epoch() {
        // Valid compression keyset ID but unparseable epoch should be rejected
        let result = InternalKeySetConfig::new(
            Some(KeySetConfig {
                keyset_type: KeySetType::Standard as i32,
                standard_keyset_config: Some(StandardKeySetConfig {
                    compute_key_type: 0,
                    secret_key_config: KeyGenSecretKeyConfig::UseExistingCompressionSecretKey
                        as i32,
                    compressed_key_config: 0,
                }),
            }),
            Some(KeySetAddedInfo {
                existing_compression_keyset_id: Some(request_id(VALID_ID)),
                compression_epoch_id: Some(request_id(INVALID_ID)),
                ..Default::default()
            }),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_new_use_existing_compression_sk_unparseable_key_id() {
        // Unparseable compression keyset ID should be rejected
        let result = InternalKeySetConfig::new(
            Some(KeySetConfig {
                keyset_type: KeySetType::Standard as i32,
                standard_keyset_config: Some(StandardKeySetConfig {
                    compute_key_type: 0,
                    secret_key_config: KeyGenSecretKeyConfig::UseExistingCompressionSecretKey
                        as i32,
                    compressed_key_config: 0,
                }),
            }),
            Some(KeySetAddedInfo {
                existing_compression_keyset_id: Some(request_id(INVALID_ID)),
                compression_epoch_id: None,
                ..Default::default()
            }),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_new_decompression_only_unparseable_from_id() {
        // Unparseable from ID should be rejected
        let result = InternalKeySetConfig::new(
            Some(KeySetConfig {
                keyset_type: KeySetType::DecompressionOnly as i32,
                standard_keyset_config: None,
            }),
            Some(KeySetAddedInfo {
                from_keyset_id_decompression_only: Some(request_id(INVALID_ID)),
                to_keyset_id_decompression_only: Some(request_id(VALID_ID)),
                ..Default::default()
            }),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_new_decompression_only_unparseable_to_id() {
        // Unparseable to ID should be rejected
        let result = InternalKeySetConfig::new(
            Some(KeySetConfig {
                keyset_type: KeySetType::DecompressionOnly as i32,
                standard_keyset_config: None,
            }),
            Some(KeySetAddedInfo {
                from_keyset_id_decompression_only: Some(request_id(VALID_ID)),
                to_keyset_id_decompression_only: Some(request_id(INVALID_ID)),
                ..Default::default()
            }),
        );
        assert!(result.is_err());
    }
}
