//! This module provides the context definition that
//! can be constructed from the protobuf types and stored in the vault.

use kms_grpc::RequestId;
use serde::{Deserialize, Serialize};
use tfhe::{named::Named, Versionize};
use tfhe_versionable::VersionsDispatch;

use crate::{
    cryptography::internal_crypto_types::{PublicEncKey, PublicSigKey},
    vault::storage::{
        crypto_material::get_core_signing_key, read_context_at_request_id, StorageReader,
    },
};

const ERR_DUPLICATE_PARTY_IDS: &str = "Duplicate party_ids found in context";
const ERR_DUPLICATE_NAMES: &str = "Duplicate names found in context";
const ERR_INCONSISTENT_SIGNING_KEY: &str = "Inconsistent signing key in context";
const ERR_INVALID_THRESHOLD_SINGLE_NODE: &str = "Invalid threshold for centralized context";
const ERR_INVALID_THRESHOLD_MULTI_NODE: &str = "Invalid threshold for threshold context";
const ERR_MISSING_PREVIOUS_CONTEXT: &str = "Missing previous context";
const ERR_WRONG_SOFTWARE_VERSION: &str = "Current version is lower than previous version";
const ERR_DUPLICATE_CONTEXT_ID: &str = "Context ID is the same as the previous context";
const ERR_PREVIOUS_CONTEXT_ID_MISMATCH: &str =
    "Previous context ID does not match the given previous context";

#[derive(Clone, Debug, VersionsDispatch)]
pub enum SoftwareVersionVersioned {
    V0(SoftwareVersion),
}

/// Represents the software version of the KMS.
/// The ordering is based on the major, minor, and patch versions,
/// the tag does not affect the ordering.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(SoftwareVersionVersioned)]
pub struct SoftwareVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
    pub tag: Option<String>,
}

impl PartialOrd for SoftwareVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SoftwareVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch))
    }
}

impl Named for SoftwareVersion {
    const NAME: &'static str = "kms::SoftwareVersion";
}

impl std::fmt::Display for SoftwareVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(tag) = &self.tag {
            write!(f, "{}.{}.{}-{}", self.major, self.minor, self.patch, tag)
        } else {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        }
    }
}

#[derive(Clone, Debug, VersionsDispatch)]
pub enum NodeInfoVersioned {
    V0(NodeInfo),
}

#[derive(Clone, Debug, Versionize, Serialize, Deserialize)]
#[versionize(NodeInfoVersioned)]
pub struct NodeInfo {
    pub name: String,
    pub party_id: u32,
    pub verification_key: PublicSigKey,
    pub backup_encryption_public_key: PublicEncKey,

    pub external_url: String,

    // Unfortunately, the TLS certificate is a Vec<u8> here,
    // because we cannot versionize the X509Certificate type.
    pub tls_cert: Vec<u8>,

    pub public_storage_url: String,
    pub extra_verification_keys: Vec<PublicSigKey>,
}

impl TryFrom<kms_grpc::kms::v1::KmsNode> for NodeInfo {
    type Error = anyhow::Error;

    fn try_from(value: kms_grpc::kms::v1::KmsNode) -> anyhow::Result<Self> {
        Ok(NodeInfo {
            name: value.name,
            party_id: value.party_id.try_into()?,
            verification_key: bc2wrap::deserialize(&value.verification_key)?,
            backup_encryption_public_key: bc2wrap::deserialize(
                &value.backup_encryption_public_key,
            )?,
            external_url: value.external_url,
            tls_cert: value.tls_cert,
            public_storage_url: value.public_storage_url,
            extra_verification_keys: value
                .extra_verification_keys
                .into_iter()
                .map(|k| bc2wrap::deserialize(&k))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl TryFrom<NodeInfo> for kms_grpc::kms::v1::KmsNode {
    type Error = anyhow::Error;
    fn try_from(value: NodeInfo) -> anyhow::Result<Self> {
        Ok(kms_grpc::kms::v1::KmsNode {
            name: value.name,
            party_id: value.party_id.try_into()?,
            verification_key: bc2wrap::serialize(&value.verification_key)?,
            backup_encryption_public_key: bc2wrap::serialize(&value.backup_encryption_public_key)?,
            external_url: value.external_url,
            tls_cert: value.tls_cert,
            public_storage_url: value.public_storage_url,
            extra_verification_keys: value
                .extra_verification_keys
                .into_iter()
                .map(|k| bc2wrap::serialize(&k))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl Named for NodeInfo {
    const NAME: &'static str = "kms::NodeInfo";
}

#[derive(VersionsDispatch, Clone, Debug, Serialize, Deserialize)]
pub enum ContextInfoVersioned {
    V0(ContextInfo),
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(ContextInfoVersioned)]
pub struct ContextInfo {
    pub kms_nodes: Vec<NodeInfo>,
    pub context_id: RequestId,
    pub previous_context_id: Option<RequestId>,
    pub software_version: SoftwareVersion,
    pub threshold: u32,
}

impl ContextInfo {
    pub fn context_id(&self) -> &RequestId {
        &self.context_id
    }

    /// Most of these checks are simply sanity checks because
    /// before the context passed to the KMS, it should have been validated on the gateway.
    pub async fn verify<S: StorageReader>(
        &self,
        my_id: u32,
        storage: &S,
        previous_context: Option<&ContextInfo>,
    ) -> anyhow::Result<()> {
        // Check the signing key is consistent with the private key in storage.
        let signing_key = get_core_signing_key(storage).await?;

        let my_node = self
            .kms_nodes
            .iter()
            .find(|node| node.party_id == my_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Node with party_id {} not found in context {}",
                    my_id,
                    self.context_id()
                )
            })?;

        if my_node.verification_key.pk() != signing_key.sk().verifying_key() {
            return Err(anyhow::anyhow!(
                "{} {}",
                ERR_INCONSISTENT_SIGNING_KEY,
                self.context_id()
            ));
        }

        // check kms_nodes have unique party_ids
        let party_ids: std::collections::HashSet<_> =
            self.kms_nodes.iter().map(|node| node.party_id).collect();
        if party_ids.len() != self.kms_nodes.len() {
            return Err(anyhow::anyhow!(
                "{} {}",
                ERR_DUPLICATE_PARTY_IDS,
                self.context_id()
            ));
        }

        // check that the party IDs are in the range [1, kms_nodes.len()]
        for node in &self.kms_nodes {
            (1..=self.kms_nodes.len() as u32)
                .contains(&node.party_id)
                .then_some(())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Party ID {} out of range in context {}",
                        node.party_id,
                        self.context_id()
                    )
                })?;
        }

        if self.kms_nodes.len() == 1 {
            // threshold must be 0 for single node context
            if self.threshold != 0 {
                return Err(anyhow::anyhow!(
                    "{} {}",
                    ERR_INVALID_THRESHOLD_SINGLE_NODE,
                    self.context_id()
                ));
            }
        } else {
            // check that threshold is valid such that 3*threshold + 1 == kms_nodes.len()
            if self.kms_nodes.len() != 3 * self.threshold as usize + 1 {
                return Err(anyhow::anyhow!(
                    "{} (context={}, threshold={}, nodes={})",
                    ERR_INVALID_THRESHOLD_MULTI_NODE,
                    self.context_id(),
                    self.threshold,
                    self.kms_nodes.len()
                ));
            }
        }

        // the kms_nodes must have unique names
        let names: std::collections::HashSet<_> = self
            .kms_nodes
            .iter()
            .map(|node| node.name.clone())
            .collect();
        if names.len() != self.kms_nodes.len() {
            return Err(anyhow::anyhow!(
                "{} {}",
                ERR_DUPLICATE_NAMES,
                self.context_id()
            ));
        }

        if let Some(prev_context) = previous_context {
            // self.previous_context_id must match the previous context ID
            if self.previous_context_id != Some(*prev_context.context_id()) {
                return Err(anyhow::anyhow!(
                    "{}: expected {:?}, got {:?}",
                    ERR_PREVIOUS_CONTEXT_ID_MISMATCH,
                    Some(*prev_context.context_id()),
                    self.previous_context_id,
                ));
            }

            // check that the previous context exists in storage
            let _ = read_context_at_request_id(storage, prev_context.context_id())
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "{} (prev_context={}, error={})",
                        ERR_MISSING_PREVIOUS_CONTEXT,
                        prev_context.context_id(),
                        e
                    )
                })?;

            // check that the software version is equal or higher than the previous context
            if self.software_version < prev_context.software_version {
                return Err(anyhow::anyhow!(
                    "{} (prev_version={}, current_version={}, context_id={})",
                    ERR_WRONG_SOFTWARE_VERSION,
                    prev_context.software_version,
                    self.software_version,
                    self.context_id()
                ));
            }

            // check that the context ID is different from the previous context
            if self.context_id == *prev_context.context_id() {
                return Err(anyhow::anyhow!(
                    "{} {}",
                    ERR_DUPLICATE_CONTEXT_ID,
                    self.context_id(),
                ));
            }
        }

        Ok(())
    }
}

impl Named for ContextInfo {
    const NAME: &'static str = "kms::ContextInfo";
}

impl TryFrom<kms_grpc::kms::v1::KmsContext> for ContextInfo {
    type Error = anyhow::Error;

    fn try_from(value: kms_grpc::kms::v1::KmsContext) -> anyhow::Result<Self> {
        let software_version = bc2wrap::deserialize(&value.software_version)?;
        Ok(ContextInfo {
            kms_nodes: value
                .kms_nodes
                .into_iter()
                .map(NodeInfo::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            context_id: RequestId::from(
                value
                    .context_id
                    .ok_or_else(|| anyhow::anyhow!("Missing context_id"))?,
            ),
            previous_context_id: value.previous_context_id.map(RequestId::from),
            software_version,
            threshold: value.threshold as u32,
        })
    }
}

impl TryFrom<ContextInfo> for kms_grpc::kms::v1::KmsContext {
    type Error = anyhow::Error;

    fn try_from(value: ContextInfo) -> anyhow::Result<Self> {
        Ok(kms_grpc::kms::v1::KmsContext {
            kms_nodes: value
                .kms_nodes
                .into_iter()
                .map(kms_grpc::kms::v1::KmsNode::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            context_id: Some(value.context_id.into()),
            previous_context_id: value.previous_context_id.map(|id| id.into()),
            software_version: bc2wrap::serialize(&value.software_version)?,
            threshold: value.threshold.try_into()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use kms_grpc::rpc_types::PrivDataType;
    use rand::rngs::OsRng;

    use crate::{
        cryptography::{
            internal_crypto_types::gen_sig_keys, signcryption::ephemeral_encryption_key_generation,
        },
        vault::storage::{ram::RamStorage, store_versioned_at_request_id, StorageType},
    };

    use super::*;

    #[test]
    fn test_software_version_display() {
        let version = SoftwareVersion {
            major: 1,
            minor: 2,
            patch: 3,
            tag: Some("alpha".to_string()),
        };
        assert_eq!(version.to_string(), "1.2.3-alpha");
    }

    #[test]
    fn test_software_version_no_tag() {
        let version = SoftwareVersion {
            major: 1,
            minor: 2,
            patch: 3,
            tag: None,
        };
        assert_eq!(version.to_string(), "1.2.3");
    }

    #[test]
    fn test_software_version_equality() {
        let version1 = SoftwareVersion {
            major: 1,
            minor: 2,
            patch: 3,
            tag: Some("alpha".to_string()),
        };
        let version2 = SoftwareVersion {
            major: 1,
            minor: 2,
            patch: 3,
            tag: Some("alpha".to_string()),
        };
        assert_eq!(version1, version2);
    }

    #[test]
    fn test_software_version_patch_comparison() {
        let version1 = SoftwareVersion {
            major: 1,
            minor: 2,
            patch: 3,
            tag: Some("alpha".to_string()),
        };
        let version2 = SoftwareVersion {
            major: 1,
            minor: 2,
            patch: 4,
            tag: Some("alpha".to_string()),
        };
        assert!(version2 > version1);
    }

    #[test]
    fn test_software_version_minor_comparison() {
        let version1 = SoftwareVersion {
            major: 1,
            minor: 2,
            patch: 3,
            tag: None,
        };
        let version2 = SoftwareVersion {
            major: 1,
            minor: 3,
            patch: 0,
            tag: None,
        };
        assert!(version2 > version1);
    }

    #[test]
    fn test_software_version_major_comparison() {
        let version1 = SoftwareVersion {
            major: 1,
            minor: 3,
            patch: 12,
            tag: None,
        };
        let version2 = SoftwareVersion {
            major: 2,
            minor: 0,
            patch: 0,
            tag: None,
        };
        assert!(version2 > version1);
    }

    #[test]
    fn test_software_version_unordered_tag() {
        let version1 = SoftwareVersion {
            major: 1,
            minor: 2,
            patch: 3,
            tag: Some("alpha".to_string()),
        };
        let version2 = SoftwareVersion {
            major: 1,
            minor: 2,
            patch: 3,
            tag: Some("beta".to_string()),
        };

        // This is a bit tricky, as the tag does not affect the ordering,
        // so they are considered equal in terms of versioning.
        // But the two versions are not equal so using the == operator
        // will return false.
        assert!(version2 <= version1);
        assert!(version2 >= version1);
        assert_ne!(version2, version1);
    }

    #[tokio::test]
    async fn test_context_info_duplicate_party_ids() {
        let (backup_encryption_public_key, _) = ephemeral_encryption_key_generation(&mut OsRng);
        let (verification_key, sk) = gen_sig_keys(&mut rand::rngs::OsRng);

        let context = ContextInfo {
            kms_nodes: vec![
                NodeInfo {
                    name: "Node1".to_string(),
                    party_id: 1,
                    verification_key: verification_key.clone(),
                    backup_encryption_public_key: backup_encryption_public_key.clone(),
                    external_url: "localhost:12345".to_string(),
                    tls_cert: vec![],
                    public_storage_url: "http://storage".to_string(),
                    extra_verification_keys: vec![],
                },
                NodeInfo {
                    name: "Node2".to_string(),
                    party_id: 1, // Duplicate party_id
                    verification_key,
                    backup_encryption_public_key,
                    external_url: "localhost:12345".to_string(),
                    tls_cert: vec![],
                    public_storage_url: "http://storage".to_string(),
                    extra_verification_keys: vec![],
                },
            ],
            context_id: RequestId::from_bytes([4u8; 32]),
            previous_context_id: None,
            software_version: SoftwareVersion {
                major: 1,
                minor: 0,
                patch: 0,
                tag: None,
            },
            threshold: 1,
        };

        let mut storage = RamStorage::new(StorageType::PRIV);
        store_versioned_at_request_id(
            &mut storage,
            &RequestId::from_bytes([1u8; 32]),
            &sk,
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();

        let result = context.verify(1, &storage, None).await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Duplicate party_ids found in context"));
    }

    // TODO more tests will be added here once the context definition is fully fleshed out
}
