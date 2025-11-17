//! This module provides the context definition that
//! can be constructed from the protobuf types and stored in the vault.

use kms_grpc::identifiers::ContextId;
use serde::{Deserialize, Serialize};
use tfhe::{named::Named, Versionize};
use tfhe_versionable::VersionsDispatch;
use threshold_fhe::{execution::runtime::party::Role, networking::tls::ReleasePCRValues};

use crate::{
    cryptography::signatures::PublicSigKey,
    engine::validation::{parse_optional_proto_request_id, RequestIdParsingErr},
    vault::storage::{crypto_material::get_core_signing_key, StorageReader},
};

const ERR_DUPLICATE_PARTY_IDS: &str = "Duplicate party_ids found in context";
const ERR_DUPLICATE_NAMES: &str = "Duplicate names found in context";
const ERR_INVALID_THRESHOLD_SINGLE_NODE: &str = "Invalid threshold for centralized context";
const ERR_INVALID_THRESHOLD_MULTI_NODE: &str = "Invalid threshold for threshold context";

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

impl SoftwareVersion {
    pub fn current() -> Self {
        let version = env!("CARGO_PKG_VERSION");
        Self::from(version)
    }
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

impl From<&str> for SoftwareVersion {
    fn from(s: &str) -> Self {
        let parts: Vec<&str> = s.split('-').collect();
        let version_parts: Vec<&str> = parts[0].split('.').collect();
        let major = version_parts
            .first()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let minor = version_parts
            .get(1)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let patch = version_parts
            .get(2)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let tag = if parts.len() > 1 {
            Some(parts[1].to_string())
        } else {
            None
        };
        SoftwareVersion {
            major,
            minor,
            patch,
            tag,
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
    pub mpc_identity: String,
    pub party_id: u32,

    /// This is optional for legacy reasons because typically MPC parties
    /// do not know the public verification keys of other parties when it first starts.
    pub verification_key: Option<PublicSigKey>,

    /// Must be a valid URL.
    pub external_url: String,

    /// The TLS certificate is a String here
    /// because we cannot versionize the X509Certificate type.
    ///
    /// Also it's optional because we need to support non-TLS connections for testing purposes.
    pub ca_cert: Option<Vec<u8>>,

    pub public_storage_url: String,
    pub extra_verification_keys: Vec<PublicSigKey>,
}

impl TryFrom<kms_grpc::kms::v1::KmsNode> for NodeInfo {
    type Error = anyhow::Error;

    fn try_from(value: kms_grpc::kms::v1::KmsNode) -> anyhow::Result<Self> {
        // check the ca_cert is valid PEM if present
        let ca_cert = match &value.ca_cert {
            Some(cert_bytes) => {
                let _pem = x509_parser::pem::parse_x509_pem(cert_bytes)
                    .map_err(|e| anyhow::anyhow!("Invalid PEM in ca_cert: {}", e))?;
                Some(cert_bytes.clone())
            }
            None => None,
        };

        // check the external_url is a valid URL
        let _ = url::Url::parse(&value.external_url)?;

        Ok(NodeInfo {
            mpc_identity: value.mpc_identity,
            party_id: value.party_id.try_into()?,
            verification_key: match value.verification_key {
                None => None,
                Some(vk_bytes) => Some(bc2wrap::deserialize_safe(&vk_bytes)?),
            },
            external_url: value.external_url,
            ca_cert,
            public_storage_url: value.public_storage_url,
            extra_verification_keys: value
                .extra_verification_keys
                .into_iter()
                .map(|k| bc2wrap::deserialize_safe(&k))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl TryFrom<NodeInfo> for kms_grpc::kms::v1::KmsNode {
    type Error = anyhow::Error;
    fn try_from(value: NodeInfo) -> anyhow::Result<Self> {
        // Observe that legacy formats have never been used here, so it is safe to use safe_serialize
        Ok(kms_grpc::kms::v1::KmsNode {
            mpc_identity: value.mpc_identity,
            party_id: value.party_id.try_into()?,
            verification_key: match value.verification_key {
                Some(inner) => Some(bc2wrap::serialize(&inner)?),
                None => None,
            },
            external_url: value.external_url,
            ca_cert: value.ca_cert,
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
    pub context_id: ContextId,
    pub software_version: SoftwareVersion,
    pub threshold: u32,
    pub pcr_values: Vec<ReleasePCRValues>,
}

impl ContextInfo {
    pub fn context_id(&self) -> &ContextId {
        &self.context_id
    }

    /// Most of these checks are simply sanity checks because
    /// before the context passed to the KMS, it should have been validated on the gateway.
    pub async fn verify<S: StorageReader>(&self, storage: &S) -> anyhow::Result<Role> {
        // Check the signing key is consistent with the private key in storage.
        let signing_key = get_core_signing_key(storage).await?;
        let verification_key = signing_key.verf_key();

        let my_node = self
            .kms_nodes
            .iter()
            .find(|node| {
                node.verification_key
                    .as_ref()
                    .map(|inner| inner == &verification_key)
                    .unwrap_or(false)
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Node with verification key {:?} not found in context {}",
                    verification_key,
                    self.context_id()
                )
            })?;

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
            .map(|node| node.mpc_identity.clone())
            .collect();
        if names.len() != self.kms_nodes.len() {
            return Err(anyhow::anyhow!(
                "{} {}",
                ERR_DUPLICATE_NAMES,
                self.context_id()
            ));
        }

        // check that the urls are valid
        for node in &self.kms_nodes {
            let mpc_url = url::Url::parse(&node.external_url)
                .map_err(|e| anyhow::anyhow!("url parsing failed {:?}", e))?;
            let _hostname = mpc_url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("missing host"))?;
            let _port = mpc_url
                .port()
                .ok_or_else(|| anyhow::anyhow!("missing port"))?;
        }

        Ok(Role::indexed_from_one(my_node.party_id as usize))
    }
}

impl Named for ContextInfo {
    const NAME: &'static str = "kms::ContextInfo";
}

impl TryFrom<kms_grpc::kms::v1::KmsContext> for ContextInfo {
    type Error = anyhow::Error;

    fn try_from(value: kms_grpc::kms::v1::KmsContext) -> anyhow::Result<Self> {
        let software_version = bc2wrap::deserialize_safe(&value.software_version)?;
        Ok(ContextInfo {
            kms_nodes: value
                .kms_nodes
                .into_iter()
                .map(NodeInfo::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            context_id: parse_optional_proto_request_id(
                &value.context_id,
                RequestIdParsingErr::Context,
            )?
            .into(),
            software_version,
            threshold: value.threshold as u32,
            pcr_values: value
                .pcr_values
                .into_iter()
                .map(|v| ReleasePCRValues {
                    pcr0: v.pcr0,
                    pcr1: v.pcr1,
                    pcr2: v.pcr2,
                })
                .collect(),
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
            software_version: bc2wrap::serialize(&value.software_version)?,
            threshold: value.threshold.try_into()?,
            pcr_values: value
                .pcr_values
                .into_iter()
                .map(|v| kms_grpc::kms::v1::PcrValues {
                    pcr0: v.pcr0,
                    pcr1: v.pcr1,
                    pcr2: v.pcr2,
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use kms_grpc::rpc_types::PrivDataType;

    use crate::{
        cryptography::signatures::gen_sig_keys,
        vault::storage::{ram::RamStorage, store_versioned_at_request_id},
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
        let (verification_key, sk) = gen_sig_keys(&mut rand::rngs::OsRng);

        let context = ContextInfo {
            kms_nodes: vec![
                NodeInfo {
                    mpc_identity: "Node1".to_string(),
                    party_id: 1,
                    verification_key: Some(verification_key.clone()),
                    external_url: "localhost:12345".to_string(),
                    ca_cert: None,
                    public_storage_url: "http://storage".to_string(),
                    extra_verification_keys: vec![],
                },
                NodeInfo {
                    mpc_identity: "Node2".to_string(),
                    party_id: 1, // Duplicate party_id
                    verification_key: Some(verification_key),
                    external_url: "localhost:12345".to_string(),
                    ca_cert: None,
                    public_storage_url: "http://storage".to_string(),
                    extra_verification_keys: vec![],
                },
            ],
            context_id: ContextId::from_bytes([4u8; 32]),
            software_version: SoftwareVersion {
                major: 1,
                minor: 0,
                patch: 0,
                tag: None,
            },
            threshold: 1,
            pcr_values: vec![],
        };

        let mut storage = RamStorage::new();
        store_versioned_at_request_id(
            &mut storage,
            &ContextId::from_bytes([1u8; 32]).into(),
            &sk,
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();

        let result = context.verify(&storage).await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains(ERR_DUPLICATE_PARTY_IDS));
    }

    #[test]
    fn parse_software_version() {
        {
            let version = SoftwareVersion::from("1.2.3-alpha");
            assert_eq!(version.major, 1);
            assert_eq!(version.minor, 2);
            assert_eq!(version.patch, 3);
            assert_eq!(version.tag, Some("alpha".to_string()));
        }
        {
            let version = SoftwareVersion::from("zzz");
            assert_eq!(version.major, 0);
            assert_eq!(version.minor, 0);
            assert_eq!(version.patch, 0);
            assert_eq!(version.tag, None);
        }
    }

    // TODO more tests will be added here once the context definition is fully fleshed out
}
