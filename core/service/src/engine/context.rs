//! This module provides the context definition that
//! can be constructed from the protobuf types and stored in the vault.

use std::collections::BTreeSet;

use kms_grpc::identifiers::ContextId;
use serde::{Deserialize, Serialize};
use tfhe::{named::Named, Versionize};
use tfhe_versionable::VersionsDispatch;
use threshold_fhe::{execution::runtime::party::Role, networking::tls::ReleasePCRValues};

use crate::{
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::{internal_crypto_types::LegacySerialization, signatures::PublicSigKey},
    engine::validation::{parse_optional_grpc_request_id, RequestIdParsingErr},
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
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub tag: Option<String>,
    pub digests: BTreeSet<Vec<u8>>,
}

impl SoftwareVersion {
    pub fn current() -> anyhow::Result<Self> {
        let version = env!("CARGO_PKG_VERSION");
        Self::new_from_semantic_version(version, BTreeSet::new())
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

impl SoftwareVersion {
    /// Use a semantic version string like "1.2.3-alpha" to create a SoftwareVersion
    pub fn new_from_semantic_version(
        semantic_str: &str,
        digests: BTreeSet<Vec<u8>>,
    ) -> anyhow::Result<Self> {
        let parts: Vec<&str> = semantic_str.split('-').collect();
        let version_parts: Vec<&str> = parts[0].split('.').collect();
        let major = match version_parts.first() {
            Some(v) => v.parse()?,
            None => anyhow::bail!("Invalid semantic version string: missing major version"),
        };
        let minor = match version_parts.get(1) {
            Some(v) => v.parse()?,
            None => 0,
        };
        let patch = match version_parts.get(2) {
            Some(p) => p.parse()?,
            None => 0,
        };
        // .and_then(|v| v.parse()?).unwrap_or(0);
        let tag = if parts.len() > 1 {
            Some(parts[1].to_string())
        } else {
            None
        };
        Ok(SoftwareVersion {
            major,
            minor,
            patch,
            tag,
            digests,
        })
    }

    /// Use a JSON string like: {"semantic_version": "1.2.3-alpha", digests: ["ABF2872DF3", "9393789A"]} to create a SoftwareVersion
    /// That is, the JSON must have a "semantic_version" field and a "digests" field which is a list of hex encoded digests.
    pub fn new_from_json(software_version_json: &str) -> anyhow::Result<Self> {
        if software_version_json.len() > SAFE_SER_SIZE_LIMIT as usize {
            return Err(anyhow::anyhow!(
                "Software version string exceeds safe size limit of {} bytes",
                SAFE_SER_SIZE_LIMIT
            ));
        }
        let json_version: JsonSoftwareVersion = serde_json::from_str(software_version_json)
            .map_err(|e| {
                anyhow::anyhow!("Deserialization of software version from JSON failed: {e}")
            })?;
        let digests = json_version
            .digests
            .into_iter()
            .map(|d| {
                hex::decode(d.trim().to_ascii_lowercase())
                    .map_err(|e| anyhow::anyhow!("Hex decoding failed: {e}"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let semantic_version = SoftwareVersion::new_from_semantic_version(
            json_version.semantic_version.as_str(),
            digests,
        )?;
        Ok(semantic_version)
    }

    /// Convert the SoftwareVersion to a JSON string. The JSON will have a "semantic_version" field and a "digests" field which is a list of hex encoded digests.
    pub fn to_json(&self) -> anyhow::Result<String> {
        let json_version = JsonSoftwareVersion {
            semantic_version: self.to_string(),
            digests: self
                .digests
                .iter()
                .map(hex::encode)
                .collect::<BTreeSet<_>>(),
        };
        let res = serde_json::to_string(&json_version).map_err(|e| {
            anyhow::anyhow!("Serialization of software version to JSON failed: {e}")
        })?;
        if res.len() > SAFE_SER_SIZE_LIMIT as usize {
            return Err(anyhow::anyhow!(
                "Software version string exceeds safe size limit of {} bytes",
                SAFE_SER_SIZE_LIMIT
            ));
        }
        Ok(res)
    }
}

/// Helper struct for deserializing the JSON representation of SoftwareVersion
#[derive(Serialize, Deserialize)]
struct JsonSoftwareVersion {
    semantic_version: String,
    digests: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, VersionsDispatch)]
pub enum NodeInfoVersioned {
    V0(NodeInfo),
}

#[derive(Clone, Debug, PartialEq, Eq, Versionize, Serialize, Deserialize)]
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
    pub public_storage_prefix: Option<String>,
    pub extra_verification_keys: Vec<PublicSigKey>,
}

impl TryFrom<kms_grpc::kms::v1::MpcNode> for NodeInfo {
    type Error = anyhow::Error;

    fn try_from(value: kms_grpc::kms::v1::MpcNode) -> anyhow::Result<Self> {
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
        let mut extra_verification_keys = Vec::new();
        for k in &value.extra_verification_keys {
            let pk = PublicSigKey::from_legacy_bytes(k)?;
            extra_verification_keys.push(pk);
        }
        Ok(NodeInfo {
            mpc_identity: value.mpc_identity,
            party_id: value.party_id.try_into()?,
            verification_key: match value.verification_key {
                None => None,
                Some(vk_bytes) => Some(PublicSigKey::from_legacy_bytes(&vk_bytes)?),
            },
            external_url: value.external_url,
            ca_cert,
            public_storage_url: value.public_storage_url,
            public_storage_prefix: value.public_storage_prefix,
            extra_verification_keys,
        })
    }
}

impl TryFrom<NodeInfo> for kms_grpc::kms::v1::MpcNode {
    type Error = anyhow::Error;
    fn try_from(value: NodeInfo) -> anyhow::Result<Self> {
        // Observe that legacy formats have never been used here, so it is safe to use safe_serialize
        Ok(kms_grpc::kms::v1::MpcNode {
            mpc_identity: value.mpc_identity,
            party_id: value.party_id.try_into()?,
            verification_key: match value.verification_key {
                Some(inner) => Some(inner.to_legacy_bytes()?),
                None => None,
            },
            external_url: value.external_url,
            ca_cert: value.ca_cert,
            public_storage_url: value.public_storage_url,
            public_storage_prefix: value.public_storage_prefix,
            extra_verification_keys: value
                .extra_verification_keys
                .into_iter()
                .map(|k| k.to_legacy_bytes())
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl Named for NodeInfo {
    const NAME: &'static str = "kms::NodeInfo";
}

#[derive(VersionsDispatch, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextInfoVersioned {
    V0(ContextInfo),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(ContextInfoVersioned)]
pub struct ContextInfo {
    pub mpc_nodes: Vec<NodeInfo>,
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
    pub async fn verify<S: StorageReader>(&self, storage: &S) -> anyhow::Result<Option<Role>> {
        // Check the signing key is consistent with the private key in storage.
        let signing_key = get_core_signing_key(storage).await?;
        let verification_key = signing_key.verf_key();

        let my_node = self.mpc_nodes.iter().find(|node| {
            node.verification_key
                .as_ref()
                .map(|inner| inner == &verification_key)
                .unwrap_or(false)
        });
        // check mpc_nodes have unique party_ids
        let party_ids: std::collections::HashSet<_> =
            self.mpc_nodes.iter().map(|node| node.party_id).collect();
        if party_ids.len() != self.mpc_nodes.len() {
            return Err(anyhow::anyhow!(
                "{} {}",
                ERR_DUPLICATE_PARTY_IDS,
                self.context_id()
            ));
        }

        // check that the party IDs are in the range [1, mpc_nodes.len()]
        for node in &self.mpc_nodes {
            (1..=self.mpc_nodes.len() as u32)
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

        if self.mpc_nodes.len() == 1 {
            // threshold must be 0 for single node context
            if self.threshold != 0 {
                return Err(anyhow::anyhow!(
                    "{} {}",
                    ERR_INVALID_THRESHOLD_SINGLE_NODE,
                    self.context_id()
                ));
            }
        } else {
            // check that threshold is valid such that 3*threshold + 1 == mpc_nodes.len()
            if self.mpc_nodes.len() != 3 * self.threshold as usize + 1 {
                return Err(anyhow::anyhow!(
                    "{} (context={}, threshold={}, nodes={})",
                    ERR_INVALID_THRESHOLD_MULTI_NODE,
                    self.context_id(),
                    self.threshold,
                    self.mpc_nodes.len()
                ));
            }
        }

        // the mpc_nodes must have unique names
        let names: std::collections::HashSet<_> = self
            .mpc_nodes
            .iter()
            .map(|node| node.mpc_identity.clone())
            .collect();
        if names.len() != self.mpc_nodes.len() {
            return Err(anyhow::anyhow!(
                "{} {}",
                ERR_DUPLICATE_NAMES,
                self.context_id()
            ));
        }

        // check that the urls are valid
        for node in &self.mpc_nodes {
            let mpc_url = url::Url::parse(&node.external_url)
                .map_err(|e| anyhow::anyhow!("url parsing failed {:?}", e))?;
            let _hostname = mpc_url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("missing host"))?;
            let _port = mpc_url
                .port()
                .ok_or_else(|| anyhow::anyhow!("missing port"))?;
        }

        Ok(my_node.map(|node| Role::indexed_from_one(node.party_id as usize)))
    }
}

impl Named for ContextInfo {
    const NAME: &'static str = "kms::ContextInfo";
}

impl TryFrom<kms_grpc::kms::v1::MpcContext> for ContextInfo {
    type Error = anyhow::Error;

    fn try_from(value: kms_grpc::kms::v1::MpcContext) -> anyhow::Result<Self> {
        let software_version = SoftwareVersion::new_from_json(&value.software_version)?;
        Ok(ContextInfo {
            mpc_nodes: value
                .mpc_nodes
                .into_iter()
                .map(NodeInfo::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            context_id: parse_optional_grpc_request_id(
                &value.context_id,
                RequestIdParsingErr::Context,
            )?,
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

impl TryFrom<ContextInfo> for kms_grpc::kms::v1::MpcContext {
    type Error = anyhow::Error;

    fn try_from(value: ContextInfo) -> anyhow::Result<Self> {
        let software_version = value.software_version.to_json()?;
        Ok(kms_grpc::kms::v1::MpcContext {
            mpc_nodes: value
                .mpc_nodes
                .into_iter()
                .map(kms_grpc::kms::v1::MpcNode::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            context_id: Some(value.context_id.into()),
            software_version,
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
            digests: BTreeSet::from(["11".as_bytes().to_vec(), "22".as_bytes().to_vec()]),
        };
        assert_eq!(version.to_string(), "1.2.3-alpha");
        assert_eq!(
            version.digests,
            // Order should not matter
            BTreeSet::from(["11".as_bytes().to_vec(), "22".as_bytes().to_vec()])
        );
    }

    #[test]
    fn test_software_version_no_tag() {
        let version = SoftwareVersion {
            major: 1,
            minor: 2,
            patch: 3,
            tag: None,
            digests: BTreeSet::new(),
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
            digests: BTreeSet::from(["11".as_bytes().to_vec(), "22".as_bytes().to_vec()]),
        };
        let version2 = SoftwareVersion {
            major: 1,
            minor: 2,
            patch: 3,
            tag: Some("alpha".to_string()),
            digests: BTreeSet::from(["22".as_bytes().to_vec(), "11".as_bytes().to_vec()]),
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
            digests: BTreeSet::from(["33".as_bytes().to_vec()]),
        };
        let version2 = SoftwareVersion {
            major: 1,
            minor: 2,
            patch: 4,
            tag: Some("alpha".to_string()),
            // Digests does not affect comparison
            digests: BTreeSet::from(["11".as_bytes().to_vec(), "22".as_bytes().to_vec()]),
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
            digests: BTreeSet::new(),
        };
        let version2 = SoftwareVersion {
            major: 1,
            minor: 3,
            patch: 0,
            tag: None,
            digests: BTreeSet::new(),
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
            digests: BTreeSet::new(),
        };
        let version2 = SoftwareVersion {
            major: 2,
            minor: 0,
            patch: 0,
            tag: None,
            digests: BTreeSet::new(),
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
            digests: BTreeSet::new(),
        };
        let version2 = SoftwareVersion {
            major: 1,
            minor: 2,
            patch: 3,
            tag: Some("beta".to_string()),
            digests: BTreeSet::new(),
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
            mpc_nodes: vec![
                NodeInfo {
                    mpc_identity: "Node1".to_string(),
                    party_id: 1,
                    verification_key: Some(verification_key.clone()),
                    external_url: "localhost:12345".to_string(),
                    ca_cert: None,
                    public_storage_url: "http://storage".to_string(),
                    public_storage_prefix: None,
                    extra_verification_keys: vec![],
                },
                NodeInfo {
                    mpc_identity: "Node2".to_string(),
                    party_id: 1, // Duplicate party_id
                    verification_key: Some(verification_key),
                    external_url: "localhost:12345".to_string(),
                    ca_cert: None,
                    public_storage_url: "http://storage".to_string(),
                    public_storage_prefix: None,
                    extra_verification_keys: vec![],
                },
            ],
            context_id: ContextId::from_bytes([4u8; 32]),
            software_version: SoftwareVersion {
                major: 1,
                minor: 0,
                patch: 0,
                tag: None,
                digests: BTreeSet::new(),
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
    fn parse_software_semantic_version() {
        {
            let version =
                SoftwareVersion::new_from_semantic_version("1.2.3-alpha", BTreeSet::new()).unwrap();
            assert_eq!(version.major, 1);
            assert_eq!(version.minor, 2);
            assert_eq!(version.patch, 3);
            assert_eq!(version.tag, Some("alpha".to_string()));
        }
        {
            let version =
                SoftwareVersion::new_from_semantic_version("zzz", BTreeSet::new()).unwrap();
            assert_eq!(version.major, 0);
            assert_eq!(version.minor, 0);
            assert_eq!(version.patch, 0);
            assert_eq!(version.tag, None);
        }
    }

    #[test]
    fn parse_software_json_version() {
        {
            let version = SoftwareVersion::new_from_json(
                "{\"semantic_version\": \"1.2.3-alpha\", \"digests\": [\"ABF2872DF3\", \"9393789A\"]}",
            )
            .unwrap();
            assert_eq!(version.major, 1);
            assert_eq!(version.minor, 2);
            assert_eq!(version.patch, 3);
            assert_eq!(version.tag, Some("alpha".to_string()));
            assert!(version
                .digests
                .contains(&hex::decode("ABF2872DF3").unwrap()));
            assert!(version.digests.contains(&hex::decode("9393789A").unwrap()));
        }
        {
            let version: anyhow::Result<SoftwareVersion> = SoftwareVersion::new_from_json(
                "{\"semantic_version\": \"1.2.3-alpha\", \"digests\": [\"ABF2872DF3\", \"9393789A==\"]}",
            );
            assert!(version.is_err()); // Not hex digest
            let version: anyhow::Result<SoftwareVersion> = SoftwareVersion::new_from_json(
                "{\"semantic_version\": \"1.2.s3-alpha\", \"digests\": [\"ABF2872DF3\", \"9393789A\"]}",
            );
            assert!(version.is_err()); // Not not a patch number
            let version: anyhow::Result<SoftwareVersion> = SoftwareVersion::new_from_json(
                "{\"dsemantic_version\": \"1.2.s3-alpha\", \"digests\": [\"ABF2872DF3\", \"9393789A\"]}",
            );
            assert!(version.is_err()); // Spelling error in semantic version
        }
    }

    // TODO more tests will be added here once the context definition is fully fleshed out
}
