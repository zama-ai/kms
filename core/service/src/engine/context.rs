//! This module provides the context definition that
//! can be constructed from the protobuf types and stored in the vault.
use alloy_primitives::Address;
use kms_grpc::identifiers::ContextId;
use serde::{Deserialize, Serialize};
use tfhe::{Versionize, named::Named};
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};
use threshold_networking::tls::ReleasePCRValues;
use threshold_types::role::Role;

use crate::{
    cryptography::signatures::PublicSigKey,
    engine::validation::{RequestIdParsingErr, parse_optional_grpc_request_id},
    impl_generic_versionize,
    vault::storage::{StorageReader, crypto_material::get_core_signing_key},
};

const ERR_DUPLICATE_PARTY_IDS: &str = "Duplicate party_ids found in context";
const ERR_DUPLICATE_NAMES: &str = "Duplicate names found in context";
const ERR_INVALID_THRESHOLD_SINGLE_NODE: &str = "Invalid threshold for centralized context";
const ERR_INVALID_THRESHOLD_MULTI_NODE: &str = "Invalid threshold for threshold context";

#[derive(Clone, Debug, VersionsDispatch)]
pub enum SoftwareVersionVersions {
    V0(SoftwareVersion),
}

/// Represents the software version of the KMS.
/// The ordering is based on the major, minor, and patch versions,
/// the tag does not affect the ordering.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(SoftwareVersionVersions)]
pub struct SoftwareVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub tag: Option<String>,
}

impl SoftwareVersion {
    pub fn current() -> anyhow::Result<Self> {
        let version = env!("CARGO_PKG_VERSION");
        Self::new(version)
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
    pub fn new(semantic_str: &str) -> anyhow::Result<Self> {
        let parsed_str = semantic_str.trim().to_ascii_lowercase();
        // Remove any leading "v." if present (e.g., "v.1.2.3")
        let parsed_str = parsed_str.strip_prefix("v.").unwrap_or(&parsed_str);
        // Remove any leading "v" if present, since some versions might be prefixed with "v" (e.g., "v1.2.3")
        let parsed_str = parsed_str.strip_prefix("v").unwrap_or(parsed_str);
        let parts: Vec<&str> = parsed_str.split('-').collect();
        let tag = if parts.len() > 1 {
            // Only care about the first '-' since the tag can also contain '-' characters, e.g., "1.2.3-alpha-1"
            Some(parts[1..].join("-"))
        } else {
            None
        };
        let version_parts = parts[0].split('.').collect::<Vec<&str>>();
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
        Ok(SoftwareVersion {
            major,
            minor,
            patch,
            tag,
        })
    }
}

/// Ethereum address identifying the verification key of a node operator.
///
/// This newtype exists solely to implement [`tfhe_versionable::Versionize`] for
/// [`alloy_primitives::Address`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerAddress(pub Address);
impl_generic_versionize!(SignerAddress);

#[derive(Clone, Debug, PartialEq, Eq, VersionsDispatch)]
pub enum NodeInfoVersions {
    V0(NodeInfoV0),
    V1(NodeInfo),
}

/// Legacy [`NodeInfo`] layout, kept for backward compatibility.
///
/// Persisted contexts stored the operator's full `PublicSigKey` instead of its Ethereum address.
/// Upgraded to the current [`NodeInfo`] by deriving the address from each key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Version)]
pub struct NodeInfoV0 {
    pub mpc_identity: String,
    pub party_id: u32,
    pub verification_key: Option<PublicSigKey>,
    pub external_url: String,
    pub ca_cert: Option<Vec<u8>>,
    pub public_storage_url: String,
    pub public_storage_prefix: Option<String>,
    pub extra_verification_keys: Vec<PublicSigKey>,
}

impl Upgrade<NodeInfo> for NodeInfoV0 {
    type Error = std::convert::Infallible;

    fn upgrade(self) -> Result<NodeInfo, Self::Error> {
        Ok(NodeInfo {
            mpc_identity: self.mpc_identity,
            party_id: self.party_id,
            signer_address: self.verification_key.map(|k| SignerAddress(k.address())),
            external_url: self.external_url,
            ca_cert: self.ca_cert,
            public_storage_url: self.public_storage_url,
            public_storage_prefix: self.public_storage_prefix,
            extra_signer_addresses: self
                .extra_verification_keys
                .into_iter()
                .map(|k| SignerAddress(k.address()))
                .collect(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Versionize, Serialize, Deserialize)]
#[versionize(NodeInfoVersions)]
pub struct NodeInfo {
    pub mpc_identity: String,
    pub party_id: u32,

    /// Ethereum address of the node operator's signing key, used to identify the node.
    ///
    /// This is optional for legacy reasons because typically MPC parties
    /// do not know the signing keys of other parties when it first starts.
    pub signer_address: Option<SignerAddress>,

    /// Must be a valid URL.
    pub external_url: String,

    /// The TLS certificate is a String here
    /// because we cannot versionize the X509Certificate type.
    ///
    /// Also it's optional because we need to support non-TLS connections for testing purposes.
    pub ca_cert: Option<Vec<u8>>,

    pub public_storage_url: String,
    pub public_storage_prefix: Option<String>,

    /// Ethereum addresses of additional signing keys permitted to make transactions on behalf of
    /// this node.
    pub extra_signer_addresses: Vec<SignerAddress>,
}

/// Parses a 20-byte Ethereum address carried in a gRPC `MpcNode` address field.
///
/// `field_label` identifies which field the `bytes` came from, for error reporting
/// (ex: "signer address").
fn parse_signer_address(
    bytes: &[u8],
    mpc_identity: &str,
    field_label: &str,
) -> anyhow::Result<SignerAddress> {
    let addr = Address::try_from(bytes)
        .map_err(|e| anyhow::anyhow!("Invalid {field_label} for node {mpc_identity}: {e}",))?;
    Ok(SignerAddress(addr))
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
        let mut extra_signer_addresses = Vec::new();
        for k in &value.extra_signer_addresses {
            extra_signer_addresses.push(parse_signer_address(
                k,
                &value.mpc_identity,
                "extra signer address",
            )?);
        }
        let signer_address = match &value.signer_address {
            None => None,
            Some(addr_bytes) => Some(parse_signer_address(
                addr_bytes,
                &value.mpc_identity,
                "signer address",
            )?),
        };
        Ok(NodeInfo {
            mpc_identity: value.mpc_identity,
            party_id: value.party_id.try_into()?,
            signer_address,
            external_url: value.external_url,
            ca_cert,
            public_storage_url: value.public_storage_url,
            public_storage_prefix: value.public_storage_prefix,
            extra_signer_addresses,
        })
    }
}

impl TryFrom<NodeInfo> for kms_grpc::kms::v1::MpcNode {
    type Error = anyhow::Error;
    fn try_from(value: NodeInfo) -> anyhow::Result<Self> {
        Ok(kms_grpc::kms::v1::MpcNode {
            mpc_identity: value.mpc_identity,
            party_id: value.party_id.try_into()?,
            signer_address: value.signer_address.map(|addr| addr.0.to_vec()),
            external_url: value.external_url,
            ca_cert: value.ca_cert,
            public_storage_url: value.public_storage_url,
            public_storage_prefix: value.public_storage_prefix,
            extra_signer_addresses: value
                .extra_signer_addresses
                .into_iter()
                .map(|addr| addr.0.to_vec())
                .collect(),
        })
    }
}

impl Named for NodeInfo {
    const NAME: &'static str = "kms::NodeInfo";
}

#[derive(VersionsDispatch, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextInfoVersions {
    V0(ContextInfo),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(ContextInfoVersions)]
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
        let core_address = SignerAddress(signing_key.verf_key().address());

        let my_node = self
            .mpc_nodes
            .iter()
            .find(|node| node.signer_address == Some(core_address));
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
        let software_version = SoftwareVersion::new(&value.software_version)?;
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
        Ok(kms_grpc::kms::v1::MpcContext {
            mpc_nodes: value
                .mpc_nodes
                .into_iter()
                .map(kms_grpc::kms::v1::MpcNode::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            context_id: Some(value.context_id.into()),
            software_version: value.software_version.to_string(),
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
            mpc_nodes: vec![
                NodeInfo {
                    mpc_identity: "Node1".to_string(),
                    party_id: 1,
                    signer_address: Some(SignerAddress(verification_key.address())),
                    external_url: "localhost:12345".to_string(),
                    ca_cert: None,
                    public_storage_url: "http://storage".to_string(),
                    public_storage_prefix: None,
                    extra_signer_addresses: vec![],
                },
                NodeInfo {
                    mpc_identity: "Node2".to_string(),
                    party_id: 1, // Duplicate party_id
                    signer_address: Some(SignerAddress(verification_key.address())),
                    external_url: "localhost:12345".to_string(),
                    ca_cert: None,
                    public_storage_url: "http://storage".to_string(),
                    public_storage_prefix: None,
                    extra_signer_addresses: vec![],
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
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains(ERR_DUPLICATE_PARTY_IDS)
        );
    }

    #[test]
    fn parse_software_semantic_version() {
        {
            let version = SoftwareVersion::new("1.2.3-alpha").unwrap();
            assert_eq!(version.major, 1);
            assert_eq!(version.minor, 2);
            assert_eq!(version.patch, 3);
            assert_eq!(version.tag, Some("alpha".to_string()));
        }
        // Ensure everything is trimmed and lower case
        {
            let version = SoftwareVersion::new(" 1.2.3-ALPHA ").unwrap();
            assert_eq!(version.major, 1);
            assert_eq!(version.minor, 2);
            assert_eq!(version.patch, 3);
            assert_eq!(version.tag, Some("alpha".to_string()));
        }
        {
            let version = SoftwareVersion::new(" 1.2.3-ALPHA ").unwrap();
            assert_eq!(version.major, 1);
            assert_eq!(version.minor, 2);
            assert_eq!(version.patch, 3);
            assert_eq!(version.tag, Some("alpha".to_string()));
        }
        // Version prefix is ignored
        {
            let version = SoftwareVersion::new("v1.2.3-alpha").unwrap();
            assert_eq!(version.major, 1);
            assert_eq!(version.minor, 2);
            assert_eq!(version.patch, 3);
            assert_eq!(version.tag, Some("alpha".to_string()));
        }
        {
            let version = SoftwareVersion::new("v.1.2.3-alpha").unwrap();
            assert_eq!(version.major, 1);
            assert_eq!(version.minor, 2);
            assert_eq!(version.patch, 3);
            assert_eq!(version.tag, Some("alpha".to_string()));
        }
        // Parsing double `-` in tag
        {
            let version = SoftwareVersion::new("1.2.3-alpha-beta").unwrap();
            assert_eq!(version.major, 1);
            assert_eq!(version.minor, 2);
            assert_eq!(version.patch, 3);
            assert_eq!(version.tag, Some("alpha-beta".to_string()));
        }
        // Non existing minor parts default to 0
        {
            let version = SoftwareVersion::new("1").unwrap();
            assert_eq!(version.major, 1);
            assert_eq!(version.minor, 0);
            assert_eq!(version.patch, 0);
            assert_eq!(version.tag, None);
        }
        {
            let version = SoftwareVersion::new("zzz");
            assert!(version.is_err());
        }
    }
    // TODO more tests will be added here once the context definition is fully fleshed out
}
