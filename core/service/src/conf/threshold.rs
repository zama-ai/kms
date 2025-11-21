use crate::engine::base::derive_request_id;
use kms_grpc::RequestId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use strum_macros::EnumIs;
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::online::preprocessing::redis::RedisConf;
use threshold_fhe::execution::runtime::party::{Identity, Role};
use threshold_fhe::networking::{
    grpc::CoreToCoreNetworkConfig,
    tls::{extract_subject_from_cert, ReleasePCRValues},
};
use validator::{Validate, ValidationError};
use x509_parser::pem::{parse_x509_pem, Pem};

#[derive(Serialize, Deserialize, Validate, Clone, Debug)]
#[serde(deny_unknown_fields)]
#[validate(schema(function = validate_threshold_party_conf))]
pub struct ThresholdPartyConf {
    // network interface for MPC communication
    #[validate(length(min = 1))]
    pub listen_address: String,
    // port for MPC communication
    #[validate(range(min = 1, max = 65535))]
    pub listen_port: u16,
    // TLS identity if MPC communication should use TLS
    pub tls: Option<TlsConf>,

    #[validate(range(min = 1))]
    pub threshold: u8,
    #[validate(range(min = 1))]
    pub my_id: usize,
    pub dec_capacity: usize,
    pub min_dec_cache: usize,
    pub preproc_redis: Option<RedisConf>,
    pub num_sessions_preproc: Option<u16>,
    // NOTE: eventually the peer list will be removed in favor of context
    #[validate(nested)]
    pub peers: Option<Vec<PeerConf>>,
    pub core_to_core_net: Option<CoreToCoreNetworkConfig>,
    pub decryption_mode: DecryptionMode,
}

fn validate_threshold_party_conf(conf: &ThresholdPartyConf) -> Result<(), ValidationError> {
    if let Some(peers) = &conf.peers {
        let num_parties = peers.len();
        // We assume for now that 3 * threshold + 1 == num_parties.
        // Note: this might change in the future
        if 3 * conf.threshold as usize + 1 != num_parties {
            return Err(ValidationError::new("Incorrect threshold").with_message(format!("3*t+1 must be equal to number of parties. Got t={} but expected t={} for n={} parties", conf.threshold,                     (num_parties - 1) / 3,
                    num_parties
        ).into() ));
        }
        if conf.my_id > num_parties {
            return Err(ValidationError::new("Incorrect party ID").with_message(
                format!(
                    "Party ID cannot be greater than the number of parties ({}), but was {}.",
                    num_parties, conf.my_id
                )
                .into(),
            ));
        }
        for peer in peers {
            if peer.party_id > num_parties {
                return Err(
                ValidationError::new("Incorrect peer party ID").with_message(
                    format!(
                        "Peer party ID cannot be greater than the number of parties ({num_parties}).",
                    )
                    .into(),
                ),
            );
            }
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, EnumIs)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum TlsConf {
    // Both public key certificate and private key are provided externally. If
    // enclaves are not used, this is the ony option.
    Manual {
        cert: TlsCert,
        key: TlsKey,
    },
    // The party will generate a keypair inside of the enclave on boot and issue
    // an ephemeral self-signed TLS certificate for it that bundles the provided
    // certificate and the attestation document. The enclave image must be
    // signed with the provided certificate.
    SemiAuto {
        cert: TlsCert,
        trusted_releases: Vec<ReleasePCRValues>,
        ignore_aws_ca_chain: Option<bool>,
    },
    // The party will use its core signing key to sign an emphemeral TLS
    // certificate on boot that that bundles the attestation document, acting as
    // its own CA. The CA certificate must be self-signed with the core signing
    // key and included in the peer list.
    FullAuto {
        trusted_releases: Vec<ReleasePCRValues>,
        ignore_aws_ca_chain: Option<bool>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "lowercase")]
pub enum TlsCert {
    Path(PathBuf),
    Pem(String),
}

impl TlsCert {
    pub fn into_pem(&self, my_id: usize, peers: &[PeerConf]) -> anyhow::Result<Pem> {
        let cert_bytes = match self {
            TlsCert::Path(ref cert_path) => std::fs::read_to_string(cert_path).map_err(|e| {
                anyhow::anyhow!("Failed to open file {}: {}", cert_path.display(), e)
            })?,
            TlsCert::Pem(ref cert_bytes) => cert_bytes.to_string(),
        };
        let cert_pem = parse_x509_pem(cert_bytes.as_ref())?.1;
        let x509_cert = cert_pem.parse_x509()?;
        // sanity check: peerlist needs to have an entry for the
        // current party
        let peer = &peers
            .iter()
            .find(|peer| peer.party_id == my_id)
            .ok_or_else(|| {
                anyhow::anyhow!("Peer list {peers:?} does not have an entry for my id {my_id}")
            })?;
        let mpc_identity = peer
            .mpc_identity
            .as_ref()
            .unwrap_or(&peer.address)
            .to_string();

        let subject = extract_subject_from_cert(&x509_cert).map_err(|e| anyhow::anyhow!(e))?;
        anyhow::ensure!(
            subject == mpc_identity,
            "Certificate subject {subject} does not match mpc_identity {mpc_identity}"
        );
        Ok(cert_pem)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "lowercase")]
pub enum TlsKey {
    Path(PathBuf),
    Pem(String),
}

impl TlsKey {
    pub fn into_pem(&self) -> anyhow::Result<Pem> {
        let key_bytes = self.to_string()?;
        Ok(parse_x509_pem(key_bytes.as_ref())?.1)
    }

    pub fn into_request_id(&self) -> anyhow::Result<RequestId> {
        let key_bytes = self.to_string()?;
        derive_request_id(key_bytes.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to derive request ID from key: {}", e))
    }

    fn to_string(&self) -> anyhow::Result<String> {
        match self {
            TlsKey::Path(ref key_path) => std::fs::read_to_string(key_path)
                .map_err(|e| anyhow::anyhow!("Failed to open file {}: {}", key_path.display(), e)),
            TlsKey::Pem(ref key_bytes) => Ok(key_bytes.to_string()),
        }
    }
}

#[derive(Serialize, Deserialize, Validate, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PeerConf {
    #[validate(range(min = 1))]
    pub party_id: usize,
    #[validate(length(min = 1))]
    pub address: String,
    pub mpc_identity: Option<String>,
    #[validate(range(min = 1, max = 65535))]
    pub port: u16,
    pub tls_cert: Option<TlsCert>,
}

impl PeerConf {
    pub fn into_role_identity(&self) -> (Role, Identity) {
        (
            Role::indexed_from_one(self.party_id),
            Identity::new(self.address.clone(), self.port, self.mpc_identity.clone()),
        )
    }
}
