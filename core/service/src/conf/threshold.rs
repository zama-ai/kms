use crate::engine::{base::derive_request_id, threshold::service::prss_compat::parse_threshold};
use alloy_primitives::Address;
use kms_grpc::RequestId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use strum_macros::EnumIs;
use threshold_execution::endpoints::decryption::DecryptionMode;
use threshold_execution::online::preprocessing::redis::RedisConf;
use threshold_networking::{
    grpc::CoreToCoreNetworkConfig,
    tls::{ReleasePCRValues, extract_subject_from_cert},
};
use threshold_types::party::Identity;
use threshold_types::role::Role;
use validator::{Validate, ValidationError};
use x509_parser::pem::{Pem, parse_x509_pem};

/// WARNING: this may be printed for debugging and hence should NOT contain any secrets, such as private keys.
/// If minor secrets needs to be added, then ensure fields are annotated with `#[serde(skip_serializing)]` to avoid accidentally diclosing them.
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
    // TODO(zama-ai/kms-internal/issues/2853): remove this or make it optional
    pub threshold: u8,

    #[validate(range(min = 1))]
    pub my_id: Option<usize>,

    pub dec_capacity: usize,
    pub min_dec_cache: usize,
    pub preproc_redis: Option<RedisConf>,
    pub num_sessions_preproc: Option<u16>,
    // NOTE: eventually the peer list will be removed in favor of context
    #[validate(nested)]
    pub peers: Option<Vec<PeerConf>>,
    pub core_to_core_net: Option<CoreToCoreNetworkConfig>,
    pub decryption_mode: DecryptionMode,

    /// Issue#3089: temporary request-ID activation thresholds for the PRSS-Mask
    /// counter-schedule fix (#663). Requests whose raw request ID, interpreted as a
    /// big-endian integer, is strictly below the configured value run the legacy PRSS.
    /// Values are decimal or 0x-prefixed hex integers of up to 256 bits, given as
    /// strings. All MPC parties MUST configure identical values.
    /// OPTIONAL: defaults to "0" (always run the fixed schedule, since no request ID is
    /// strictly below 0) when absent. This lets a config written by an older chart — or a
    /// rolling upgrade that enables the threshold only *after* the new binary is running —
    /// parse cleanly, which is required because pre-#663 binaries reject the field entirely
    /// (`deny_unknown_fields`) and the config is read fresh at process start. Public and user
    /// decryption request IDs come from separate counters, hence one threshold each. Remove
    /// once the migration is complete.
    #[serde(default = "default_legacy_prss_mask_threshold")]
    pub legacy_prss_mask_before_public_decrypt_id: String,
    /// See [`Self::legacy_prss_mask_before_public_decrypt_id`].
    #[serde(default = "default_legacy_prss_mask_threshold")]
    pub legacy_prss_mask_before_user_decrypt_id: String,
}

/// Default PRSS-Mask activation threshold ("0" = always use the fixed post-#663 schedule).
fn default_legacy_prss_mask_threshold() -> String {
    "0".to_string()
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
        if let Some(my_id) = conf.my_id
            && my_id > num_parties
        {
            tracing::warn!(
                "my_id {} is greater than number of parties {}, in some situations this may be a misconfiguration",
                my_id,
                num_parties
            );
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
    } else {
        tracing::info!("No peer list provided; skipping threshold and party ID validation");
    }

    // Issue#3089: fail at config load on malformed PRSS-Mask schedule activation thresholds.
    for (name, value) in [
        (
            "legacy_prss_mask_before_public_decrypt_id",
            &conf.legacy_prss_mask_before_public_decrypt_id,
        ),
        (
            "legacy_prss_mask_before_user_decrypt_id",
            &conf.legacy_prss_mask_before_user_decrypt_id,
        ),
    ] {
        if let Err(e) = parse_threshold(value) {
            return Err(
                ValidationError::new("Invalid PRSS-Mask schedule activation threshold")
                    .with_message(format!("{name}: {e}").into()),
            );
        }
    }
    Ok(())
}

/// WARNING: this may be printed for debugging and hence should NOT contain any secrets, such as private keys.
/// If minor secrets needs to be added, then ensure fields are annotated with `#[serde(skip_serializing)]` to avoid accidentally diclosing them.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, EnumIs)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum TlsConf {
    // Both public key certificate and private key are provided externally. If
    // enclaves are not used, this is the ony option.
    Manual {
        #[serde(skip_serializing, default)]
        cert: TlsCert,
        #[serde(skip_serializing, default)]
        key: TlsKey,
    },
    // The party will generate a keypair inside of the enclave on boot and issue
    // an ephemeral TLS certificate with a bundled attestation document. By
    // default, the party will use its core signing key to sign it, acting as
    // its own CA. The CA certificate must be self-signed with the core signing
    // key and included in the peer list.
    Auto {
        // If a certificate is provided, the enclave image must be signed with
        // the matching private key. This certificate will be used to establish
        // the party identity instead of the core signing key then, so it must
        // be included in the peer list.
        #[serde(skip_serializing, default)]
        eif_signing_cert: Option<TlsCert>,
        trusted_releases: Vec<ReleasePCRValues>,
        ignore_aws_ca_chain: Option<bool>,
        attest_private_vault_root_key: Option<bool>,
        renew_slack_after_expiration: Option<u64>,
        renew_fail_retry_timeout: Option<u64>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "lowercase")]
pub enum TlsCert {
    Path(PathBuf),
    Pem(String),
}

impl Default for TlsCert {
    fn default() -> Self {
        TlsCert::Pem("REDACTED".to_string())
    }
}

impl TlsCert {
    pub fn unchecked_cert_string(&self) -> anyhow::Result<String> {
        match self {
            TlsCert::Path(cert_path) => std::fs::read_to_string(cert_path).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to open TLS cert file {}: {}",
                    cert_path.display(),
                    e
                )
            }),
            TlsCert::Pem(cert_bytes) => Ok(cert_bytes.to_string()),
        }
    }

    /// Parses the certificate without any validation against peerlist.
    pub fn unchecked_pem(&self) -> anyhow::Result<Pem> {
        let cert_bytes = self.unchecked_cert_string()?;
        Ok(parse_x509_pem(cert_bytes.as_ref())?.1)
    }

    pub fn into_pem(&self, peer: &PeerConf) -> anyhow::Result<Pem> {
        let cert_pem = self.unchecked_pem()?;
        let x509_cert = cert_pem.parse_x509()?;
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

    pub fn into_pem_with_sanity_check(
        &self,
        my_id: usize,
        peers: &[PeerConf],
    ) -> anyhow::Result<Pem> {
        // sanity check: peerlist needs to have an entry for the
        // current party
        let peer = &peers
            .iter()
            .find(|peer| peer.party_id == my_id)
            .ok_or_else(|| {
                anyhow::anyhow!("Peer list {peers:?} does not have an entry for my id {my_id}")
            })?;
        self.into_pem(peer)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "lowercase")]
pub enum TlsKey {
    Path(PathBuf),
    Pem(String),
}

impl Default for TlsKey {
    fn default() -> Self {
        TlsKey::Pem("REDACTED".to_string())
    }
}

impl TlsKey {
    pub fn into_pem(&self) -> anyhow::Result<Pem> {
        let key_bytes = self.to_string()?;
        Ok(parse_x509_pem(key_bytes.as_ref())?.1)
    }

    pub fn into_request_id(&self) -> anyhow::Result<RequestId> {
        let key_bytes = self.to_string()?;
        derive_request_id(key_bytes.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to derive request ID from TLS key: {}", e))
    }

    fn to_string(&self) -> anyhow::Result<String> {
        match self {
            TlsKey::Path(key_path) => std::fs::read_to_string(key_path).map_err(|e| {
                anyhow::anyhow!("Failed to open TLS key file {}: {}", key_path.display(), e)
            }),
            TlsKey::Pem(key_bytes) => Ok(key_bytes.to_string()),
        }
    }
}

/// WARNING: this may be printed for debugging and hence should NOT contain any secrets, such as private keys.
/// If minor secrets needs to be added, then ensure fields are annotated with `#[serde(skip_serializing)]` to avoid accidentally diclosing them.
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
    pub verification_address: Option<Address>,
}

impl PeerConf {
    pub fn into_role_identity(&self) -> (Role, Identity) {
        (
            Role::indexed_from_one(self.party_id),
            Identity::new(self.address.clone(), self.port, self.mpc_identity.clone()),
        )
    }
}

#[test]
fn test_pem_serialization() {
    let tls_cert = "-----BEGIN CERTIFICATE-----
MIIB8zCCAZmgAwIBAgIURPn0etQqZ41UG1Q6WlXa9al6M7owCgYIKoZIzj0EAwIw
HTEbMBkGA1UEAwwSZGV2LWttcy1jb3JlLTEuY29tMCAXDTc1MDEwMTAwMDAwMFoY
DzQwOTYwMTAxMDAwMDAwWjAdMRswGQYDVQQDDBJkZXYta21zLWNvcmUtMS5jb20w
VjAQBgcqhkjOPQIBBgUrgQQACgNCAAQqtmWLJljQ8oxemhbeNvlW71Xxmg/FgTrG
z3KoIG6XAbnv2OqNrYnZRRK4ksQOiB7VIL2EUq+zmX9nizhfxXZMo4G3MIG0MG4G
A1UdEQRnMGWCFCouZGV2LWttcy1jb3JlLTEuY29tghJkZXYta21zLWNvcmUtMS5j
b22HBH8AAAGCCWxvY2FsaG9zdIcEwKgAAYcQAAAAAAAAAAAAAAAAAAAAAYcQAAAA
AAAAAAAAAAAAAAAAATAPBgNVHQ8BAf8EBQMDB4YAMB0GA1UdDgQWBBRxsm/KVbIt
6jODpZfF90u9faexGjASBgNVHRMBAf8ECDAGAQH/AgEAMAoGCCqGSM49BAMCA0gA
MEUCIEfh23uIR76K+tv+s5pi0uksEeleDonWm+tqStxeRFR5AiEAs4mw/Yi6aoDg
2XT+7AGP8EPTN4GHif+bdwU0TZDjPVQ=
-----END CERTIFICATE-----
";

    let tls_cert = TlsCert::Pem(tls_cert.to_string());
    let peers = vec![PeerConf {
        party_id: 1,
        address: "localhost".to_string(),
        mpc_identity: Some("dev-kms-core-1.com".to_string()),
        port: 1234,
        tls_cert: Some(tls_cert.clone()),
        verification_address: None,
    }];

    // `into_pem` will deserialize the string inside `tls_cert`
    let _ = tls_cert.into_pem_with_sanity_check(1, &peers).unwrap();
}

/// Issue#3089: `validate_threshold_party_conf` must reject malformed PRSS-Mask schedule activation thresholds at config
/// load. Complements the `parse_threshold` unit tests in `prss_compat` by covering the config-validation wiring (both
/// fields), including the empty-string case that a templating mishap could produce.
#[test]
fn rejects_malformed_legacy_prss_mask_threshold() {
    // Minimal conf with no peers (skips the peer/threshold checks), so only the PRSS-Mask
    // threshold validation runs.
    let conf_with = |public: &str, user: &str| ThresholdPartyConf {
        listen_address: "0.0.0.0".to_string(),
        listen_port: 5000,
        tls: None,
        threshold: 1,
        my_id: None,
        dec_capacity: 1,
        min_dec_cache: 1,
        preproc_redis: None,
        num_sessions_preproc: None,
        peers: None,
        core_to_core_net: None,
        decryption_mode: DecryptionMode::NoiseFloodSmall,
        legacy_prss_mask_before_public_decrypt_id: public.to_string(),
        legacy_prss_mask_before_user_decrypt_id: user.to_string(),
    };

    // Well-formed values (default "0", decimal, and 0x-hex) pass.
    assert!(validate_threshold_party_conf(&conf_with("0", "0")).is_ok());
    assert!(validate_threshold_party_conf(&conf_with("1234", "0x1f")).is_ok());

    // A malformed value in either field is rejected, and the error names the offending field.
    let err = validate_threshold_party_conf(&conf_with("nonsense", "0"))
        .expect_err("a malformed public threshold must be rejected");
    assert!(
        err.message
            .as_ref()
            .is_some_and(|m| m.contains("legacy_prss_mask_before_public_decrypt_id")),
        "unexpected error: {err:?}"
    );
    let err = validate_threshold_party_conf(&conf_with("0", "0xzz"))
        .expect_err("a malformed user threshold must be rejected");
    assert!(
        err.message
            .as_ref()
            .is_some_and(|m| m.contains("legacy_prss_mask_before_user_decrypt_id")),
        "unexpected error: {err:?}"
    );

    // An empty string (e.g. from a templating mishap) fails loudly rather than defaulting to 0.
    assert!(validate_threshold_party_conf(&conf_with("", "0")).is_err());
}
