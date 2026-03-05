use std::sync::Arc;

use anyhow::ensure;
use kms_grpc::rpc_types::PubDataType;
use threshold_fhe::networking::tls::AttestedVerifier;
use tokio_rustls::rustls::{
    client::{danger::DangerousClientConfigBuilder, ClientConfig},
    crypto::{aws_lc_rs::default_provider as aws_lc_rs_default_provider, CryptoProvider},
    pki_types::{CertificateDer, PrivateKeyDer},
    server::ServerConfig,
    sign::{CertifiedKey, SingleCertAndKey},
    version::TLS13,
};

use kms_grpc::RequestId;

use crate::{
    conf::threshold::{PeerConf, TlsConf},
    cryptography::{
        attestation::{AutoRefreshCertResolver, CertResolver, SecurityModuleProxy},
        signatures::PrivateSigKey,
    },
    vault::{
        keychain::RootKeyMeasurements,
        storage::{read_text_at_request_id, StorageReader},
    },
};

/// Communication between MPC parties can be optionally protected with mTLS
/// which requires a TLS certificate valid both for server and client
/// authentication.  We have to construct rustls config structs ourselves
/// instead of using the wrapper from tonic::transport because we need to
/// provide our own certificate verifier that can validate bundled attestation
/// documents and that can receive new trust roots on the context change.
#[allow(clippy::too_many_arguments)]
pub async fn build_tls_config<PubS: StorageReader + Send + Sync>(
    peers: &Option<Vec<PeerConf>>,
    tls_config: &TlsConf,
    security_module: Option<Arc<SecurityModuleProxy>>,
    private_vault_root_key_measurements: Option<Arc<RootKeyMeasurements>>,
    public_storage: &PubS,
    sk: Arc<PrivateSigKey>,
    signing_key_id: &RequestId,
    #[cfg(feature = "insecure")] mock_enclave: bool,
) -> anyhow::Result<(ServerConfig, ClientConfig, Arc<AttestedVerifier>)> {
    let verf_key = sk.verf_key();
    aws_lc_rs_default_provider()
        .install_default()
        .unwrap_or_else(|_| {
            panic!("Failed to load default crypto provider");
        });
    let crypto_provider = CryptoProvider::get_default()
        .ok_or_else(|| anyhow::anyhow!("rustls cryptoprovider not initialized"))?;
    // Communication between MPC parties can be optionally protected
    // with mTLS which requires a TLS certificate valid both for server
    // and client authentication.
    let my_peer = match peers {
        Some(peers) => {
            // Sanity check that the certificates are ok.
            let _cert_list = peers
                .iter()
                .map(|peer| {
                    peer.tls_cert
                        .as_ref()
                        .map(|cert| cert.into_pem_with_sanity_check(peer.party_id, peers))
                        .unwrap_or_else(|| {
                            panic!("No CA certificate present for peer {}", peer.party_id)
                        })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            peers
                .iter()
                .find(|p| p.verification_address == Some(verf_key.address()))
        }
        None => None,
    };

    let (cert_resolver, pcr8_expected, ignore_aws_ca_chain, attest_private_vault_root_key) =
        match tls_config {
            TlsConf::Manual { ref cert, ref key } => {
                tracing::info!(
                    "Using third-party TLS certificate without Nitro remote attestation"
                );
                let cert = match my_peer {
                    Some(peer) => cert.into_pem(peer)?,
                    None => {
                        tracing::info!(
                        "Cannot find a peer that corresponds to myself, skipping TLS certificate validation against peerlist"
                    );
                        cert.unchecked_pem()?
                    }
                };
                let key = key.into_pem()?;
                let cert_resolver = Arc::new(CertResolver::Single(SingleCertAndKey::from(
                    CertifiedKey::from_der(
                        vec![CertificateDer::from_slice(cert.contents.as_slice()).into_owned()],
                        PrivateKeyDer::try_from(key.contents.as_slice())
                            .map_err(|e| anyhow::anyhow!("{e}"))?
                            .clone_key(),
                        crypto_provider,
                    )?,
                )));
                (cert_resolver, false, false, false)
            }

            // When remote attestation is used, the enclave generates a
            // self-signed TLS certificate for a private key that never
            // leaves its memory. This certificate includes the AWS
            // Nitro attestation document and the certificate used
            // by the MPC party to sign the enclave image it is
            // running. The private key is not supplied, since it needs
            // to be generated inside an AWS Nitro enclave.
            TlsConf::Auto {
                ref eif_signing_cert,
                trusted_releases: _,
                ref ignore_aws_ca_chain,
                ref attest_private_vault_root_key,
                ref renew_slack_after_expiration,
                ref renew_fail_retry_timeout,
            } => {
                let security_module = security_module
                    .as_ref()
                    .unwrap_or_else(|| panic!("TLS identity and security module not present"));
                let (sk, ca_cert) = match eif_signing_cert {
                    Some(eif_signing_cert) => {
                        tracing::info!(
                            "Using wrapped TLS certificate with Nitro remote attestation"
                        );
                        (
                            None,
                            match my_peer {
                                Some(peer) => eif_signing_cert.into_pem(peer)?,
                                None => {
                                    tracing::info!(
                                    "No peerlist present, skipping TLS certificate validation against peerlist"
                                );
                                    eif_signing_cert.unchecked_pem()?
                                }
                            },
                        )
                    }
                    None => {
                        tracing::info!(
                        "Using TLS certificate with Nitro remote attestation signed by onboard CA"
                    );
                        let ca_cert_bytes = read_text_at_request_id(
                            public_storage,
                            signing_key_id,
                            &PubDataType::CACert.to_string(),
                        )
                        .await?;
                        let ca_cert = x509_parser::pem::parse_x509_pem(ca_cert_bytes.as_bytes())?.1;

                        // check if the CA certificate matches the KMS signing key
                        let ca_cert_x509 = ca_cert.parse_x509()?;
                        if let x509_parser::public_key::PublicKey::EC(pk_sec1) =
                            ca_cert_x509.public_key().parsed()?
                        {
                            let ca_pk = Box::new(pk_sec1.data());
                            #[allow(deprecated)]
                            let sk_vk = sk.sk().verifying_key().to_encoded_point(false).to_bytes();
                            ensure!(
                    **ca_pk == *sk_vk,
                    "CA certificate public key {:?} doesn't correspond to the KMS verifying key {:?}",
                    hex::encode(*ca_pk),
                    hex::encode(sk_vk)
                            );
                        } else {
                            panic!("CA certificate public key isn't ECDSA");
                        };
                        (Some(sk), ca_cert)
                    }
                };

                let attest_private_vault_root_key_flag =
                    attest_private_vault_root_key.is_some_and(|m| m);

                let cert_resolver = Arc::new(CertResolver::AutoRefresh(
                    AutoRefreshCertResolver::new(
                        sk,
                        ca_cert,
                        security_module.clone(),
                        if attest_private_vault_root_key_flag {
                            private_vault_root_key_measurements
                        } else {
                            None
                        },
                        renew_slack_after_expiration.unwrap_or(5),
                        renew_fail_retry_timeout.unwrap_or(60),
                    )
                    .await?,
                ));

                (
                    cert_resolver,
                    eif_signing_cert.is_some(),
                    ignore_aws_ca_chain.is_some_and(|m| m),
                    attest_private_vault_root_key_flag,
                )
            }
        };

    let verifier = Arc::new(AttestedVerifier::new(
        if attest_private_vault_root_key {
            Some(Arc::new(
                crate::vault::keychain::verify_root_key_measurements,
            ))
        } else {
            None
        },
        pcr8_expected,
        #[cfg(feature = "insecure")]
        mock_enclave,
        ignore_aws_ca_chain,
    )?);

    // We do not need to add context to verifier here
    // because it'll be added using [ensure_default_threshold_context_in_storage].

    let server_config = ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_client_cert_verifier(verifier.clone())
        .with_cert_resolver(cert_resolver.clone());
    let client_config = DangerousClientConfigBuilder {
        cfg: ClientConfig::builder_with_protocol_versions(&[&TLS13]),
    }
    .with_custom_certificate_verifier(verifier.clone())
    .with_client_cert_resolver(cert_resolver.clone());
    Ok((server_config, client_config, verifier))
}
