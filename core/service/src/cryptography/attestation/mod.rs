use super::signatures::PrivateSigKey;
use crate::vault::keychain::RootKeyMeasurements;
use anyhow::{bail, ensure};
use attestation_doc_validation::attestation_doc::decode_attestation_document;
use enum_dispatch::enum_dispatch;
use k256::pkcs8::EncodePrivateKey;
#[cfg(feature = "insecure")]
use nsm_nitro_enclave_utils::{driver::dev::DevNitro, pcr::Pcrs};
#[cfg(feature = "insecure")]
use rcgen::{BasicConstraints, PKCS_ECDSA_P384_SHA384};
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PublicKeyData, PKCS_ECDSA_P256K1_SHA256, PKCS_ECDSA_P256_SHA256,
};
use std::{sync::Arc, time::Duration};
use threshold_fhe::networking::tls::extract_subject_from_cert;
use tokio::sync::RwLock;
use tokio_rustls::rustls::{
    client::ResolvesClientCert,
    crypto::CryptoProvider,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime},
    server::{ClientHello, ResolvesServerCert},
    sign::{CertifiedKey, SingleCertAndKey},
    SignatureScheme,
};
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage};
use x509_parser::{parse_x509_certificate, pem::Pem};

pub mod nitro;
#[cfg(feature = "insecure")]
pub mod nitro_mock;

#[allow(async_fn_in_trait)]
#[enum_dispatch]
pub trait SecurityModule {
    /// Get enthropy from the hardware RNG
    async fn get_random(&self, num_bytes: usize) -> anyhow::Result<Vec<u8>>;

    /// Request the attestation document signed by the security module that
    /// contains PCR values and, at the minimum, an application public
    /// key. Optionally, the attestation document can include some userdata and
    /// a nonce.
    async fn attest(&self, pk: Vec<u8>, user_data: Option<Vec<u8>>) -> anyhow::Result<Vec<u8>>;

    /// Generate a fresh keypair and issue a new TLS certificate for it.  This
    /// TLS certificate also includes the attestation document for its
    /// associated private key and the party software version (as PCR0,1,2
    /// values).
    ///
    /// If the party EIP712 signing key is provided, the TLS certificate is
    /// signed with it. If it's not provided, the party CA certificate is
    /// included in the TLS certificate, and the EIF image should be signed by
    /// the matching private key, so the attestation document can include the
    /// party CA certificate hash as the PCR8 value. The presence of the PCR8
    /// value will then allow the verifier to link the party identity to the
    /// attested TLS public key.
    async fn issue_x509_cert(
        &self,
        ca_cert_pem: &Pem,
        ca_key: Option<Arc<PrivateSigKey>>,
        wildcard: bool,
        private_vault_root_key_measurements: Option<Arc<RootKeyMeasurements>>,
    ) -> anyhow::Result<Arc<CertifiedKey>> {
        let ca_cert_x509 = ca_cert_pem.parse_x509()?;
        let Some(ca_cert_key_usage) = ca_cert_x509.key_usage()? else {
            bail!("Bad CA certificate: key usage not specified");
        };

        // The attestation document can optionally include a copy of the private
        // storage root key policy that the peers can mutually validate
        let private_vault_root_key_measurements_bytes = match private_vault_root_key_measurements {
            Some(private_vault_root_key_measurements) => {
                // user data section in the AWS Nitro attestation document
                // should not exceed 1024 bytes
                let mut private_vault_root_key_measurements_bytes = Vec::with_capacity(1024);
                ciborium::into_writer(
                    &private_vault_root_key_measurements,
                    &mut private_vault_root_key_measurements_bytes,
                )?;
                ensure!(private_vault_root_key_measurements_bytes.len() <= 1024, "Private vault root key measurements length too long for inclusion into attestation document, impossible to continue");
                Some(private_vault_root_key_measurements_bytes)
            }
            None => {
                tracing::info!(
                    "TLS certificate issued without private vault root key measurements"
                );
                None
            }
        };

        // TLS certificate

        // The subject name and at least one distinguished name should be set to
        // the party DNS address, as specified on the peer list. Parties connect
        // to each other using DNS addresses in the peer list, and TLS
        // connections would fail if certificates aren't issued for these DNS
        // addresses.
        let subject = extract_subject_from_cert(&ca_cert_x509)?;

        let sans_vec = [
            if wildcard {
                vec![format!("*.{}", subject.clone())]
            } else {
                vec![]
            },
            vec![subject.clone()],
        ]
        .concat();

        // Usage should permit mTLS
        let mut tls_cp = CertificateParams::new(sans_vec)?;
        tls_cp.is_ca = IsCa::ExplicitNoCa;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, subject);
        tls_cp.distinguished_name = distinguished_name;

        // Key usages
        tls_cp.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
            KeyUsagePurpose::KeyAgreement,
        ];

        tls_cp.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];

        // Enclave-terminated TLS sessions will use this keypair, not the one in
        // `cert`.
        let tls_keypair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let attestation_document = self
            .attest(
                tls_keypair.subject_public_key_info(),
                private_vault_root_key_measurements_bytes,
            )
            .await?;

        // TLS certificates shouldn't be valid longer than the attestation
        // document signing certificate.
        let (_, attestation_doc) = decode_attestation_document(attestation_document.as_slice())?;
        let (_, attestation_doc_signing_cert) =
            parse_x509_certificate(&attestation_doc.certificate)?;
        tls_cp.not_before = attestation_doc_signing_cert
            .validity
            .not_before
            .to_datetime();
        tls_cp.not_after = attestation_doc_signing_cert
            .validity
            .not_after
            .to_datetime();

        // This custom extension is meant to carry an AWS Nitro attestation
        // document stored as a CBOR-encoded COSE_Sign1 object which has no
        // assigned OID. We reuse the OID assigned to PKCS7_SIGNED_DATA here
        // because it's close enough spiritually. It's not nice but we can't
        // do better for now.
        tls_cp.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 2, 840, 113549, 1, 7, 2],
            attestation_document,
        )];

        // If the party signing key isn't used to issue certificates, we expect
        // that the EIF image is signed by some other key held by the party and
        // we include the certificate matching that key into the TLS certificate
        // to enable PCR8 validation
        if ca_key.is_none() {
            ensure!(
                ca_cert_key_usage.value.digital_signature(),
                "Bad party CA certificate: cannot be used to sign EIF images"
            );
            tls_cp
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[2, 5, 4],
                    ca_cert_pem.contents.clone(),
                ));
        }

        let tls_cert = match ca_key {
            Some(ca_key) => {
                // CA certificate
                ensure!(
                    ca_cert_key_usage.value.key_cert_sign(),
                    "Bad party CA certificate: cannot be used to sign other certificates"
                );

                #[allow(deprecated)]
                let sk_der = ca_key.sk().to_pkcs8_der()?;
                let ca_keypair = KeyPair::from_pkcs8_der_and_sign_algo(
                    &PrivatePkcs8KeyDer::from(sk_der.as_bytes()),
                    &PKCS_ECDSA_P256K1_SHA256,
                )?;
                let ca_cert_params =
                    CertificateParams::from_ca_cert_der(&ca_cert_pem.contents.as_slice().into())?;

                let tls_cert = tls_cp.signed_by(&tls_keypair, &ca_cert_params, &ca_keypair)?;
                // sanity check
                EndEntityCert::try_from(tls_cert.der())?.verify_for_usage(
                    &[webpki::aws_lc_rs::ECDSA_P256K1_SHA256],
                    &[anchor_from_trusted_cert(
                        &ca_cert_pem.contents.as_slice().into(),
                    )?],
                    &[],
                    UnixTime::now(),
                    KeyUsage::server_auth(),
                    None,
                    None,
                )?;
                tls_cert
            }
            // If the party signing key isn't used to sign TLS certificates, the
            // TLS certificate will technically be self-signed but the link to
            // the party identity would be still established through the PCR8
            // value
            None => tls_cp.self_signed(&tls_keypair)?,
        };

        let cert_chain = vec![tls_cert.der().clone()];
        let key_der =
            PrivateKeyDer::try_from(tls_keypair.serialize_der()).map_err(|e| anyhow::anyhow!(e))?;
        let crypto_provider = CryptoProvider::get_default()
            .ok_or_else(|| anyhow::anyhow!("rustls cryptoprovider not initialized"))?;
        Ok(Arc::new(CertifiedKey::from_der(
            cert_chain,
            key_der,
            crypto_provider,
        )?))
    }
}

#[allow(clippy::large_enum_variant)]
#[enum_dispatch(SecurityModule)]
pub enum SecurityModuleProxy {
    Nitro(nitro::Nitro),
    #[cfg(feature = "insecure")]
    MockNitro(DevNitro),
}

pub fn make_security_module(
    #[cfg(feature = "insecure")] mock_enclave: bool,
) -> anyhow::Result<SecurityModuleProxy> {
    #[cfg(not(feature = "insecure"))]
    let security_module = SecurityModuleProxy::from(nitro::Nitro::new()?);
    #[cfg(feature = "insecure")]
    let security_module = if mock_enclave {
        let sk = p384::SecretKey::from_sec1_der(&crate::consts::MOCK_NITRO_SIGNING_KEY_BYTES)
            .expect("Failed to load mock Nitro key");
        let sk_der = sk.to_pkcs8_der()?;
        let ca_keypair = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(sk_der.as_bytes()),
            &PKCS_ECDSA_P384_SHA384,
        )?;
        let mut ca_cp = CertificateParams::new(vec!["mock-nitro".to_string()])?;
        ca_cp.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_cp.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_cert = ca_cp.self_signed(&ca_keypair)?;
        SecurityModuleProxy::from(
            DevNitro::builder(sk, ca_cert.der().to_vec().into())
                .pcrs(Pcrs::zeros())
                .build(),
        )
    } else {
        SecurityModuleProxy::from(nitro::Nitro::new()?)
    };
    Ok(security_module)
}

pub struct AutoRefreshCertResolver {
    certified_key_with_expiration: Arc<RwLock<(Arc<CertifiedKey>, Duration)>>,
}

impl std::fmt::Debug for AutoRefreshCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("AutoRefreshCertResolver");
        f.finish()
    }
}

impl AutoRefreshCertResolver {
    pub async fn new(
        sk: Option<Arc<PrivateSigKey>>,
        ca_cert: Pem,
        security_module: Arc<SecurityModuleProxy>,
        private_vault_root_key_measurements: Option<Arc<RootKeyMeasurements>>,
        renew_slack_after_expiration: u64,
        renew_fail_retry_timeout: u64,
    ) -> anyhow::Result<Self> {
        let (certified_key, expiration) = AutoRefreshCertResolver::refresh(
            sk.clone(),
            ca_cert.clone(),
            security_module.clone(),
            private_vault_root_key_measurements.clone(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Could not issue initial TLS certificate: {e}"))?;
        tracing::info!(
            "Issued initial TLS certificate valid for {} s",
            expiration.as_secs()
        );
        let certified_key_with_expiration = Arc::new(RwLock::new((certified_key, expiration)));
        let resolver = Self {
            certified_key_with_expiration: certified_key_with_expiration.clone(),
        };

        // This task is expected to run forever as long at the node is running
        // because AWS Nitro signing certificates expire every 24h, and
        // ephemeral TLS certificates cannot outlive them. However, it's
        // possible that the renewal won't succeed for a multitude of reasons:
        //
        // 0) bug in our code
        // 1) bad party CA certificate
        // 2) NSM giving up on us for reasons only known to Amazon
        // and not signing a fresh attestation document
        //
        // There isn't a good way to automatically recover from any of these
        // scenarios (definitely not from 0 or 1), and the node is not going to
        // establish new peer connections if they happen because it won't have a
        // valid TLS certificate anymore. Manual intervention will be required.
        //
        // If TLS certificates would only be generated on the node boot, we
        // could just crash it in case of certificate generation failure, and we
        // used to do that. Now, we regenerate certificates on a running node,
        // and we can't simply crash it because it might already participate in
        // many MPC sessions. We should let them finish. Also, just in case if
        // the refresh failure is caused by a random NSM misbehaviour, we keep
        // retrying once a minute.
        //
        // Still, we cannot let nodes run without valid TLS certificates. There
        // has to be an alert if the certificate refresh failed more than 3
        // times in a row.
        tokio::spawn(async move {
            loop {
                match AutoRefreshCertResolver::refresh(
                    sk.clone(),
                    ca_cert.clone(),
                    security_module.clone(),
                    private_vault_root_key_measurements.clone(),
                )
                .await
                {
                    Ok((certified_key, expiration)) => {
                        tracing::info!(
                            "Issued renewed TLS certificate valid for {} s",
                            expiration.as_secs()
                        );

                        let mut guarded_certified_key_with_expiration =
                            certified_key_with_expiration.write().await;
                        guarded_certified_key_with_expiration.0 = certified_key.clone();
                        guarded_certified_key_with_expiration.1 = expiration;
                        drop(guarded_certified_key_with_expiration);

                        tokio::time::sleep(
                            expiration + Duration::from_secs(renew_slack_after_expiration),
                        )
                        .await;
                    }
                    Err(e) => {
                        tracing::error!("Could not renew ephemeral TLS certificate: {e}");
                        tokio::time::sleep(Duration::from_secs(renew_fail_retry_timeout)).await;
                    }
                }
            }
        });
        Ok(resolver)
    }

    async fn refresh(
        sk: Option<Arc<PrivateSigKey>>,
        ca_cert: Pem,
        security_module: Arc<SecurityModuleProxy>,
        private_vault_root_key_measurements: Option<Arc<RootKeyMeasurements>>,
    ) -> anyhow::Result<(Arc<CertifiedKey>, Duration)> {
        let certified_key = security_module
            .issue_x509_cert(
                &ca_cert,
                sk.clone(),
                true,
                private_vault_root_key_measurements.clone(),
            )
            .await?;
        let expiration = parse_x509_certificate(certified_key.end_entity_cert()?)?
            .1
            .validity
            .time_to_expiration()
            .map(|x| x.unsigned_abs())
            .ok_or_else(|| {
                anyhow::anyhow!("Ephemeral TLS certificate must have an expiration date")
            })?;
        Ok((certified_key, expiration))
    }
}

impl ResolvesServerCert for AutoRefreshCertResolver {
    // Since this trait method is not async, and we can't use `blocking_read()`
    // in it because its implementation will be called from an async context
    // that we don't implement ourselves, we have to resort to `try_read()`
    // which will lead to returning None if the read lock can't be obtained,
    // which will lead to TLS handshake failure, which will require a retry.
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.certified_key_with_expiration
            .try_read()
            .ok()
            .map(|k| k.0.clone())
    }
}

impl ResolvesClientCert for AutoRefreshCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.certified_key_with_expiration
            .try_read()
            .ok()
            .map(|k| k.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// I expected to be able to use `enum_dispatch` here but it doesn't work for
/// traits defined in external crates due to the Rust macro system limitations,
/// so I have to write boilerplate myself.
#[derive(Debug)]
pub enum CertResolver {
    Single(SingleCertAndKey),
    AutoRefresh(AutoRefreshCertResolver),
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match self {
            CertResolver::Single(s) => ResolvesServerCert::resolve(s, client_hello),
            CertResolver::AutoRefresh(ar) => ResolvesServerCert::resolve(ar, client_hello),
        }
    }
}

impl ResolvesClientCert for CertResolver {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        match self {
            CertResolver::Single(s) => {
                ResolvesClientCert::resolve(s, root_hint_subjects, sigschemes)
            }
            CertResolver::AutoRefresh(ar) => {
                ResolvesClientCert::resolve(ar, root_hint_subjects, sigschemes)
            }
        }
    }

    fn has_certs(&self) -> bool {
        match self {
            CertResolver::Single(s) => s.has_certs(),
            CertResolver::AutoRefresh(ar) => ar.has_certs(),
        }
    }
}
