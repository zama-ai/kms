use super::signatures::PrivateSigKey;
use crate::vault::keychain::RootKeyMeasurements;
use anyhow::{bail, ensure};
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
use threshold_fhe::networking::tls::extract_subject_from_cert;
use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;
use x509_parser::pem::{parse_x509_pem, Pem};

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

    /// Generate a fresh keypair and issue a self-signed TLS certificate for it
    /// that bundles the provided certificate and the attestation document
    /// containing the provided certificate public key hash. This self-signed
    /// certificate can be used for establishing TLS connections where both
    /// sides can not only verify each other's identities but also software
    /// versions.
    async fn wrap_x509_cert(&self, cert_pem: Pem, wildcard: bool) -> anyhow::Result<(Pem, Pem)> {
        let cert = cert_pem.parse_x509()?;

        // The subject name and at least one distinguished name should be set to
        // the party DNS address, as specified in the peer list. Parties connect
        // to each other using DNS addresses in the peer list, and TLS
        // connections would fail if certificates aren't issued for these DNS
        // addresses.
        let subject = extract_subject_from_cert(&cert)?;

        let sans_vec = [
            if wildcard {
                vec![format!("*.{}", subject.clone())]
            } else {
                vec![]
            },
            vec![subject.clone()],
        ]
        .concat();

        let mut cp = CertificateParams::new(sans_vec)?;

        cp.is_ca = IsCa::ExplicitNoCa;

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, subject);
        cp.distinguished_name = distinguished_name;

        // Key usages
        let Some(key_usage) = cert.key_usage()? else {
            bail!("Bad certificate: key usage not specified");
        };
        let Some(ext_key_usage) = cert.extended_key_usage()? else {
            bail!("Bad certificate: key usage not specified");
        };
        let key_usage_val = key_usage.value;
        let ext_key_usage_val = ext_key_usage.value;

        ensure!(
            key_usage_val.digital_signature()
                && key_usage_val.key_encipherment()
                && key_usage_val.key_agreement()
                && ext_key_usage_val.server_auth
                && ext_key_usage_val.client_auth,
            "Bad certificate: not allowed to be used for TLS"
        );

        cp.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
            KeyUsagePurpose::KeyAgreement,
        ];

        cp.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];

        // Enclave-terminated TLS sessions will use this keypair, not the one in
        // `cert`.
        let keypair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let attestation_document = self.attest(keypair.subject_public_key_info(), None).await?;

        cp.custom_extensions = vec![
            // This custom extension is meant to carry an AWS Nitro attestation
            // document stored as a CBOR-encoded COSE_Sign1 object which has no
            // assigned OID. We reuse the OID assigned to PKCS7_SIGNED_DATA here
            // because it's close enough spiritually. It's not nice but we can't
            // do better for now.
            CustomExtension::from_oid_content(&[1, 2, 840, 113549, 1, 7, 2], attestation_document),
            // The AWS Nitro attestation document has a PCR8 value computed by
            // hashing the EIF signing certificate. To verify that value, that
            // certificate needs to be distributed with the attestation
            // document.
            CustomExtension::from_oid_content(&[2, 5, 4], cert_pem.contents),
        ];

        let wrapped_cert = cp.self_signed(&keypair)?;
        Ok((
            parse_x509_pem(wrapped_cert.pem().as_ref())?.1,
            parse_x509_pem(keypair.serialize_pem().as_ref())?.1,
        ))
    }

    /// Generate a fresh keypair and issue a new TLS certificate for it signed
    /// it with the party EIP712 signing key. This TLS certificate also includes
    /// the attestation document for its associated private key.
    ///
    /// The difference between `issue_wrap_cert()` and `wrap_x509_cert()` lies
    /// in where the party identity comes from. `wrap_x509_cert()` relies on the
    /// enclave image being signed with the externally managed party certificate
    /// before the enclave starts, whereas `issue_x509_cert()` signs TLS
    /// certificates with the party EIP712 signing keys managed in the enclave.
    async fn issue_x509_cert(
        &self,
        ca_cert_pem: &Pem,
        ca_key: &PrivateSigKey,
        wildcard: bool,
        private_vault_root_key_measurements: Option<&RootKeyMeasurements>,
    ) -> anyhow::Result<(Pem, Pem)> {
        let ca_cert_x509 = ca_cert_pem.parse_x509()?;
        let Some(key_usage) = ca_cert_x509.key_usage()? else {
            bail!("Bad CA certificate: key usage not specified");
        };
        ensure!(
            key_usage.value.key_cert_sign(),
            "Bad CA certificate: cannot be used to sign other certificates"
        );

        let private_vault_root_key_measurements_bytes = match private_vault_root_key_measurements {
            Some(private_vault_root_key_measurements) => {
                // user data section in the AWS Nitro attestation document
                // should not exceed 1024 bytes
                let mut private_vault_root_key_measurements_bytes = Vec::with_capacity(1024);
                ciborium::into_writer(
                    private_vault_root_key_measurements,
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

        #[allow(deprecated)]
        let sk_der = ca_key.sk().to_pkcs8_der()?;
        let ca_keypair = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(sk_der.as_bytes()),
            &PKCS_ECDSA_P256K1_SHA256,
        )?;
        let ca_cert_params =
            CertificateParams::from_ca_cert_der(&ca_cert_pem.contents.as_slice().into())?;

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

        tls_cp.custom_extensions = vec![
            // This custom extension is meant to carry an AWS Nitro attestation
            // document stored as a CBOR-encoded COSE_Sign1 object which has no
            // assigned OID. We reuse the OID assigned to PKCS7_SIGNED_DATA here
            // because it's close enough spiritually. It's not nice but we can't
            // do better for now.
            CustomExtension::from_oid_content(&[1, 2, 840, 113549, 1, 7, 2], attestation_document),
        ];

        let tls_cert = tls_cp.signed_by(&tls_keypair, &ca_cert_params, &ca_keypair)?;

        Ok((
            parse_x509_pem(tls_cert.pem().as_ref())?.1,
            parse_x509_pem(tls_keypair.serialize_pem().as_ref())?.1,
        ))
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
