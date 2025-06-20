use super::internal_crypto_types::PrivateSigKey;
use anyhow::{bail, ensure};
use enum_dispatch::enum_dispatch;
use k256::pkcs8::EncodePrivateKey;
use kms_grpc::RequestId;
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PublicKeyData, SerialNumber, PKCS_ECDSA_P256K1_SHA256,
    PKCS_ECDSA_P256_SHA256,
};
use threshold_fhe::networking::tls::extract_subject_from_cert;
use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;
use x509_parser::pem::{parse_x509_pem, Pem};

pub mod nitro;

#[allow(async_fn_in_trait)]
#[enum_dispatch]
pub trait SecurityModule {
    /// Get enthropy from the hardware RNG
    async fn get_random(&self, num_bytes: usize) -> anyhow::Result<Vec<u8>>;

    /// Request the attestation document signed by the security module that
    /// contains PCR values and the provided byte string, usually, an
    /// application public key
    async fn attest_pk_bytes(&self, pk: Vec<u8>) -> anyhow::Result<Vec<u8>>;

    /// Generate a fresh keypair and issue a self-signed TLS certificate for it
    /// that bundles the provided certificate and the attestation document
    /// containing the provided certificate public key hash. This self-signed
    /// certificate can be used for establishing TLS connections where both
    /// sides can not only verify each other's identities but also software
    /// versions.
    async fn wrap_x509_cert(
        &self,
        context_id: RequestId,
        cert_pem: Pem,
    ) -> anyhow::Result<(Pem, Pem)> {
        let cert = cert_pem.parse_x509()?;

        // The subject name and at least one distinguished name should be set to
        // the party DNS address, as specified in the peer list. Parties connect
        // to each other using DNS addresses in the peer list, and TLS
        // connections would fail if certificates aren't issued for these DNS
        // addresses.
        let subject = extract_subject_from_cert(&cert)?;

        let mut cp = CertificateParams::new(vec![subject.clone()])?;

        cp.is_ca = IsCa::ExplicitNoCa;

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, subject);
        cp.distinguished_name = distinguished_name;
        cp.serial_number = Some(SerialNumber::from_slice(
            &context_id.derive_session_id()?.to_le_bytes(),
        ));

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
        let attestation_document = self.attest_pk_bytes(keypair.der_bytes().to_vec()).await?;

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
        context_id: RequestId,
        ca_cert_pem: Pem,
        ca_key: &PrivateSigKey,
    ) -> anyhow::Result<(Pem, Pem)> {
        let ca_cert_x509 = ca_cert_pem.parse_x509()?;
        let Some(key_usage) = ca_cert_x509.key_usage()? else {
            bail!("Bad CA certificate: key usage not specified");
        };
        ensure!(
            key_usage.value.key_cert_sign(),
            "Bad CA certificate: cannot be used to sign other certificates"
        );

        // The subject name and at least one distinguished name should be set to
        // the party DNS address, as specified on the peer list. Parties connect
        // to each other using DNS addresses in the peer list, and TLS
        // connections would fail if certificates aren't issued for these DNS
        // addresses.
        let subject = extract_subject_from_cert(&ca_cert_x509)?;

        let sk_der = ca_key.sk().to_pkcs8_der()?;
        let ca_keypair = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(sk_der.as_bytes()),
            &PKCS_ECDSA_P256K1_SHA256,
        )?;
        let ca_cert_params = CertificateParams::from_ca_cert_der(&ca_cert_pem.contents.into())?;

        let mut tls_cp = CertificateParams::new(vec![subject.clone()])?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, subject);
        tls_cp.distinguished_name = distinguished_name;
        tls_cp.serial_number = Some(SerialNumber::from_slice(
            &context_id.derive_session_id()?.to_le_bytes(),
        ));

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
            .attest_pk_bytes(tls_keypair.der_bytes().to_vec())
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

#[derive(Clone, Debug)]
#[enum_dispatch(SecurityModule)]
pub enum SecurityModuleProxy {
    Nitro(nitro::Nitro),
}

pub fn make_security_module() -> anyhow::Result<SecurityModuleProxy> {
    let security_module = nitro::Nitro::new()?;
    Ok(SecurityModuleProxy::from(security_module))
}
