use super::SecurityModule;
use anyhow::{bail, ensure};
use aws_nitro_enclaves_nsm_api::api::{Request as NSMRequest, Response as NSMResponse};
use aws_nitro_enclaves_nsm_api::driver as nsm_driver;
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use x509_parser::pem::{parse_x509_pem, Pem};

const ATTESTATION_NONCE_SIZE: usize = 8;

#[derive(Clone)]
pub struct Nitro {
    nsm_fd: Arc<Mutex<i32>>,
}

impl Nitro {
    pub fn new() -> anyhow::Result<Self> {
        let nsm_fd = nsm_driver::nsm_init();
        ensure!(nsm_fd != -1, "NSM device unavailable");
        Ok(Nitro {
            nsm_fd: Arc::new(Mutex::new(nsm_fd)),
        })
    }
}

#[tonic::async_trait]
impl SecurityModule for Nitro {
    /// Request the attestation document from the Nitro security module. Attestation
    /// documents are used in AWS KMS requests to receive responses where the
    /// sensitive data that can only be shared with enclaves running an approved
    /// software version is encrypted under the attested enclave public key.
    async fn attest_pk_bytes(&self, pk: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        // generate a nonce to include into the attestation document
        let attestation_nonce = self.get_random(ATTESTATION_NONCE_SIZE).await?;

        // request Nitro enclave attestation
        let nsm_request = NSMRequest::Attestation {
            public_key: Some(pk.into()),
            user_data: None,
            // The nonce can potentially be used in protocols that do not allow using the same
            // attestation twice. The AWS KMS API allows reusing attestations (in fact, there
            // does not seem to be a way to forbid it).
            nonce: Some(attestation_nonce.into()),
        };
        let guarded_nsm_fd = self.nsm_fd.lock().await;
        let NSMResponse::Attestation { document } =
            nsm_driver::nsm_process_request(*guarded_nsm_fd, nsm_request)
        else {
            bail!("Nitro enclave attestation request failed");
        };
        Ok(document)
    }

    /// Request random bytes from the Nitro security module. Only used for generating initialization
    /// vectors in symmetric encryption and attestation document nonces at the moment.
    async fn get_random(&self, num_bytes: usize) -> anyhow::Result<Vec<u8>> {
        let nsm_request = NSMRequest::GetRandom;
        let guarded_nsm_fd = self.nsm_fd.lock().await;
        let NSMResponse::GetRandom { random } =
            nsm_driver::nsm_process_request(*guarded_nsm_fd, nsm_request)
        else {
            bail!("Nitro enclave entropy generation request failed");
        };
        ensure!(
            random.len() >= 256,
            "NSM returned less than 256 bytes of entropy"
        );
        ensure!(
            num_bytes <= random.len(),
            "More bytes of entropy requested than generated"
        );
        Ok(random[0..num_bytes].to_vec())
    }

    async fn wrap_x509_cert(&self, cert_pem: Pem) -> anyhow::Result<(Pem, Pem)> {
        let cert = cert_pem.parse_x509()?;
        let subject = threshold_fhe::networking::tls::extract_subject_from_cert(&cert)?;

        let mut cp = CertificateParams::new(vec![subject.clone()])?;

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

        if !(key_usage_val.digital_signature()
            && key_usage_val.key_encipherment()
            && key_usage_val.key_agreement()
            && ext_key_usage_val.server_auth
            && ext_key_usage_val.client_auth)
        {
            bail!("Bad certificate: not allowed to be used for TLS");
        };

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
        let attestation_document = self.attest_pk_bytes(keypair.public_key_der()).await?;

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
}
