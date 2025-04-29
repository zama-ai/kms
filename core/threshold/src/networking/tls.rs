use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use std::{collections::HashMap, sync::Arc};
use tokio_rustls::rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        WebPkiClientVerifier,
    },
    DigitallySignedStruct, DistinguishedName, Error, RootCertStore, SignatureScheme,
};
use x509_parser::{
    certificate::X509Certificate,
    parse_x509_certificate,
    pem::{parse_x509_pem, Pem},
};

/// These three values, PCR0,1,2, describe a software release. We also check
/// PCR8 which is the hash of the certificate that signed a running enclave
/// image but its reference value comes from hashing the certificate bundled
/// within the mTLS certificate, not through configuration.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReleasePCRValues {
    // EIF hash
    #[serde(with = "hex::serde")]
    pub pcr0: Vec<u8>,
    // kernel+boot ramdisk hash
    #[serde(with = "hex::serde")]
    pub pcr1: Vec<u8>,
    // rootfs hash
    #[serde(with = "hex::serde")]
    pub pcr2: Vec<u8>,
}

/// Public key certificate, private key, allowed software hashes
pub type BasicTLSConfig = (Pem, Pem, Option<Arc<Vec<ReleasePCRValues>>>);

/// Public key certificate, private key, allowed software hashes, and
/// additionally a map from party subject names to party CAs. This map needs to
/// be built by `build_ca_certs_map` to have the keys equal to subject names by
/// construction.
pub type SendingServiceTLSConfig = (
    Pem,
    Pem,
    HashMap<String, Pem>,
    Option<Arc<Vec<ReleasePCRValues>>>,
);

/// Our custom verifier for our custom mTLS certificates extended with AWS Nitro
/// attestation documents. It doesn't reimplement normal X.509 certificate
/// verification and wraps around a well-tested verifier. In addition to the usual X.509 checks, it checks PCR values from the bundled attestation document.
#[derive(Debug)]
pub struct AttestedServerVerifier {
    verifier: Arc<dyn ServerCertVerifier>,
    release_pcrs: Arc<Vec<ReleasePCRValues>>,
}

impl AttestedServerVerifier {
    pub fn new(
        verifier: Arc<dyn ServerCertVerifier>,
        release_pcrs: Arc<Vec<ReleasePCRValues>>,
    ) -> Self {
        Self {
            verifier,
            release_pcrs,
        }
    }
}

/// Verifies our wrapped certificates that carry AWS Nitro attestation
/// documents.
impl ServerCertVerifier for AttestedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // check the enclave-generated certificate used for the TLS session as
        // usual (however, we expect it to be self-signed)
        self.verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        // check the bundled attestation document and EIF signing certificate
        let (_, cert) = parse_x509_certificate(end_entity.as_ref())
            .map_err(|e| Error::General(e.to_string()))?;
        validate_wrapped_cert(
            &cert,
            &self.release_pcrs,
            CertVerifier::Server(self.verifier.clone(), server_name, ocsp_response),
            intermediates,
            now,
        )
        .map_err(|e| Error::General(e.to_string()))?;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

#[derive(Debug)]
pub struct AttestedClientVerifier {
    root_hint_subjects: Vec<DistinguishedName>,
    supported_algs: WebPkiSupportedAlgorithms,
    verifiers: HashMap<String, Arc<dyn ClientCertVerifier>>,
    release_pcrs: Option<Arc<Vec<ReleasePCRValues>>>,
}

impl AttestedClientVerifier {
    pub fn new(
        ca_certs: HashMap<String, Pem>,
        release_pcrs: Option<Arc<Vec<ReleasePCRValues>>>,
    ) -> anyhow::Result<Self> {
        let verifiers = ca_certs
            .iter()
            .map(|(subject, ca_cert)| {
                let mut roots = RootCertStore::empty();
                roots
                    .add(CertificateDer::from_slice(&ca_cert.contents))
                    .map_err(|e| anyhow::anyhow!("{e}"))
                    .and_then(|_| {
                        WebPkiClientVerifier::builder(Arc::new(roots))
                            .build()
                            .map_err(|e| anyhow::anyhow!("{e}"))
                    })
                    .map(|verifier| (subject.clone(), verifier))
            })
            .collect::<anyhow::Result<HashMap<String, _>, _>>()?;
        let root_hint_subjects = verifiers
            .values()
            .flat_map(|v| v.root_hint_subjects())
            .cloned()
            .collect();
        // All verifiers use the same per-process crypto provider, so this
        // should never fail
        let supported_algs = CryptoProvider::get_default()
            .expect("Crypto provider should exist at this point")
            .signature_verification_algorithms;
        Ok(Self {
            root_hint_subjects,
            supported_algs,
            verifiers,
            release_pcrs,
        })
    }

    fn get_verifier_for_x509_cert(
        &self,
        cert: &X509Certificate<'_>,
    ) -> Result<Arc<dyn ClientCertVerifier>, Error> {
        let subject = extract_subject_from_cert(cert).map_err(|e| Error::General(e.to_string()))?;
        self.verifiers
            .get(subject.as_str())
            .ok_or(Error::General(format!("{subject} is not a trust anchor")))
            .cloned()
    }

    fn get_verifier_for_cert_der(
        &self,
        cert: &CertificateDer<'_>,
    ) -> Result<Arc<dyn ClientCertVerifier>, Error> {
        let (_, x509_cert) =
            parse_x509_certificate(cert.as_ref()).map_err(|e| Error::General(e.to_string()))?;
        self.get_verifier_for_x509_cert(&x509_cert)
    }
}

impl ClientCertVerifier for AttestedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.root_hint_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let (_, cert) = parse_x509_certificate(end_entity.as_ref())
            .map_err(|e| Error::General(e.to_string()))?;
        let verifier = self.get_verifier_for_x509_cert(&cert)?;

        // check the enclave-generated certificate used for the TLS session as
        // usual (however, we expect it to be self-signed)
        verifier.verify_client_cert(end_entity, intermediates, now)?;

        // check the bundled attestation document and EIF signing certificate
        if let Some(release_pcrs) = &self.release_pcrs {
            validate_wrapped_cert(
                &cert,
                release_pcrs,
                CertVerifier::Client(verifier.clone()),
                intermediates,
                now,
            )
            .map_err(|e| Error::General(e.to_string()))?;
        }

        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.get_verifier_for_cert_der(cert)?
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.get_verifier_for_cert_der(cert)?
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

pub enum CertVerifier<'a> {
    Client(Arc<dyn ClientCertVerifier>),
    Server(Arc<dyn ServerCertVerifier>, &'a ServerName<'a>, &'a [u8]),
}

pub enum CertVerified {
    Client(ClientCertVerified),
    Server(ServerCertVerified),
}

fn validate_wrapped_cert(
    cert: &X509Certificate,
    trusted_releases: &[ReleasePCRValues],
    verifier: CertVerifier,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
) -> anyhow::Result<()> {
    // Self-signed certificates need to include the party certificate so the
    // PCR8 value attestation can be verified
    let Some(party_cert_bytes) = cert
        .get_extension_unique(&oid_registry::OID_X509)
        .map_err(|e| anyhow!("{e}"))?
    else {
        bail!("Bad certificate: original party certificate not present")
    };

    // Self-signed certificates do not actually include AWS Nitro
    // attestation documents as a PKCS7 structure. We only reused
    // its OID because there is not one formally assigned to
    // COSE_Sign1 structures.
    let Some(attestation_doc) = cert
        .get_extension_unique(&oid_registry::OID_PKCS7_ID_SIGNED_DATA)
        .map_err(|e| anyhow!("{e}"))?
    else {
        bail!("Bad certificate: attestation document not present")
    };
    let attestation_doc =
        attestation_doc_validation::validate_and_parse_attestation_doc(attestation_doc.value)
            .map_err(|e| tonic::Status::new(tonic::Code::Aborted, e.to_string()))?;
    let Some(attested_pk) = attestation_doc.public_key else {
        bail!("Bad certificate: public key not present in attestation document")
    };
    if cert.public_key().raw != attested_pk.as_slice() {
        let mut cert_pk_hasher = Sha256::new();
        cert_pk_hasher.update(cert.public_key().raw);
        let cert_pk_hash = hex::encode(cert_pk_hasher.finalize().as_slice());
        let mut att_pk_hasher = Sha256::new();
        att_pk_hasher.update(attested_pk.as_slice());
        let att_pk_hash = hex::encode(att_pk_hasher.finalize().as_slice());
        bail!("Bad certificate: subject public key with hash {} does not match attestation document public key with hash {}", cert_pk_hash, att_pk_hash)
    };

    // check software release hashes
    let Some(pcr0) = attestation_doc.pcrs.get(&0) else {
        bail!("Bad certificate: PCR0 value not present in attestation document");
    };
    let Some(pcr1) = attestation_doc.pcrs.get(&1) else {
        bail!("Bad certificate: PCR1 value not present in attestation document");
    };
    let Some(pcr2) = attestation_doc.pcrs.get(&2) else {
        bail!("Bad certificate: PCR2 value not present in attestation document")
    };
    let Some(pcr8) = attestation_doc.pcrs.get(&8) else {
        bail!("Bad certificate: PCR8 value not present in attestation document")
    };
    if !trusted_releases.contains(&ReleasePCRValues {
        pcr0: pcr0.to_vec(),
        pcr1: pcr1.to_vec(),
        pcr2: pcr2.to_vec(),
    }) {
        bail!(
            "Bad certificate: untrusted release hash triple {}, {}, {} in attestation document",
            hex::encode(pcr0),
            hex::encode(pcr1),
            hex::encode(pcr2)
        )
    };
    // check party certificate validity
    match verifier {
        CertVerifier::Client(v) => CertVerified::Client(v.verify_client_cert(
            &CertificateDer::from_slice(party_cert_bytes.value),
            intermediates,
            now,
        )?),
        CertVerifier::Server(v, server_name, ocsp_response) => {
            CertVerified::Server(v.verify_server_cert(
                &CertificateDer::from_slice(party_cert_bytes.value),
                intermediates,
                server_name,
                ocsp_response,
                now,
            )?)
        }
    };
    // Check party certificate hash against the attested value. Note that the
    // Nitro attestation document format uses SHA2-384 only (not SHA3).
    let mut hasher = Sha384::new();
    hasher.update(party_cert_bytes.value);
    let party_cert_hash = hasher.finalize();
    if party_cert_hash.as_slice() != pcr8.as_slice() {
        bail!("Bad certificate: untrusted party certificate hash {} in attestation document, expected {}", hex::encode(party_cert_hash.as_slice()), hex::encode(pcr8.as_slice()))
    }
    Ok(())
}

/// Extract the party name from the certificate.
///
/// Each party should have its own self-signed certificate.
/// Each self-signed certificate is loaded into the trust store of all the parties.
pub fn extract_subject_from_cert(cert: &X509Certificate) -> anyhow::Result<String> {
    let Some(sans) = cert
        .subject_alternative_name()
        .map_err(|e| anyhow!("{e}"))?
    else {
        bail!("SAN not specified");
    };
    let san_strings: Vec<_> = sans
        .value
        .general_names
        .iter()
        .filter_map(|san| match san {
            x509_parser::extensions::GeneralName::DNSName(s) => Some(*s),
            _ => None,
        })
        .collect();

    if san_strings.is_empty() {
        bail!("No valid SAN found");
    }

    // find the subject and issuer CN, check there's a matching name in SAN list
    let Some(subject) = cert.subject().iter_common_name().next() else {
        bail!("Bad certificate: missing subject");
    };
    let subject_str = subject.as_str().map_err(|e| anyhow!("{e}"))?;

    let Some(issuer) = cert.issuer().iter_common_name().next() else {
        bail!("Bad certificate: missing issuer");
    };
    let issuer_str = issuer.as_str().map_err(|e| anyhow!("{e}"))?;

    if subject_str != issuer_str {
        bail!("Bad certificate: subject CN does not match issuer CN");
    }

    if !san_strings.contains(&subject_str) {
        bail!("Bad certificate: subject CN not found in SAN");
    }

    Ok(subject_str.to_string())
}

pub fn build_ca_certs_map<I: Iterator<Item = anyhow::Result<String>>>(
    cert_bytes: I,
) -> anyhow::Result<HashMap<String, Pem>> {
    cert_bytes
        .map(|cert_bytes| {
            cert_bytes.and_then(|c| {
                parse_x509_pem(c.as_ref())
                    .map(|(_, pem)| pem)
                    .map_err(|e| anyhow::anyhow!("Could not parse PEM envelope: {e}"))
            })
        })
        .map(|cert_pem| {
            cert_pem.and_then(|c| {
                c.parse_x509()
                    .map_err(|e| anyhow::anyhow!("Could not parse X509 structure: {e}"))
                    .and_then(|ref x509_cert| {
                        extract_subject_from_cert(x509_cert).map(|s| (s, c.clone()))
                    })
            })
        })
        .collect::<Result<HashMap<String, Pem>, _>>()
}
