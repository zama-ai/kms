use crate::session_id::SessionId;

use anyhow::{anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tokio_rustls::rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        WebPkiClientVerifier,
    },
    DigitallySignedStruct, DistinguishedName, Error, RootCertStore, SignatureScheme,
};
use x509_parser::{certificate::X509Certificate, parse_x509_certificate, pem::Pem};

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

#[derive(Debug)]
pub struct AttestedTLSContext {
    #[allow(dead_code)]
    root_hint_subjects: Vec<DistinguishedName>,
    verifiers: HashMap<String, (Arc<dyn ClientCertVerifier>, Arc<WebPkiServerVerifier>)>,
    // allowed software hashes
    release_pcrs: Option<Arc<Vec<ReleasePCRValues>>>,
}

impl AttestedTLSContext {
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
                    .map(|_| Arc::new(roots))
                    .and_then(|roots| {
                        WebPkiClientVerifier::builder(roots.clone())
                            .build()
                            .map_err(|e| anyhow::anyhow!("{e}"))
                            .map(|client_verifier| (roots, client_verifier))
                    })
                    .and_then(|(roots, client_verifier)| {
                        WebPkiServerVerifier::builder(roots)
                            .build()
                            .map_err(|e| anyhow::anyhow!("{e}"))
                            .map(|server_verifier| {
                                (subject.clone(), (client_verifier, server_verifier))
                            })
                    })
            })
            .collect::<anyhow::Result<HashMap<String, _>>>()?;
        let root_hint_subjects: Vec<_> = verifiers
            .values()
            .flat_map(|(client_verifier, _)| client_verifier.root_hint_subjects())
            .cloned()
            .collect();
        Ok(Self {
            root_hint_subjects,
            verifiers,
            release_pcrs,
        })
    }
}

/// Our custom verifier for our custom mTLS certificates extended with AWS Nitro
/// attestation documents. It doesn't reimplement normal X.509 certificate
/// verification and wraps around the well-tested
/// WebPki[Client|Server]Verifier. In addition to the usual X.509 checks, it
/// checks PCR values from the bundled attestation document. It also supports
/// multiple trust root sets configurable at runtime which is handy when working
/// with multiple MPC contexts.
///
/// The TLS certificates are expected to embed the context id in their serial
/// number. Depending on the context id and the certificate subject name, this
/// verifier will choose a verifier with just one appropriate CA certificate in
/// the trust root store to actually verify the certificate.
#[derive(Debug)]
pub struct AttestedVerifier {
    root_hint_subjects: Vec<DistinguishedName>,
    supported_algs: WebPkiSupportedAlgorithms,
    // SessionId is supposed to be based on RequestId, and we're representing
    // ContextId as RequestId so far, so let's say it's all the same for now
    contexts: RwLock<HashMap<SessionId, Arc<AttestedTLSContext>>>,
    // If the "semi-auto" TLS scheme is used, where the party TLS identity is
    // linked to some certificate issued and managed by some traditional PKI,
    // the enclave image should be signed by that certificate and the
    // certificate hash is stored in PCR8. Enabling this flag will compare the
    // PCR8 against the hash of the party certificate found in the peer
    // list. This flag is not used in the "full-auto" TLS scheme where the party
    // TLS identity is based on the decryption signing key, and no traditional
    // PKI is used.
    pcr8_expected: bool,
    #[cfg(feature = "testing")]
    mock_enclave: bool,
}

impl AttestedVerifier {
    pub fn new(
        pcr8_expected: bool,
        #[cfg(feature = "testing")] mock_enclave: bool,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            root_hint_subjects: Vec::new(),
            supported_algs: CryptoProvider::get_default()
                .ok_or(anyhow!(
                    "
Crypto provider should exist at this point"
                ))?
                .signature_verification_algorithms,
            contexts: RwLock::new(HashMap::new()),
            pcr8_expected,
            #[cfg(feature = "testing")]
            mock_enclave,
        })
    }

    pub fn add_context(
        &self,
        context_id: SessionId,
        ca_certs: HashMap<String, Pem>,
        release_pcrs: Option<Arc<Vec<ReleasePCRValues>>>,
    ) -> anyhow::Result<()> {
        let mut contexts = self
            .contexts
            .write()
            .map_err(|e| anyhow::anyhow!("Failed to acquire write lock: {e}"))?;
        ensure!(
            !contexts.contains_key(&context_id),
            "Context with ID {context_id} already exists"
        );
        let context = AttestedTLSContext::new(ca_certs, release_pcrs)
            .map_err(|e| anyhow::anyhow!("Failed to add new TLS context: {e}"))?;
        contexts.insert(context_id, Arc::new(context));
        Ok(())
    }

    pub fn remove_context(&self, context_id: SessionId) -> anyhow::Result<()> {
        let mut contexts = self
            .contexts
            .write()
            .map_err(|e| anyhow::anyhow!("Failed to acquire write lock: {e}"))?;
        contexts.remove(&context_id);
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn get_context_and_verifiers_for_x509_cert(
        &self,
        cert: &X509Certificate<'_>,
    ) -> Result<
        (
            Arc<AttestedTLSContext>,
            Arc<dyn ClientCertVerifier>,
            Arc<dyn ServerCertVerifier>,
        ),
        Error,
    > {
        let context_id =
            extract_context_id_from_cert(cert).map_err(|e| Error::General(e.to_string()))?;
        let subject = extract_subject_from_cert(cert).map_err(|e| Error::General(e.to_string()))?;
        tracing::debug!("Getting context and verifiers for {subject}");

        let contexts = self
            .contexts
            .read()
            .map_err(|e| Error::General(format!("Failed to acquire read lock: {e}")))?;
        let context = contexts
            .get(&context_id)
            .ok_or_else(|| Error::General(format!("Context {context_id} not found")))
            .inspect_err(|e| {
                tracing::error!("{e}");
            })?;
        let (client_verifier, server_verifier) = context
            .verifiers
            .get(subject.as_str())
            .ok_or(Error::General(format!("{subject} is not a trust anchor")))
            .cloned()
            .inspect_err(|e| {
                tracing::error!("{e}");
            })?;
        Ok((context.clone(), client_verifier, server_verifier))
    }

    #[allow(clippy::type_complexity)]
    fn get_context_and_verifiers_for_cert_der(
        &self,
        cert: &CertificateDer<'_>,
    ) -> Result<
        (
            Arc<AttestedTLSContext>,
            Arc<dyn ClientCertVerifier>,
            Arc<dyn ServerCertVerifier>,
        ),
        Error,
    > {
        let (_, x509_cert) =
            parse_x509_certificate(cert.as_ref()).map_err(|e| Error::General(e.to_string()))?;
        self.get_context_and_verifiers_for_x509_cert(&x509_cert)
    }
}

/// Verifies our wrapped certificates that carry AWS Nitro attestation
/// documents.
impl ServerCertVerifier for AttestedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let (_, cert) = parse_x509_certificate(end_entity.as_ref())
            .map_err(|e| Error::General(e.to_string()))?;
        let (context, _, server_verifier) = self.get_context_and_verifiers_for_x509_cert(&cert)?;
        // check the enclave-generated certificate used for the TLS session as
        // usual (however, we expect it to be self-signed)
        tracing::debug!("Verifying certificate for server {:?}", server_name,);
        server_verifier
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .inspect_err(|e| {
                tracing::error!("server verifier validation error: {e}");
            })?;
        // check the bundled attestation document and EIF signing certificate
        #[cfg(feature = "testing")]
        let do_validation = !&self.mock_enclave;
        #[cfg(not(feature = "testing"))]
        let do_validation = true;

        if do_validation {
            if let Some(release_pcrs) = &context.release_pcrs {
                validate_wrapped_cert(
                    &cert,
                    release_pcrs,
                    self.pcr8_expected,
                    CertVerifier::Server(server_verifier.clone(), server_name, ocsp_response),
                    intermediates,
                    now,
                )
                .map_err(|e| {
                    tracing::error!("bundled attestation document validation error: {e}");
                    Error::General(e.to_string())
                })?;
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.get_context_and_verifiers_for_cert_der(cert)?
            .2
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.get_context_and_verifiers_for_cert_der(cert)?
            .2
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

impl ClientCertVerifier for AttestedVerifier {
    // This method is used by the server to give acceptable CA names to the
    // client, so it can choose a client certificate that the server might
    // accept. We're sending an empty list here because this method has to
    // return a slice pointer, which isn't thread-safe when the list is
    // dynamically modified.
    //
    // A "good" behaviour would be sending all CA names from all contexts, but
    // that would require updating the CA list everytime a context is added or
    // removed, which would require locking. Returning a slice pointer would
    // require holding a read lock indefinitely though.
    //
    // It's not a big deal to return an empty list here because all MPC parties
    // are supposed to know which CA certificates are valid for each party in
    // every context anyway. We're not choosing client certificates based on
    // what this method returns in practice.
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
        // if none of the trust roots has a subject name matching the client
        // subject name, verification will fail
        let (context, client_verifier, _) = self.get_context_and_verifiers_for_x509_cert(&cert)?;

        // check the enclave-generated certificate used for the TLS session as
        // usual
        client_verifier
            .verify_client_cert(end_entity, intermediates, now)
            .inspect_err(|e| {
                tracing::error!("client verifier validation error: {e}");
            })?;

        // check the bundled attestation document and EIF signing certificate
        #[cfg(feature = "testing")]
        let do_validation = !&self.mock_enclave;
        #[cfg(not(feature = "testing"))]
        let do_validation = true;

        if do_validation {
            if let Some(release_pcrs) = &context.release_pcrs {
                validate_wrapped_cert(
                    &cert,
                    release_pcrs,
                    self.pcr8_expected,
                    CertVerifier::Client(client_verifier.clone()),
                    intermediates,
                    now,
                )
                .map_err(|e| {
                    tracing::error!("bundled attestation document validation error: {e}");
                    Error::General(e.to_string())
                })?;
            }
        }

        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.get_context_and_verifiers_for_cert_der(cert)?
            .1
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.get_context_and_verifiers_for_cert_der(cert)?
            .1
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
    pcr8_expected: bool,
    verifier: CertVerifier,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
) -> anyhow::Result<()> {
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
            .map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Aborted,
                    format!("AWS Nitro attestation failed: {e}"),
                )
            })?;
    let Some(attested_pk) = attestation_doc.public_key else {
        bail!("Bad certificate: public key not present in attestation document")
    };
    ensure!(*cert.public_key().raw == *attested_pk.as_slice(), "Bad certificate: subject public key info {} does not match attestation document public key info {}", hex::encode(cert.public_key().raw), hex::encode(attested_pk.as_slice()));

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
    // If enclave images are expected to be signed, we need to check the
    // attested PCR8 value against the bundled party certificate
    if pcr8_expected {
        let Some(pcr8) = attestation_doc.pcrs.get(&8) else {
            bail!("Bad certificate: PCR8 value not present in attestation document")
        };
        // Self-signed certificates need to include the party certificate so the
        // PCR8 value attestation can be verified
        let Some(party_cert_bytes) = cert
            .get_extension_unique(&oid_registry::OID_X509)
            .map_err(|e| anyhow!("{e}"))?
        else {
            bail!("Bad certificate: original party certificate not present")
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
        #[allow(deprecated)]
        if party_cert_hash.as_slice() != pcr8.as_slice() {
            bail!("Bad certificate: untrusted party certificate hash {} in attestation document, expected {}", hex::encode(party_cert_hash.as_slice()), hex::encode(pcr8.as_slice()))
        }
    }

    Ok(())
}

/// Extract the context ID from the certificate. All TLS certificates are signed
/// by the party CA certificate, so we can see context ID as the serial number
/// of the certificate.
pub fn extract_context_id_from_cert(cert: &X509Certificate) -> anyhow::Result<SessionId> {
    // Each TLS certificate is issued in a specific configuration context, we
    // use the context ID as the certificate serial number
    //
    // Note that `cert.serial` is a BigInt, so we need to convert it to
    // bytes and then convert it to u128. As such, it does not matter
    // what endianess we use for the conversion, as long as we are
    // consistent on both sides. Here we use big-endian.
    let context_id = SessionId::from(u128::from_be_bytes(
        cert.serial
            .to_bytes_be()
            .try_into()
            .or(Err(anyhow!("Invalid context ID length")))?,
    ));
    Ok(context_id)
}

/// Extract the party name from the certificate.
///
/// Each party should have its own self-signed certificate.
/// Each self-signed certificate is loaded into the trust store of all the parties.
///
/// We support wildcards so the certificate may have
/// CN: example.com
/// SAN: *.example.com, example.com
/// The identity is the one in the CN field and it should exist in the SAN too.
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

pub fn build_ca_certs_map<I: Iterator<Item = Pem>>(
    cert_pems: I,
) -> anyhow::Result<HashMap<String, Pem>> {
    cert_pems
        .map(|c| {
            c.parse_x509()
                .map_err(|e| anyhow::anyhow!("Could not parse X509 structure: {e}"))
                .and_then(|ref x509_cert| {
                    extract_subject_from_cert(x509_cert).map(|s| (s, c.clone()))
                })
        })
        .collect::<Result<HashMap<String, Pem>, _>>()
}
