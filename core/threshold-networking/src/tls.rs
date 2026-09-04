use threshold_types::party::MpcIdentity;
use threshold_types::session_id::SessionId;

use anyhow::{anyhow, bail, ensure};
use attestation_doc_validation::validate_and_parse_attestation_doc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};
use tfhe_versionable::{Versionize, VersionsDispatch};
use tokio_rustls::rustls::{
    DigitallySignedStruct, DistinguishedName, Error, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::{
        WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};
use x509_parser::{certificate::X509Certificate, parse_x509_certificate, pem::Pem};

#[derive(VersionsDispatch, Clone, Debug, Serialize, Deserialize)]
pub enum ReleasePCRValuesVersions {
    V0(ReleasePCRValues),
}

/// These three values, PCR0,1,2, describe a software release. We also check
/// PCR8 which is the hash of the certificate that signed a running enclave
/// image but its reference value comes from hashing the certificate bundled
/// within the mTLS certificate, not through configuration.
///
/// WARNING: this may be printed for debugging and hence should NOT contain any secrets, such as private keys.
/// If minor secrets needs to be added, then ensure fields are annotated with `#[serde(skip_serializing)]` to avoid accidentally diclosing them.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Versionize, Hash, Eq)]
#[versionize(ReleasePCRValuesVersions)]
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

#[derive(Clone)]
struct ContextTrustRoot {
    client: Arc<dyn ClientCertVerifier>,
    server: Arc<WebPkiServerVerifier>,
}

type UserDataVerifier = dyn Fn(ReleasePCRValues, Vec<u8>) -> anyhow::Result<bool> + Send + Sync;

struct VerifierCandidate {
    context_id: SessionId,
    trust_root: ContextTrustRoot,
    pcrs: HashSet<ReleasePCRValues>,
}

/// The active context verifiers for a peer certificate subject.
struct Verifiers {
    subject: String,
    candidates: Vec<VerifierCandidate>,
}

fn verify_with_any_context<T>(
    verifiers: &Verifiers,
    mut verify: impl FnMut(&VerifierCandidate) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut last_error = None;
    for candidate in &verifiers.candidates {
        match verify(candidate) {
            Ok(result) => return Ok(result),
            Err(error) => last_error = Some((candidate.context_id, error)),
        }
    }

    Err(Error::General(match last_error {
        Some((context_id, error)) => format!(
            "certificate for {} failed validation against all active contexts; last failure was for context {context_id}: {error}",
            verifiers.subject
        ),
        None => format!("no active contexts found for {}", verifiers.subject),
    }))
}

/// Our custom verifier for our custom mTLS certificates extended with AWS Nitro
/// attestation documents. It doesn't reimplement normal X.509 certificate
/// verification and wraps around the well-tested
/// WebPki[Client|Server]Verifier. In addition to the usual X.509 checks, it
/// checks PCR values from the bundled attestation document. It also supports
/// multiple trust root sets configurable at runtime which is handy when working
/// with multiple MPC contexts.
///
/// The verifier tries each active context's CA certificate and PCR allowlist for
/// the certificate subject.
pub struct AttestedVerifier {
    root_hint_subjects: Vec<DistinguishedName>,
    supported_algs: WebPkiSupportedAlgorithms,
    // Each context supplies its own trust root for an MPC identity.
    trust_roots: RwLock<HashMap<MpcIdentity, HashMap<SessionId, ContextTrustRoot>>>,
    // Each context can specify a list of valid PCR values
    release_pcrs: RwLock<HashMap<SessionId, HashSet<ReleasePCRValues>>>,
    // In addition to the PCR values, the verifier can also check the user data
    // section in the attestation document using a custom function of the type
    // `UserDataVerifier`. For example, If the node is configured to attest
    // private vault root key policies, the user data section will contain its
    // canonicalized key policy, and it'll check other parties' key policies
    // using `user_data_verifier`.
    user_data_verifier: Option<Arc<UserDataVerifier>>,
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

/// We have to manually implement Debug for `AttestedVerifier` because Debug
/// can't be derived for `user_data_verifier`.
impl std::fmt::Debug for AttestedVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("AttestedVerifier");
        let f = f
            .field("root_hint_subjects", &self.root_hint_subjects)
            .field("supported_algs", &self.supported_algs)
            .field(
                "user_data_verifier_present",
                &self.user_data_verifier.is_some(),
            )
            .field("pcr8_expected", &self.pcr8_expected);
        #[cfg(feature = "testing")]
        let f = f.field("mock_enclave", &self.mock_enclave);
        f.finish()
    }
}

impl AttestedVerifier {
    pub fn new(
        user_data_verifier: Option<Arc<UserDataVerifier>>,
        pcr8_expected: bool,
        #[cfg(feature = "testing")] mock_enclave: bool,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            root_hint_subjects: Vec::new(),
            supported_algs: CryptoProvider::get_default()
                .ok_or_else(|| {
                    anyhow!(
                        "
Crypto provider should exist at this point"
                    )
                })?
                .signature_verification_algorithms,
            trust_roots: RwLock::new(HashMap::new()),
            release_pcrs: RwLock::new(HashMap::new()),
            user_data_verifier,
            pcr8_expected,
            #[cfg(feature = "testing")]
            mock_enclave,
        })
    }

    pub fn add_context(
        &self,
        context_id: SessionId,
        ca_certs: HashMap<MpcIdentity, Pem>,
        release_pcrs: Option<HashSet<ReleasePCRValues>>,
    ) -> anyhow::Result<()> {
        let context_roots = ca_certs
            .into_iter()
            .map(|(mpc_identity, ca_cert)| {
                let mut roots = RootCertStore::empty();
                roots.add(CertificateDer::from_slice(&ca_cert.contents))?;
                let roots = Arc::new(roots);
                let client_verifier = WebPkiClientVerifier::builder(roots.clone()).build()?;
                let server_verifier = WebPkiServerVerifier::builder(roots).build()?;
                Ok((
                    mpc_identity,
                    ContextTrustRoot {
                        client: client_verifier,
                        server: server_verifier,
                    },
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let mut trust_roots = self
            .trust_roots
            .write()
            .map_err(|e| anyhow::anyhow!("Failed to acquire write lock: {e}"))?;
        let mut release_pcrs_by_context = self
            .release_pcrs
            .write()
            .map_err(|e| anyhow::anyhow!("Failed to acquire write lock: {e}"))?;

        let replaced = trust_roots
            .values()
            .any(|roots| roots.contains_key(&context_id))
            || release_pcrs_by_context.contains_key(&context_id);
        trust_roots.retain(|_, roots| {
            roots.remove(&context_id);
            !roots.is_empty()
        });
        for (mpc_identity, trust_root) in context_roots {
            trust_roots
                .entry(mpc_identity)
                .or_default()
                .insert(context_id, trust_root);
        }
        match release_pcrs {
            Some(release_pcrs) => {
                release_pcrs_by_context.insert(context_id, release_pcrs);
            }
            None => {
                release_pcrs_by_context.remove(&context_id);
            }
        }
        if replaced {
            tracing::warn!("Replaced TLS trust roots and PCR values for context {context_id}");
        }
        Ok(())
    }

    pub fn remove_context(&self, context_id: SessionId) -> anyhow::Result<()> {
        let mut trust_roots = self
            .trust_roots
            .write()
            .map_err(|e| anyhow::anyhow!("Failed to acquire write lock: {e}"))?;
        let mut release_pcrs = self
            .release_pcrs
            .write()
            .map_err(|e| anyhow::anyhow!("Failed to acquire write lock: {e}"))?;
        trust_roots.retain(|_, context_roots| {
            context_roots.remove(&context_id);
            !context_roots.is_empty()
        });
        release_pcrs.remove(&context_id);
        Ok(())
    }

    fn get_verifiers_and_pcrs_for_x509_cert(
        &self,
        cert: &X509Certificate<'_>,
    ) -> Result<Verifiers, Error> {
        let subject = extract_subject_from_cert(cert).map_err(|e| Error::General(e.to_string()))?;
        tracing::debug!("Getting context and verifiers for {subject}");

        let trust_roots = self
            .trust_roots
            .read()
            .map_err(|e| Error::General(format!("Failed to acquire read lock: {e}")))?;
        let context_roots = trust_roots
            .get(&MpcIdentity(subject.clone()))
            .ok_or_else(|| {
                let e = Error::General(format!("{subject} is not a trust anchor"));
                tracing::error!("{e}");
                e
            })?;
        let release_pcrs = self
            .release_pcrs
            .read()
            .map_err(|e| Error::General(format!("Failed to acquire read lock: {e}")))?;
        Ok(Verifiers {
            subject,
            candidates: context_roots
                .iter()
                .map(|(context_id, trust_root)| VerifierCandidate {
                    context_id: *context_id,
                    trust_root: trust_root.clone(),
                    pcrs: release_pcrs.get(context_id).cloned().unwrap_or_default(),
                })
                .collect(),
        })
    }

    fn get_verifiers_and_pcrs_for_cert_der(
        &self,
        cert: &CertificateDer<'_>,
    ) -> Result<Verifiers, Error> {
        let (_, x509_cert) =
            parse_x509_certificate(cert.as_ref()).map_err(|e| Error::General(e.to_string()))?;
        self.get_verifiers_and_pcrs_for_x509_cert(&x509_cert)
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
        let verifiers = self.get_verifiers_and_pcrs_for_x509_cert(&cert)?;
        // check the enclave-generated certificate used for the TLS session as
        // usual (however, we expect it to be self-signed)
        tracing::debug!("Verifying certificate for server {:?}", server_name,);
        // check the bundled attestation document and EIF signing certificate
        #[cfg(feature = "testing")]
        let do_validation = !&self.mock_enclave;
        #[cfg(not(feature = "testing"))]
        let do_validation = true;

        verify_with_any_context(&verifiers, |candidate| {
            candidate.trust_root.server.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )?;
            if do_validation && !candidate.pcrs.is_empty() {
                validate_wrapped_cert(
                    &cert,
                    candidate.pcrs.clone(),
                    self.user_data_verifier.as_ref().map(Arc::clone),
                    self.pcr8_expected,
                    CertVerifier::Server(
                        candidate.trust_root.server.clone(),
                        server_name,
                        ocsp_response,
                    ),
                    intermediates,
                    now,
                )
                .map_err(|e| Error::General(e.to_string()))?;
            }
            Ok(ServerCertVerified::assertion())
        })
        .inspect_err(|e| {
            tracing::error!(
                "server certificate validation error for party {}: {e}, supported algorithms: {:?}",
                verifiers.subject,
                &self.supported_algs
            );
        })
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let verifiers = self.get_verifiers_and_pcrs_for_cert_der(cert)?;
        verify_with_any_context(&verifiers, |candidate| {
            candidate
                .trust_root
                .server
                .verify_tls12_signature(message, cert, dss)
        })
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let verifiers = self.get_verifiers_and_pcrs_for_cert_der(cert)?;
        verify_with_any_context(&verifiers, |candidate| {
            candidate
                .trust_root
                .server
                .verify_tls13_signature(message, cert, dss)
        })
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
        let verifiers = self.get_verifiers_and_pcrs_for_x509_cert(&cert)?;

        // check the bundled attestation document and EIF signing certificate
        #[cfg(feature = "testing")]
        let do_validation = !&self.mock_enclave;
        #[cfg(not(feature = "testing"))]
        let do_validation = true;

        verify_with_any_context(&verifiers, |candidate| {
            candidate
                .trust_root
                .client
                .verify_client_cert(end_entity, intermediates, now)?;
            if do_validation && !candidate.pcrs.is_empty() {
                validate_wrapped_cert(
                    &cert,
                    candidate.pcrs.clone(),
                    self.user_data_verifier.as_ref().map(Arc::clone),
                    self.pcr8_expected,
                    CertVerifier::Client(candidate.trust_root.client.clone()),
                    intermediates,
                    now,
                )
                .map_err(|e| Error::General(e.to_string()))?;
            } else {
                tracing::warn!(
                    "Skipping attestation document validation for context {} because do_validation={}, release_pcrs.is_empty={}",
                    candidate.context_id,
                    do_validation,
                    candidate.pcrs.is_empty()
                );
            }
            Ok(ClientCertVerified::assertion())
        })
        .inspect_err(|e| {
            tracing::error!(
                "client certificate validation error for party {}: {e}, supported algorithms: {:?}",
                verifiers.subject,
                &self.supported_algs
            );
        })
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let verifiers = self.get_verifiers_and_pcrs_for_cert_der(cert)?;
        verify_with_any_context(&verifiers, |candidate| {
            candidate
                .trust_root
                .client
                .verify_tls12_signature(message, cert, dss)
        })
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let verifiers = self.get_verifiers_and_pcrs_for_cert_der(cert)?;
        verify_with_any_context(&verifiers, |candidate| {
            candidate
                .trust_root
                .client
                .verify_tls13_signature(message, cert, dss)
        })
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

pub enum CertVerifier<'a> {
    Client(Arc<dyn ClientCertVerifier>),
    Server(Arc<dyn ServerCertVerifier>, &'a ServerName<'a>, &'a [u8]),
}

fn validate_wrapped_cert(
    cert: &X509Certificate,
    trusted_releases: HashSet<ReleasePCRValues>,
    user_data_verifier: Option<Arc<UserDataVerifier>>,
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

    let attestation_doc = validate_and_parse_attestation_doc(attestation_doc.value)
        .map_err(|e| anyhow!("Could not validate attestation document: {e}"))?;

    let Some(attested_pk) = attestation_doc.public_key else {
        bail!("Bad certificate: public key not present in attestation document")
    };
    ensure!(
        *cert.public_key().raw == *attested_pk.as_slice(),
        "Bad certificate: subject public key info {} does not match attestation document public key info {}",
        hex::encode(cert.public_key().raw),
        hex::encode(attested_pk.as_slice())
    );

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

    let pcr_values = ReleasePCRValues {
        pcr0: pcr0.to_vec(),
        pcr1: pcr1.to_vec(),
        pcr2: pcr2.to_vec(),
    };

    if !trusted_releases.contains(&pcr_values) {
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
        // check party certificate validity (the verification result is only used
        // for its `?`-propagated error; there is nothing to bind on success)
        match verifier {
            CertVerifier::Client(v) => {
                v.verify_client_cert(
                    &CertificateDer::from_slice(party_cert_bytes.value),
                    intermediates,
                    now,
                )?;
            }
            CertVerifier::Server(v, server_name, ocsp_response) => {
                v.verify_server_cert(
                    &CertificateDer::from_slice(party_cert_bytes.value),
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                )?;
            }
        };
        // Check party certificate hash against the attested value. Note that the
        // Nitro attestation document format uses SHA2-384 only (not SHA3).
        let mut hasher = Sha384::new();
        hasher.update(party_cert_bytes.value);
        let party_cert_hash = hasher.finalize();
        #[allow(deprecated)]
        if party_cert_hash.as_slice() != pcr8.as_slice() {
            bail!(
                "Bad certificate: untrusted party certificate hash {} in attestation document, expected {}",
                hex::encode(party_cert_hash.as_slice()),
                hex::encode(pcr8.as_slice())
            )
        }
    }

    // If the node wasn't configured to attest key policies, it shouldn't check
    // for the presence of user data carrying key policy attestation at all.
    if let Some(user_data_verifier) = user_data_verifier {
        let Some(user_data) = attestation_doc.user_data else {
            bail!("Bad certificate: additional measurements not present in attestation document")
        };
        ensure!(
            user_data_verifier(pcr_values, user_data.into_vec())?,
            "Bad certificate: additional measurements verification failed"
        );
    };

    Ok(())
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

    // If we have replicas, we expect the jth replica CN to be
    // core{j}.example.com and the issuer CN to be example.com.
    // If we don't have replicas, we expect the subject CN to match the issuer CN.
    if let Some((_subject_core, subject_ca)) = subject_str.split_once(".") {
        if subject_ca != issuer_str && subject_str != issuer_str {
            bail!("Bad certificate: subject CN (or subject CN suffix) does not match issuer CN");
        }
    } else {
        if subject_str != issuer_str {
            bail!("Bad certificate: subject CN does not match issuer CN");
        }
    }

    if !san_strings.contains(&subject_str) {
        bail!("Bad certificate: subject CN not found in SAN");
    }

    Ok(subject_str.to_string())
}

pub fn build_ca_certs_map<I: Iterator<Item = Pem>>(
    cert_pems: I,
) -> anyhow::Result<HashMap<MpcIdentity, Pem>> {
    cert_pems
        .map(|c| {
            c.parse_x509()
                .map_err(|e| anyhow::anyhow!("Could not parse X509 structure: {e}"))
                .and_then(|ref x509_cert| {
                    extract_subject_from_cert(x509_cert).map(|s| (MpcIdentity(s), c.clone()))
                })
        })
        .collect::<Result<HashMap<MpcIdentity, Pem>, _>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
    use tokio_rustls::rustls::crypto::aws_lc_rs::default_provider;

    fn test_ca(identity: &str) -> (rcgen::Certificate, Pem) {
        let keypair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let certificate =
            crate::tls_certs::create_selfsigned_cert_from_keypair(identity, false, false, &keypair)
                .unwrap()
                .1;
        let pem = x509_parser::pem::parse_x509_pem(certificate.pem().as_bytes())
            .unwrap()
            .1;
        (certificate, pem)
    }

    fn test_pcr(value: u8) -> ReleasePCRValues {
        ReleasePCRValues {
            pcr0: vec![value],
            pcr1: vec![value],
            pcr2: vec![value],
        }
    }

    #[test]
    fn pcrs_are_scoped_to_context_candidates() {
        _ = default_provider().install_default();
        let verifier = AttestedVerifier::new(
            None,
            false,
            #[cfg(feature = "testing")]
            true,
        )
        .unwrap();
        let identity = "scoped-pcr.example.com";
        let (certificate_a, ca_a) = test_ca(identity);
        let (_, ca_b) = test_ca(identity);
        let context_a = SessionId::from(1u128);
        let context_b = SessionId::from(2u128);
        let pcr_a = test_pcr(1);
        let pcr_b = test_pcr(2);

        verifier
            .add_context(
                context_a,
                HashMap::from([(MpcIdentity(identity.to_string()), ca_a)]),
                Some(HashSet::from([pcr_a.clone()])),
            )
            .unwrap();
        verifier
            .add_context(
                context_b,
                HashMap::from([(MpcIdentity(identity.to_string()), ca_b)]),
                Some(HashSet::from([pcr_b.clone()])),
            )
            .unwrap();

        let (_, certificate_a) = parse_x509_certificate(certificate_a.der()).unwrap();
        let verifiers = verifier
            .get_verifiers_and_pcrs_for_x509_cert(&certificate_a)
            .unwrap();
        assert_eq!(verifiers.candidates.len(), 2);
        let candidate_a = verifiers
            .candidates
            .iter()
            .find(|candidate| candidate.context_id == context_a)
            .unwrap();
        let candidate_b = verifiers
            .candidates
            .iter()
            .find(|candidate| candidate.context_id == context_b)
            .unwrap();
        assert_eq!(candidate_a.pcrs, HashSet::from([pcr_a]));
        assert_eq!(candidate_b.pcrs, HashSet::from([pcr_b]));
    }
}
