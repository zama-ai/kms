use crate::{execution::runtime::party::MpcIdentity, session_id::SessionId};

use anyhow::{anyhow, bail, ensure};
use attestation_doc_validation::{
    attestation_doc::{decode_attestation_document, validate_cose_signature},
    cert::validate_cert_trust_chain,
    nsm::{CryptoClient as NsmCryptoClient, PublicKey as NsmPublicKey},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};
use tfhe::Versionize;
use tfhe_versionable::VersionsDispatch;
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

#[derive(VersionsDispatch, Clone, Debug, Serialize, Deserialize)]
pub enum ReleasePCRValuesVersioned {
    V0(ReleasePCRValues),
}

/// These three values, PCR0,1,2, describe a software release. We also check
/// PCR8 which is the hash of the certificate that signed a running enclave
/// image but its reference value comes from hashing the certificate bundled
/// within the mTLS certificate, not through configuration.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Versionize, Hash, Eq)]
#[versionize(ReleasePCRValuesVersioned)]
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

pub type TrustRootValue = (
    Arc<dyn ClientCertVerifier>,
    Arc<WebPkiServerVerifier>,
    HashSet<SessionId>,
);

type UserDataVerifier = dyn Fn(ReleasePCRValues, Vec<u8>) -> anyhow::Result<bool> + Send + Sync;

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
pub struct AttestedVerifier {
    root_hint_subjects: Vec<DistinguishedName>,
    supported_algs: WebPkiSupportedAlgorithms,
    // There is one trust root per MPC identity but one MPC identity can belong
    // to multiple contexts.  SessionId is supposed to be based on RequestId,
    // and we're representing ContextId as RequestId so far, so let's say it's
    // all the same for now.
    trust_roots: RwLock<HashMap<MpcIdentity, TrustRootValue>>,
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
    ignore_aws_ca_chain: bool,
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
            .field("pcr8_expected", &self.pcr8_expected)
            .field("ignore_aws_ca_chain", &self.ignore_aws_ca_chain);
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
        ignore_aws_ca_chain: bool,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            root_hint_subjects: Vec::new(),
            supported_algs: CryptoProvider::get_default()
                .ok_or(anyhow!(
                    "
Crypto provider should exist at this point"
                ))?
                .signature_verification_algorithms,
            trust_roots: RwLock::new(HashMap::new()),
            release_pcrs: RwLock::new(HashMap::new()),
            user_data_verifier,
            pcr8_expected,
            #[cfg(feature = "testing")]
            mock_enclave,
            ignore_aws_ca_chain,
        })
    }

    pub fn add_context(
        &self,
        context_id: SessionId,
        ca_certs: HashMap<MpcIdentity, Pem>,
        release_pcrs: Option<HashSet<ReleasePCRValues>>,
    ) -> anyhow::Result<()> {
        let mut trust_roots = self
            .trust_roots
            .write()
            .map_err(|e| anyhow::anyhow!("Failed to acquire write lock: {e}"))?;
        for (mpc_identity, ca_cert) in ca_certs {
            match trust_roots.get_mut(&mpc_identity) {
                Some((_, _, contexts)) => {
                    if !contexts.insert(context_id) {
                        tracing::warn!("MPC identity {mpc_identity} is already present in context {context_id}")
                    }
                }
                None => {
                    let mut roots = RootCertStore::empty();
                    roots.add(CertificateDer::from_slice(&ca_cert.contents))?;
                    let roots = Arc::new(roots);
                    let client_verifier = WebPkiClientVerifier::builder(roots.clone()).build()?;
                    let server_verifier = WebPkiServerVerifier::builder(roots).build()?;
                    trust_roots.insert(
                        mpc_identity,
                        (
                            client_verifier,
                            server_verifier,
                            HashSet::from([context_id]),
                        ),
                    );
                }
            }
        }
        if let Some(new_release_pcrs) = release_pcrs {
            let mut release_pcrs = self
                .release_pcrs
                .write()
                .map_err(|e| anyhow::anyhow!("Failed to acquire write lock: {e}"))?;
            if let std::collections::hash_map::Entry::Vacant(e) = release_pcrs.entry(context_id) {
                e.insert(new_release_pcrs);
            } else {
                tracing::warn!("PCR values already defined in context {context_id}")
            }
        }
        Ok(())
    }

    pub fn remove_context(&self, context_id: SessionId) -> anyhow::Result<()> {
        let mut trust_roots = self
            .trust_roots
            .write()
            .map_err(|e| anyhow::anyhow!("Failed to acquire write lock: {e}"))?;
        trust_roots.retain(|_, (_, _, contexts)| {
            contexts.remove(&context_id);
            !contexts.is_empty()
        });
        let mut release_pcrs = self
            .release_pcrs
            .write()
            .map_err(|e| anyhow::anyhow!("Failed to acquire write lock: {e}"))?;
        release_pcrs.remove(&context_id);
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn get_verifiers_and_pcrs_for_x509_cert(
        &self,
        cert: &X509Certificate<'_>,
    ) -> Result<
        (
            Arc<dyn ClientCertVerifier>,
            Arc<dyn ServerCertVerifier>,
            HashSet<ReleasePCRValues>,
        ),
        Error,
    > {
        let subject = extract_subject_from_cert(cert).map_err(|e| Error::General(e.to_string()))?;
        tracing::debug!("Getting context and verifiers for {subject}");

        let trust_roots = self
            .trust_roots
            .read()
            .map_err(|e| Error::General(format!("Failed to acquire read lock: {e}")))?;
        let (client_verifier, server_verifier, contexts) = trust_roots
            .get(&MpcIdentity(subject.clone()))
            .ok_or(Error::General(format!("{subject} is not a trust anchor")))
            .cloned()
            .inspect_err(|e| {
                tracing::error!("{e}");
            })?;
        let release_pcrs = self
            .release_pcrs
            .read()
            .map_err(|e| Error::General(format!("Failed to acquire read lock: {e}")))?;
        let pcrs_for_mpc_identity = contexts
            .iter()
            .filter_map(|context_id| release_pcrs.get(context_id))
            .flatten()
            .cloned()
            .collect::<HashSet<_>>();

        Ok((client_verifier, server_verifier, pcrs_for_mpc_identity))
    }

    #[allow(clippy::type_complexity)]
    fn get_verifiers_and_pcrs_for_cert_der(
        &self,
        cert: &CertificateDer<'_>,
    ) -> Result<
        (
            Arc<dyn ClientCertVerifier>,
            Arc<dyn ServerCertVerifier>,
            HashSet<ReleasePCRValues>,
        ),
        Error,
    > {
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
        let (_, server_verifier, release_pcrs) =
            self.get_verifiers_and_pcrs_for_x509_cert(&cert)?;
        let subject =
            extract_subject_from_cert(&cert).map_err(|e| Error::General(e.to_string()))?;
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

        if do_validation && !release_pcrs.is_empty() {
            validate_wrapped_cert(
                &cert,
                release_pcrs,
                self.user_data_verifier.as_ref().map(Arc::clone),
                self.pcr8_expected,
                CertVerifier::Server(server_verifier.clone(), server_name, ocsp_response),
                intermediates,
                now,
                self.ignore_aws_ca_chain,
            )
            .map_err(|e| {
                tracing::error!(
                    "bundled attestation document validation error for party {subject}: {e}"
                );
                Error::General(e.to_string())
            })?;
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.get_verifiers_and_pcrs_for_cert_der(cert)?
            .1
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.get_verifiers_and_pcrs_for_cert_der(cert)?
            .1
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
        let (client_verifier, _, release_pcrs) =
            self.get_verifiers_and_pcrs_for_x509_cert(&cert)?;
        let subject =
            extract_subject_from_cert(&cert).map_err(|e| Error::General(e.to_string()))?;
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

        if do_validation && !release_pcrs.is_empty() {
            validate_wrapped_cert(
                &cert,
                release_pcrs,
                self.user_data_verifier.as_ref().map(Arc::clone),
                self.pcr8_expected,
                CertVerifier::Client(client_verifier.clone()),
                intermediates,
                now,
                self.ignore_aws_ca_chain,
            )
            .map_err(|e| {
                tracing::error!(
                    "bundled attestation document validation error for party {subject}: {e}"
                );
                Error::General(e.to_string())
            })?;
        } else {
            tracing::warn!("Skipping attestation document validation because do_validation={}, release_pcrs.is_empty={}", do_validation, release_pcrs.is_empty());
        }

        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.get_verifiers_and_pcrs_for_cert_der(cert)?
            .0
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.get_verifiers_and_pcrs_for_cert_der(cert)?
            .0
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

#[allow(clippy::too_many_arguments)]
fn validate_wrapped_cert(
    cert: &X509Certificate,
    trusted_releases: HashSet<ReleasePCRValues>,
    user_data_verifier: Option<Arc<UserDataVerifier>>,
    pcr8_expected: bool,
    verifier: CertVerifier,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
    ignore_aws_ca_chain: bool,
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

    // Parse attestation doc from cose signature and validate structure
    let (cose_sign_1_decoded, attestation_doc) = decode_attestation_document(attestation_doc.value)
        .map_err(|e| anyhow!("Could not decode attestation document: {e}"))?;
    let (_, attestation_doc_signing_cert) =
        x509_parser::parse_x509_certificate(&attestation_doc.certificate).map_err(|e| {
            anyhow!("Could not parse attestation document signing certificate: {e}")
        })?;
    // Validate Cose signature over attestation doc
    let pub_key =
        NsmPublicKey::try_from(attestation_doc_signing_cert.public_key()).map_err(|e| {
            anyhow!("Could not parse attestation document signing certificate public key: {e}")
        })?;
    validate_cose_signature::<NsmCryptoClient>(&pub_key, &cose_sign_1_decoded)
        .map_err(|e| anyhow!("Could not verify attestation document signature: {e}"))?;
    // Validate that the attestation doc's signature can be tied back to the AWS Nitro CA
    let intermediate_certs: Vec<&[u8]> = attestation_doc
        .cabundle
        .iter()
        .map(|cert| cert.as_slice())
        .collect();
    let aws_cert_chain_valid_res = validate_cert_trust_chain(
        &attestation_doc.certificate,
        &intermediate_certs,
        Some(now.as_secs()),
    );
    if let Err(e) = aws_cert_chain_valid_res {
        if ignore_aws_ca_chain {
            let subject = extract_subject_from_cert(cert)?;
            tracing::warn!(
                "Cannot validate CA chain for party {subject} attestation document at timestamp {}: {}", now.as_secs(), e
            );
            tracing::warn!(
                "Party {} attestation document signing certificate: {:#?}",
                subject,
                attestation_doc_signing_cert
            );
            for cert in attestation_doc.cabundle {
                let (_, intermediate_cert) =
                    x509_parser::parse_x509_certificate(&cert).map_err(|e| {
                        anyhow!(
                            "Could not parse attestation document intermediate certificate: {e}"
                        )
                    })?;
                tracing::warn!(
                    "Party {} attestation document intermediate certificate: {:#?}",
                    subject,
                    intermediate_cert
                );
            }
        } else {
            bail!("{e}")
        }
    }

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
