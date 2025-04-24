use x509_parser::pem::Pem;

pub mod nitro;

#[tonic::async_trait]
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
    async fn wrap_x509_cert(&self, cert_pem: Pem) -> anyhow::Result<(Pem, Pem)>;
}

#[derive(Clone)]
pub enum SecurityModuleProxy {
    Nitro(nitro::Nitro),
}

#[tonic::async_trait]
impl SecurityModule for SecurityModuleProxy {
    async fn get_random(&self, num_bytes: usize) -> anyhow::Result<Vec<u8>> {
        match &self {
            SecurityModuleProxy::Nitro(sm) => sm.get_random(num_bytes).await,
        }
    }

    async fn attest_pk_bytes(&self, pk: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        match &self {
            SecurityModuleProxy::Nitro(sm) => sm.attest_pk_bytes(pk).await,
        }
    }

    async fn wrap_x509_cert(&self, cert_pem: Pem) -> anyhow::Result<(Pem, Pem)> {
        match &self {
            SecurityModuleProxy::Nitro(sm) => sm.wrap_x509_cert(cert_pem).await,
        }
    }
}

pub fn make_security_module() -> anyhow::Result<SecurityModuleProxy> {
    let security_module = nitro::Nitro::new()?;
    Ok(SecurityModuleProxy::Nitro(security_module))
}
