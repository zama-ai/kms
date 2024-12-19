use rsa::RsaPublicKey;

pub mod nitro;

#[tonic::async_trait]
pub trait SecurityModule {
    /// Get enthropy from the hardware RNG
    async fn get_random(&self, num_bytes: usize) -> anyhow::Result<Vec<u8>>;

    /// Request the attestation document signed by the security module that
    /// contains PCR values and the application RSA public key
    async fn attest_rsa_pk(&self, pk: &RsaPublicKey) -> anyhow::Result<Vec<u8>>;
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

    async fn attest_rsa_pk(&self, pk: &RsaPublicKey) -> anyhow::Result<Vec<u8>> {
        match &self {
            SecurityModuleProxy::Nitro(sm) => sm.attest_rsa_pk(pk).await,
        }
    }
}

pub fn make_security_module() -> anyhow::Result<SecurityModuleProxy> {
    let security_module = nitro::Nitro::new()?;
    Ok(SecurityModuleProxy::Nitro(security_module))
}
