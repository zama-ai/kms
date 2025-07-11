use super::SecurityModule;

use nsm_nitro_enclave_utils::{
    api::nsm::{Request, Response},
    driver::{dev::DevNitro, Driver},
};
use rand::{rngs::OsRng, RngCore};

impl SecurityModule for DevNitro {
    async fn attest_pk_bytes(&self, pk: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let request = Request::Attestation {
            public_key: Some(pk.into()),
            user_data: None,
            nonce: None,
        };
        let Response::Attestation { document } = self.process_request(request) else {
            anyhow::bail!("Mock Nitro enclave attestation request failed");
        };
        Ok(document)
    }

    async fn get_random(&self, num_bytes: usize) -> anyhow::Result<Vec<u8>> {
        let mut vec = Vec::with_capacity(num_bytes);
        OsRng.try_fill_bytes(&mut vec)?;
        Ok(vec)
    }
}
