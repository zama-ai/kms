use super::SecurityModule;

use nsm_nitro_enclave_utils::{
    api::nsm::{Request, Response},
    driver::{Driver, dev::DevNitro},
};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

impl SecurityModule for DevNitro {
    async fn attest(&self, pk: Vec<u8>, user_data: Option<Vec<u8>>) -> anyhow::Result<Vec<u8>> {
        let request = Request::Attestation {
            public_key: Some(pk.into()),
            user_data: user_data.map(|x| x.into()),
            nonce: None,
        };
        let Response::Attestation { document } = self.process_request(request) else {
            anyhow::bail!("Mock Nitro enclave attestation request failed");
        };
        Ok(document)
    }

    async fn get_random(&self, num_bytes: usize) -> anyhow::Result<Vec<u8>> {
        let mut vec = vec![0u8; num_bytes];
        OsRng.try_fill_bytes(&mut vec)?;
        Ok(vec)
    }

    fn get_random_sync<const N: usize>(&self) -> anyhow::Result<Zeroizing<[u8; N]>> {
        let mut buf = Zeroizing::new([0u8; N]);
        OsRng.try_fill_bytes(buf.as_mut())?;
        Ok(buf)
    }
}
