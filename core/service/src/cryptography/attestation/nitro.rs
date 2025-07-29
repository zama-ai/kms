use super::SecurityModule;
use anyhow::{bail, ensure};
use aws_nitro_enclaves_nsm_api::{
    api::{Request as NSMRequest, Response as NSMResponse},
    driver as nsm_driver,
};
use std::sync::Arc;
use tokio::sync::Mutex;

const ATTESTATION_NONCE_SIZE: usize = 8;

#[derive(Clone, Debug)]
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
}
