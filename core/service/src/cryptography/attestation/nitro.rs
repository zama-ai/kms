use super::SecurityModule;
use anyhow::{bail, ensure};
use aws_nitro_enclaves_nsm_api::{
    api::{Request as NSMRequest, Response as NSMResponse},
    driver as nsm_driver,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

fn extract_random<const N: usize>(response: NSMResponse) -> anyhow::Result<Zeroizing<[u8; N]>> {
    let NSMResponse::GetRandom { random } = response else {
        bail!("Nitro enclave entropy generation failed");
    };
    let random = Zeroizing::new(random);
    ensure!(
        random.len() >= 256,
        "NSM returned less than 256 bytes of entropy"
    );
    ensure!(
        N <= random.len(),
        "More bytes of entropy requested than generated"
    );
    let mut bytes = Zeroizing::new([0u8; N]);
    bytes.copy_from_slice(&random[..N]);
    Ok(bytes)
}

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

impl SecurityModule for Nitro {
    /// Request the attestation document from the Nitro security module. Attestation
    /// documents are used in AWS KMS requests to receive responses where the
    /// sensitive data that can only be shared with enclaves running an approved
    /// software version is encrypted under the attested enclave public key.
    async fn attest(&self, pk: Vec<u8>, user_data: Option<Vec<u8>>) -> anyhow::Result<Vec<u8>> {
        // generate a nonce to include into the attestation document
        let attestation_nonce = self.get_random(ATTESTATION_NONCE_SIZE).await?;

        // request Nitro enclave attestation
        let nsm_request = NSMRequest::Attestation {
            public_key: Some(pk.into()),
            user_data: user_data.map(|x| x.into()),
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

    fn get_random_sync<const N: usize>(&self) -> anyhow::Result<Zeroizing<[u8; N]>> {
        // A separate connection avoids blocking on the async attestation mutex.
        let nsm_fd = nsm_driver::nsm_init();
        ensure!(nsm_fd != -1, "NSM device unavailable");
        let response = nsm_driver::nsm_process_request(nsm_fd, NSMRequest::GetRandom);
        nsm_driver::nsm_exit(nsm_fd);
        extract_random(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_nitro_enclaves_nsm_api::api::ErrorCode;

    #[test]
    fn fixed_size_random_response_is_checked_before_copying() {
        let bytes = extract_random::<{ aes_prng::SEED_SIZE }>(NSMResponse::GetRandom {
            random: vec![0xA5; 256],
        })
        .unwrap();
        assert_eq!(*bytes, [0xA5; aes_prng::SEED_SIZE]);
        assert!(
            extract_random::<16>(NSMResponse::GetRandom {
                random: vec![0; 255]
            })
            .is_err()
        );
        assert!(
            extract_random::<257>(NSMResponse::GetRandom {
                random: vec![0; 256]
            })
            .is_err()
        );
        assert!(extract_random::<16>(NSMResponse::Error(ErrorCode::InternalError)).is_err());
    }
}
