use crate::anyhow_error_and_log;
use crate::core::der_types::{self, PrivateSigKey, PublicEncKey, PublicSigKey};
use crate::core::kms_core::BaseKmsStruct;
use crate::core::signcryption::signcrypt;
use crate::file_handling::read_element;
use crate::kms::kms_endpoint_server::{KmsEndpoint, KmsEndpointServer};
use crate::kms::{
    DecryptionRequest, DecryptionResponse, FheType, ReencryptionRequest, ReencryptionResponse,
};
use crate::rpc::kms_rpc::{
    handle_potential_err, process_response, validate_decrypt_req, validate_reencrypt_req,
};
use crate::rpc::rpc_types::{
    BaseKms, DecryptionResponseSigPayload, Plaintext, RawDecryption, SigncryptionPayload,
};
use aes_prng::AesRng;
use distributed_decryption::algebra::base_ring::Z128;
use distributed_decryption::algebra::residue_poly::{ResiduePoly, ResiduePoly128};
use distributed_decryption::choreography::NetworkingStrategy;
use distributed_decryption::computation::SessionId;
use distributed_decryption::execution::endpoints::decryption::{
    batch_partial_decrypt, reconstruct_message,
};
use distributed_decryption::execution::runtime::party::{Identity, Role, RoleAssignment};
use distributed_decryption::execution::runtime::session::{
    SessionParameters, SmallSession, SmallSessionStruct,
};
use distributed_decryption::execution::sharing::open::robust_opens_to_all;
use distributed_decryption::execution::small_execution::agree_random::RealAgreeRandomWithAbort;
use distributed_decryption::execution::small_execution::prss::PRSSSetup;
use distributed_decryption::lwe::{
    combine128, to_large_ciphertext_block, BootstrappingKey, Ciphertext64, SecretKeyShare,
    ThresholdLWEParameters,
};
use distributed_decryption::networking::grpc::GrpcNetworkingManager;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_asn1_der::to_vec;
use std::fmt;
use std::net::SocketAddr;
use tokio::task::AbortHandle;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

pub type FhePublicKey = distributed_decryption::lwe::PublicKey;
// Jump between the webserver being externally visible and the webserver used to execute DDec
// TODO this should eventually be specified a bit better
pub const PORT_JUMP: u16 = 100;

/// Construct and initialize a threshold KMS server. Its port will be `base_port`+`my_id``.
pub async fn threshold_server_handle(
    url: String,
    base_port: u16,
    key_path: String,
    parties: usize,
    threshold: u8,
    my_id: usize,
) -> anyhow::Result<()> {
    let port = base_port + (my_id as u16);
    let socket: std::net::SocketAddr = format!("{}:{}", url, port).parse()?;
    let keys: ThresholdKmsKeys = read_element(key_path.to_string())?;
    let mut kms = ThresholdKms::new(keys, parties, threshold, &url, base_port, my_id)?;
    tracing::info!("Initializing threshold KMS server ...");
    kms.init().await?;
    tracing::info!("Initialization done! Starting threshold KMS server ...");
    Server::builder()
        .add_service(KmsEndpointServer::new(kms))
        .serve(socket)
        .await?;
    Ok(())
}

/// Helper method for combining reconstructed messages after decryption.
// TODO is this the right place for this function? Should probably be in ddec
pub fn decrypted_blocks_to_raw_decryption(
    params: &ThresholdLWEParameters,
    fhe_type: FheType,
    recon_blocks: Vec<Z128>,
) -> anyhow::Result<Plaintext> {
    let bits_in_block = params.output_cipher_parameters.usable_message_modulus_log.0 as u32;
    let res = match combine128(bits_in_block, recon_blocks) {
        Ok(res) => res,
        Err(error) => {
            eprint!("Panicked in combining {error}");
            return Err(anyhow_error_and_log(format!(
                "Panicked in combining {error}"
            )));
        }
    };
    Ok(Plaintext::new(res, fhe_type))
}
#[derive(Serialize, Deserialize)]
pub struct ThresholdKmsKeys {
    pub params: ThresholdLWEParameters,
    pub fhe_dec_key_share: SecretKeyShare,
    pub fhe_pk: FhePublicKey,
    pub bsk: BootstrappingKey,
    pub sig_sk: PrivateSigKey,
    pub sig_pk: PublicSigKey,
}
pub struct ThresholdKms {
    params: ThresholdLWEParameters,
    fhe_dec_key_share: SecretKeyShare,
    bsk: BootstrappingKey,
    base_kms: BaseKmsStruct,
    threshold: u8,
    my_id: usize,
    role_assignments: RoleAssignment,
    networking_strategy: NetworkingStrategy,
    abort_handle: AbortHandle,
    // TODO eventually add mode to allow for nlarge as well.
    prss_setup: Option<PRSSSetup<ResiduePoly128>>,
}
impl ThresholdKms {
    pub fn new(
        keys: ThresholdKmsKeys,
        parties: usize,
        threshold: u8,
        url: &str,
        base_port: u16,
        my_id: usize,
    ) -> anyhow::Result<Self> {
        let role_assignment: RoleAssignment = (1..=parties)
            .map(|party_id| {
                let port = base_port + PORT_JUMP + (party_id as u16);
                let role = Role::indexed_by_one(party_id);
                let uri = &format!("{url}:{port}");
                let identity = Identity::from(uri);
                (role, identity)
            })
            .collect();
        let own_identity = role_assignment
            .get(&Role::indexed_by_one(my_id))
            .unwrap()
            .clone();

        let networking_manager = GrpcNetworkingManager::without_tls(own_identity.clone());
        let networking_server = networking_manager.new_server();
        let port = base_port + PORT_JUMP + (my_id as u16);
        let mut server = Server::builder();
        let router = server.add_service(networking_server);
        let addr: SocketAddr = format!("{url}:{port}").parse().unwrap();
        let ddec_handle = tokio::spawn(async move {
            match router.serve(addr).await {
                Ok(handle) => Ok(handle),
                Err(e) => {
                    let msg = format!("Failed to launch ddec server with error: {:?}", e);
                    Err(anyhow_error_and_log(msg))
                }
            }
        });

        let networking_strategy: NetworkingStrategy =
            Box::new(move |session_id, roles| networking_manager.new_session(session_id, roles));
        let base_kms = BaseKmsStruct::new(keys.sig_sk);
        Ok(ThresholdKms {
            params: keys.params,
            fhe_dec_key_share: keys.fhe_dec_key_share,
            bsk: keys.bsk,
            base_kms,
            threshold,
            my_id,
            role_assignments: role_assignment,
            networking_strategy,
            abort_handle: ddec_handle.abort_handle(),
            prss_setup: None,
        })
    }

    /// Initializes a threshold KMS server by executing the PRSS setup.
    pub async fn init(&mut self) -> anyhow::Result<()> {
        let own_identity = self
            .role_assignments
            .get(&Role::indexed_by_one(self.my_id))
            .unwrap()
            .clone();

        // Assume we only have one epoch and start with session 1
        let session_id = SessionId(1);
        let networking = (self.networking_strategy)(session_id, self.role_assignments.clone());

        let mut session = SmallSession::new(
            session_id,
            self.role_assignments.clone(),
            networking.clone(),
            self.threshold,
            None,
            own_identity.clone(),
            Some(self.base_kms.new_rng()?),
        )?;

        self.prss_setup = Some(
            PRSSSetup::init_with_abort::<
                RealAgreeRandomWithAbort,
                AesRng,
                SmallSessionStruct<ResiduePoly128, AesRng, SessionParameters>,
            >(&mut session)
            .await?,
        );
        Ok(())
    }

    pub fn shutdown(&self) {
        self.abort_handle.abort();
    }
}

impl BaseKms for ThresholdKms {
    fn verify_sig<T: fmt::Debug + Serialize>(
        payload: &T,
        signature: &der_types::Signature,
        verification_key: &PublicSigKey,
    ) -> bool {
        BaseKmsStruct::verify_sig(payload, signature, verification_key)
    }

    fn sign<T: fmt::Debug + Serialize>(&self, msg: &T) -> anyhow::Result<der_types::Signature> {
        self.base_kms.sign(msg)
    }

    fn get_verf_key(&self) -> PublicSigKey {
        self.base_kms.get_verf_key()
    }

    fn digest<T: fmt::Debug + Serialize>(msg: &T) -> anyhow::Result<Vec<u8>> {
        BaseKmsStruct::digest(&msg)
    }
}
impl ThresholdKms {
    async fn inner_decrypt(&self, ct: &[u8]) -> anyhow::Result<Vec<ResiduePoly<Z128>>> {
        // TODO handle that we use low level ciphertexts here
        let ciphertext: Ciphertext64 = serde_asn1_der::from_bytes(ct)?;
        let ct_large = ciphertext
            .iter()
            .map(|ct_block| to_large_ciphertext_block(&self.bsk, ct_block))
            .collect_vec();
        let session_id = SessionId::new(&ciphertext)?;
        let networking = (self.networking_strategy)(session_id, self.role_assignments.clone());
        let own_identity = self
            .role_assignments
            .get(&Role::indexed_by_one(self.my_id))
            .unwrap()
            .clone();
        let mut session = SmallSession::new(
            session_id,
            self.role_assignments.clone(),
            networking,
            self.threshold,
            self.prss_setup.clone(),
            own_identity.clone(),
            Some(self.base_kms.new_rng()?),
        )?;
        let partial_dec = batch_partial_decrypt(&mut session, &self.fhe_dec_key_share, ct_large)?;
        let openeds =
            robust_opens_to_all(&session, &partial_dec, (self.threshold + 1) as usize).await?;
        Ok(openeds.unwrap())
    }

    async fn inner_reencrypt(
        &self,
        ct: &[u8],
        ct_type: FheType,
        digest: Vec<u8>,
        client_enc_key: &PublicEncKey,
        client_verf_key: &PublicSigKey,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let partial_dec = self.inner_decrypt(ct).await?;
        let partial_dec_serialized = serde_asn1_der::to_vec(&partial_dec)?;
        let signcryption_msg = SigncryptionPayload {
            raw_decryption: RawDecryption::new(partial_dec_serialized, ct_type),
            req_digest: digest,
        };
        let enc_res = signcrypt(
            &mut self.base_kms.new_rng()?,
            &serde_asn1_der::to_vec(&signcryption_msg)?,
            client_enc_key,
            client_verf_key,
            &self.base_kms.sig_key,
        )?;
        let res = to_vec(&enc_res)?;
        // TODO make logs everywhere. In particular make sure to log errors before throwing the
        // error back up
        tracing::info!("Completed reencyption of ciphertext {:?} with type {:?} to client verification key {:?} under client encryption key {:?}", ct, ct_type, client_verf_key.pk, client_enc_key.0);
        Ok(Some(res))
    }
}

#[tonic::async_trait]
impl KmsEndpoint for ThresholdKms {
    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let inner = request.into_inner();
        let (ciphertext, fhe_type, req_digest, client_enc_key, client_verf_key, shares_needed) =
            handle_potential_err(
                validate_reencrypt_req(&inner).await,
                format!("Invalid key in request {:?}", inner),
            )?;
        let return_cipher = process_response(
            self.inner_reencrypt(
                &ciphertext,
                fhe_type,
                req_digest.clone(),
                &client_enc_key,
                &client_verf_key,
            )
            .await,
        )?;
        Ok(Response::new(ReencryptionResponse {
            shares_needed,
            signcrypted_ciphertext: return_cipher,
            fhe_type: fhe_type.into(),
            digest: req_digest,
            verification_key: handle_potential_err(
                to_vec(&self.get_verf_key()),
                "Could not serialize server verification key".to_string(),
            )?,
        }))
    }

    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        tracing::info!("Received a new request!");
        let inner = request.into_inner();
        let (ciphertext, fhe_type, req_digest, randomness, shares_needed) = handle_potential_err(
            validate_decrypt_req(&inner).await,
            format!("Invalid key in request {:?}", inner),
        )?;
        let raw_decryption = handle_potential_err(
            self.inner_decrypt(&ciphertext).await,
            format!("Decryption failed for request {:?}", inner),
        )?;
        let recon_msg = reconstruct_message(Some(raw_decryption), &self.params).unwrap();
        let plaintext = handle_potential_err(
            decrypted_blocks_to_raw_decryption(&self.params, fhe_type, recon_msg),
            "Could not reconstruct message from blocks".to_string(),
        )?;
        let decrypted_bytes = handle_potential_err(
            to_vec(&plaintext),
            format!(
                "Could not convert plaintext to bytes in request {:?}",
                inner
            ),
        )?;
        let server_verf_key = handle_potential_err(
            to_vec(&self.get_verf_key()),
            "Could not serialize server verification key".to_string(),
        )?;
        let sig_payload = DecryptionResponseSigPayload {
            shares_needed,
            plaintext: decrypted_bytes,
            verification_key: server_verf_key,
            digest: req_digest,
            randomness,
        };
        let sig = handle_potential_err(
            self.sign(&sig_payload),
            format!("Could not sign payload {:?}", sig_payload),
        )?;
        Ok(Response::new(DecryptionResponse {
            signature: sig.sig.to_vec(),
            payload: Some(sig_payload.into()),
        }))
    }
}
