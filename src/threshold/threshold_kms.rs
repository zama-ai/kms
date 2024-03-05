use crate::anyhow_error_and_log;
use crate::core::der_types::{self, PrivateSigKey, PublicEncKey, PublicSigKey};
use crate::core::kms_core::BaseKmsStruct;
use crate::core::signcryption::signcrypt;
use crate::kms::kms_endpoint_server::{KmsEndpoint, KmsEndpointServer};
use crate::kms::{
    DecryptionRequest, DecryptionResponse, FheType, ReencryptionRequest, ReencryptionResponse,
};
use crate::rpc::kms_rpc::{
    handle_potential_err, process_response, some_or_err, validate_decrypt_req,
    validate_reencrypt_req, CURRENT_FORMAT_VERSION,
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
    combine128, to_large_ciphertext_block, BootstrappingKey, SecretKeyShare, ThresholdLWEParameters,
};
use distributed_decryption::networking::grpc::GrpcNetworkingManager;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use serde_asn1_der::to_vec;
use std::fmt;
use std::net::SocketAddr;
use tfhe::core_crypto::entities::LweCiphertextOwned;
use tfhe::integer::IntegerRadixCiphertext;
use tfhe::{FheUint16, FheUint32, FheUint4, FheUint64, FheUint8};
use tokio::task::AbortHandle;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

// Jump between the webserver being externally visible and the webserver used to execute DDec
// TODO this should eventually be specified a bit better
pub const PORT_JUMP: u16 = 100;

/// Initialize a threshold KMS server using the DDec initialization protocol.
/// This MUST be done before the server is started.
pub async fn threshold_server_init(
    url: String,
    base_port: u16,
    parties: usize,
    threshold: u8,
    my_id: usize,
    keys: ThresholdKmsKeys,
) -> anyhow::Result<ThresholdKms> {
    let mut kms = ThresholdKms::new(keys, parties, threshold, &url, base_port, my_id)?;
    tracing::info!("Initializing threshold KMS server for {my_id}...");
    kms.init().await?;
    tracing::info!("Initialization done! Starting threshold KMS server for {my_id} ...");
    Ok(kms)
}

/// Starts threshold KMS server. Its port will be `base_port`+`my_id``.
/// This MUST be done after the server has been initialized.
pub async fn threshold_server_start(
    url: String,
    base_port: u16,
    my_id: usize,
    kms_server: ThresholdKms,
) -> anyhow::Result<()> {
    let port = base_port + (my_id as u16);
    let socket: std::net::SocketAddr = format!("{}:{}", url, port).parse()?;
    Server::builder()
        .add_service(KmsEndpointServer::new(kms_server))
        .serve(socket)
        .await?;
    tracing::info!("Started server {my_id}");
    Ok(())
}

/// Helper method for combining reconstructed messages after decryption.
// TODO is this the right place for this function? Should probably be in ddec. Related to this issue https://github.com/zama-ai/distributed-decryption/issues/352
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

impl FheType {
    pub fn deserialize_to_low_level(
        &self,
        serialized_high_level: &[u8],
    ) -> anyhow::Result<Vec<LweCiphertextOwned<u64>>> {
        let radix_ct = match self {
            FheType::Bool => {
                let hl_ct: FheUint8 = bincode::deserialize(serialized_high_level)?;
                let (radix_ct, _id) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint4 => {
                let hl_ct: FheUint4 = bincode::deserialize(serialized_high_level)?;
                let (radix_ct, _id) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint8 => {
                let hl_ct: FheUint8 = bincode::deserialize(serialized_high_level)?;
                let (radix_ct, _id) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint16 => {
                let hl_ct: FheUint16 = bincode::deserialize(serialized_high_level)?;
                let (radix_ct, _id) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint32 => {
                let hl_ct: FheUint32 = bincode::deserialize(serialized_high_level)?;
                let (radix_ct, _id) = hl_ct.into_raw_parts();
                radix_ct
            }
            FheType::Euint64 => {
                let hl_ct: FheUint64 = bincode::deserialize(serialized_high_level)?;
                let (radix_ct, _id) = hl_ct.into_raw_parts();
                radix_ct
            }
        };
        Ok(radix_ct
            .into_blocks()
            .into_iter()
            .map(|block| block.ct)
            .collect::<Vec<_>>())
    }
}

#[derive(Serialize, Deserialize)]
pub struct ThresholdKmsKeys {
    pub params: ThresholdLWEParameters,
    pub fhe_dec_key_share: SecretKeyShare,
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
    async fn inner_decrypt(
        &self,
        fhe_type: FheType,
        high_level_ct: &[u8],
    ) -> anyhow::Result<Vec<ResiduePoly<Z128>>> {
        // Deserialize the highlevel ciphertext into a low level ciphertext. Both the high level and
        // low level are over u64
        let low_level_ct_small = fhe_type.deserialize_to_low_level(high_level_ct)?;
        // Convert the low level ciphertext over u64 into a low level ciphertext over u128
        let ct_large = low_level_ct_small
            .par_iter()
            .map(|ct_block| to_large_ciphertext_block(&self.bsk, ct_block))
            .collect();
        let session_id = SessionId::new(&low_level_ct_small)?;
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
        tracing::info!("Server {} doing batch decrypt", self.my_id);
        let partial_dec = batch_partial_decrypt(&mut session, &self.fhe_dec_key_share, ct_large)?;
        let openeds = some_or_err(
            robust_opens_to_all(&session, &partial_dec, self.threshold as usize).await?,
            "Could not do reconstruction of opened values".to_string(),
        )?;
        tracing::info!("Server {} opened result", self.my_id);
        Ok(openeds)
    }

    async fn inner_reencrypt(
        &self,
        high_level_ct: &[u8],
        ct_type: FheType,
        digest: Vec<u8>,
        client_enc_key: &PublicEncKey,
        client_verf_key: &PublicSigKey,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let partial_dec = self.inner_decrypt(ct_type, high_level_ct).await?;
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
        tracing::info!("Completed reencyption of ciphertext");
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
        tracing::info!("Server {} validated reencryption request", self.my_id);
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
        tracing::info!("Server {} did reencryption ", self.my_id);
        Ok(Response::new(ReencryptionResponse {
            version: CURRENT_FORMAT_VERSION,
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
            self.inner_decrypt(fhe_type, &ciphertext).await,
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
            version: CURRENT_FORMAT_VERSION,
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
