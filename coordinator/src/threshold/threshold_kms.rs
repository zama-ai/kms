use crate::anyhow_error_and_log;
use crate::kms::CrsGenRequest;
use crate::kms::{coordinator_endpoint_server::CoordinatorEndpoint, RequestId};
use crate::kms::{
    DecryptionRequest, DecryptionResponse, FheType, KeyGenRequest, KeyGenResult,
    ReencryptionRequest, ReencryptionResponse,
};
use crate::rpc::central_rpc::{
    process_response, tonic_handle_potential_err, tonic_some_or_err, validate_decrypt_req,
    validate_reencrypt_req,
};
use crate::rpc::rpc_types::{
    BaseKms, DecryptionResponseSigPayload, Plaintext, RawDecryption, SigncryptionPayload,
    CURRENT_FORMAT_VERSION,
};
use crate::{
    cryptography::central_kms::BaseKmsStruct,
    kms::coordinator_endpoint_server::CoordinatorEndpointServer,
};
use crate::{
    cryptography::der_types::{self, PrivateSigKey, PublicEncKey, PublicSigKey},
    kms::CrsGenResult,
};
use crate::{cryptography::signcryption::signcrypt, kms::Empty};
use aes_prng::AesRng;
use alloy_sol_types::{Eip712Domain, SolStruct};
use distributed_decryption::algebra::base_ring::Z64;
use distributed_decryption::algebra::residue_poly::ResiduePoly128;
use distributed_decryption::computation::SessionId;
use distributed_decryption::execution::endpoints::decryption::{
    decrypt_using_noiseflooding, partial_decrypt_using_noiseflooding, Small,
};
use distributed_decryption::execution::runtime::session::{
    BaseSessionStruct, DecryptionMode, ParameterHandles, SessionParameters, SmallSession,
};
use distributed_decryption::execution::small_execution::prss::PRSSSetup;
use distributed_decryption::execution::{
    endpoints::keygen::PrivateKeySet, small_execution::agree_random::RealAgreeRandomWithAbort,
};
use distributed_decryption::execution::{
    runtime::party::{Identity, Role, RoleAssignment},
    tfhe_internals::switch_and_squash::SwitchAndSquashKey,
};
use distributed_decryption::networking::grpc::GrpcNetworkingManager;
use distributed_decryption::{
    choreography::NetworkingStrategy, execution::tfhe_internals::parameters::Ciphertext64,
};
use serde::{Deserialize, Serialize};
use serde_asn1_der::to_vec;
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use tfhe::{FheUint16, FheUint32, FheUint4, FheUint64, FheUint8};
use tokio::task::AbortHandle;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

// Jump between the webserver being externally visible and the webserver used to execute DDec
// TODO this should eventually be specified a bit better
pub const PORT_JUMP: u16 = 100;
pub const DECRYPTION_MODE: DecryptionMode = DecryptionMode::PRSSDecrypt;

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
        .add_service(CoordinatorEndpointServer::new(kms_server))
        .serve(socket)
        .await?;
    tracing::info!("Started server {my_id}");
    Ok(())
}

impl FheType {
    pub fn deserialize_to_low_level(
        &self,
        serialized_high_level: &[u8],
    ) -> anyhow::Result<Ciphertext64> {
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
            &FheType::Euint128 | &FheType::Euint160 => {
                return Err(anyhow_error_and_log(
                    "Euint128 or Euint160 are not supported yet!",
                ));
            }
        };
        Ok(radix_ct)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdFheKeys {
    pub private_keys: PrivateKeySet,
    pub sns_key: SwitchAndSquashKey,
}

#[derive(Serialize, Deserialize)]
pub struct ThresholdKmsKeys {
    pub fhe_keys: HashMap<String, ThresholdFheKeys>,
    pub sig_sk: PrivateSigKey,
    pub sig_pk: PublicSigKey,
}

pub struct ThresholdKms {
    fhe_keys: HashMap<String, ThresholdFheKeys>,
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
        let own_identity = tonic_some_or_err(
            role_assignment.get(&Role::indexed_by_one(my_id)),
            "Could not find my own identity".to_string(),
        )?;

        // TODO setup TLS
        let networking_manager = GrpcNetworkingManager::new(own_identity.to_owned(), None);
        let networking_server = networking_manager.new_server();
        let port = base_port + PORT_JUMP + (my_id as u16);
        let mut server = Server::builder();
        let router = server.add_service(networking_server);
        let addr: SocketAddr = format!("{url}:{port}").parse()?;
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
            Box::new(move |session_id, roles| networking_manager.make_session(session_id, roles));
        let base_kms = BaseKmsStruct::new(keys.sig_sk);
        Ok(ThresholdKms {
            fhe_keys: keys.fhe_keys,
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
        let own_identity = self.own_identity()?;
        // Assume we only have one epoch and start with session 1
        let session_id = SessionId(1);
        let networking = (self.networking_strategy)(session_id, self.role_assignments.clone());

        let parameters = SessionParameters::new(
            self.threshold,
            session_id,
            own_identity.clone(),
            self.role_assignments.clone(),
        )?;
        let mut base_session =
            BaseSessionStruct::new(parameters, networking, self.base_kms.new_rng()?)?;

        // TODO does this work with base session? we have a catch 22 otherwise
        self.prss_setup = Some(
            PRSSSetup::init_with_abort::<
                RealAgreeRandomWithAbort,
                AesRng,
                BaseSessionStruct<AesRng, SessionParameters>,
            >(&mut base_session)
            .await?,
        );
        Ok(())
    }

    pub fn own_identity(&self) -> anyhow::Result<Identity> {
        let id = tonic_some_or_err(
            self.role_assignments.get(&Role::indexed_by_one(self.my_id)),
            "Could not find my own identity in role assignments".to_string(),
        )?;
        Ok(id.to_owned())
    }

    pub fn shutdown(&self) {
        self.abort_handle.abort();
    }
}

impl BaseKms for ThresholdKms {
    fn verify_sig<T: Serialize>(
        payload: &T,
        signature: &der_types::Signature,
        verification_key: &PublicSigKey,
    ) -> bool {
        BaseKmsStruct::verify_sig(payload, signature, verification_key)
    }

    fn sign<T: Serialize>(&self, msg: &T) -> anyhow::Result<der_types::Signature> {
        self.base_kms.sign(msg)
    }

    fn get_verf_key(&self) -> PublicSigKey {
        self.base_kms.get_verf_key()
    }

    fn digest<T: fmt::Debug + Serialize>(msg: &T) -> anyhow::Result<Vec<u8>> {
        BaseKmsStruct::digest(&msg)
    }

    fn verify_sig_eip712<T: SolStruct>(
        payload: &T,
        domain: &Eip712Domain,
        signature: &der_types::Signature,
        verification_key: &PublicSigKey,
    ) -> bool {
        BaseKmsStruct::verify_sig_eip712(payload, domain, signature, verification_key)
    }

    fn sign_eip712<T: SolStruct>(
        &self,
        msg: &T,
        domain: &Eip712Domain,
    ) -> anyhow::Result<der_types::Signature> {
        self.base_kms.sign_eip712(msg, domain)
    }
}
impl ThresholdKms {
    async fn inner_decrypt(
        &self,
        fhe_type: FheType,
        ct: &[u8],
        key_handle: &str,
    ) -> anyhow::Result<Z64> {
        let (mut session, low_level_ct) = self.prepare_ddec_data(ct, fhe_type)?;
        let mut protocol = Small::new(session.clone());
        let id = session.own_identity();
        let keys = match self.fhe_keys.get(key_handle) {
            Some(keys) => keys,
            None => {
                return Err(anyhow_error_and_log(
                    "Key handle {key_handle} does not exist",
                ))
            }
        };
        let (partial_dec, _time) = decrypt_using_noiseflooding(
            &mut session,
            &mut protocol,
            &keys.sns_key,
            low_level_ct,
            &keys.private_keys,
            DECRYPTION_MODE,
            id,
        )
        .await?;
        tracing::info!("Server {} completed decryption", self.my_id);
        let session_id_string = format!("{}", session.session_id());
        let res = tonic_some_or_err(
            partial_dec.get(&session_id_string),
            "Result for the session does not exist".to_string(),
        )?;
        Ok(*res)
    }

    async fn inner_reencrypt(
        &self,
        ct: &[u8],
        fhe_type: FheType,
        digest: Vec<u8>,
        client_enc_key: &PublicEncKey,
        client_verf_key: &PublicSigKey,
        key_handle: &str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let (mut session, low_level_ct) = self.prepare_ddec_data(ct, fhe_type)?;
        let mut protocol = Small::new(session.clone());
        let keys = match self.fhe_keys.get(key_handle) {
            Some(keys) => keys,
            None => {
                return Err(anyhow_error_and_log(
                    "Key handle {key_handle} does not exist",
                ))
            }
        };
        let (partial_dec, _time) = partial_decrypt_using_noiseflooding(
            &mut session,
            &mut protocol,
            &keys.sns_key,
            low_level_ct,
            &keys.private_keys,
            DECRYPTION_MODE,
        )
        .await?;
        tracing::info!("Server {} did partial decryption", self.my_id);
        let session_id_string = format!("{}", session.session_id());
        let partial_dec = tonic_some_or_err(
            partial_dec.get(&session_id_string),
            "Result for the session does not exist".to_string(),
        )?;
        let partial_dec_serialized = serde_asn1_der::to_vec(&partial_dec)?;
        let signcryption_msg = SigncryptionPayload {
            raw_decryption: RawDecryption::new(partial_dec_serialized, fhe_type),
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

    /// helper function to prepare the data for ddec by deserializing the ciphertext and creating a
    /// session
    fn prepare_ddec_data(
        &self,
        ct: &[u8],
        fhe_type: FheType,
    ) -> anyhow::Result<(SmallSession<ResiduePoly128>, Ciphertext64)> {
        let low_level_ct = fhe_type.deserialize_to_low_level(ct)?;
        let session_id = SessionId::new(&low_level_ct)?;
        let networking = (self.networking_strategy)(session_id, self.role_assignments.clone());
        let own_identity = self.own_identity()?;
        let parameters = SessionParameters::new(
            self.threshold,
            session_id,
            own_identity.clone(),
            self.role_assignments.clone(),
        )?;
        let prss_setup =
            tonic_some_or_err(self.prss_setup.clone(), "No PRSS setup exists".to_string())?;
        let prss_state = prss_setup.new_prss_session_state(session_id);
        let session = SmallSession {
            base_session: BaseSessionStruct::new(parameters, networking, self.base_kms.new_rng()?)?,
            prss_state,
        };
        Ok((session, low_level_ct))
    }
}

#[tonic::async_trait]
impl CoordinatorEndpoint for ThresholdKms {
    async fn key_gen(&self, _request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
        todo!()
    }

    async fn get_key_gen_result(
        &self,
        _request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        todo!()
    }

    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let inner = request.into_inner();
        let (
            ciphertext,
            fhe_type,
            req_digest,
            client_enc_key,
            client_verf_key,
            servers_needed,
            key_handle,
        ) = tonic_handle_potential_err(
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
                &key_handle,
            )
            .await,
        )?;
        tracing::info!("Server {} did reencryption ", self.my_id);
        Ok(Response::new(ReencryptionResponse {
            version: CURRENT_FORMAT_VERSION,
            servers_needed,
            signcrypted_ciphertext: return_cipher,
            fhe_type: fhe_type.into(),
            digest: req_digest,
            verification_key: tonic_handle_potential_err(
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
        let (ciphertext, fhe_type, req_digest, servers_needed, key_handle) =
            tonic_handle_potential_err(
                validate_decrypt_req(&inner).await,
                format!("Invalid key in request {:?}", inner),
            )?;
        let raw_decryption = tonic_handle_potential_err(
            self.inner_decrypt(fhe_type, &ciphertext, &key_handle).await,
            format!("Decryption failed for request {:?}", inner),
        )?;
        let plaintext = Plaintext::new(raw_decryption.0 as u128, fhe_type);
        let decrypted_bytes = tonic_handle_potential_err(
            to_vec(&plaintext),
            format!(
                "Could not convert plaintext to bytes in request {:?}",
                inner
            ),
        )?;
        let server_verf_key = tonic_handle_potential_err(
            to_vec(&self.get_verf_key()),
            "Could not serialize server verification key".to_string(),
        )?;
        let sig_payload = DecryptionResponseSigPayload {
            version: CURRENT_FORMAT_VERSION,
            servers_needed,
            plaintext: decrypted_bytes,
            verification_key: server_verf_key,
            digest: req_digest,
        };
        let sig = tonic_handle_potential_err(
            self.sign(&sig_payload),
            format!("Could not sign payload {:?}", sig_payload),
        )?;
        Ok(Response::new(DecryptionResponse {
            signature: sig.sig.to_vec(),
            payload: Some(sig_payload.into()),
        }))
    }

    async fn crs_gen(&self, _request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
        todo!();
    }

    async fn get_crs_gen_result(
        &self,
        _request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        todo!();
    }
}
