use crate::consts::{MINIMUM_SESSIONS_PREPROC, SEC_PAR};
use crate::cryptography::central_kms::{compute_info_from_key, BaseKmsStruct};
use crate::cryptography::der_types::{self, PrivateSigKey, PublicEncKey, PublicSigKey};
use crate::cryptography::signcryption::signcrypt;
use crate::kms::coordinator_endpoint_server::{CoordinatorEndpoint, CoordinatorEndpointServer};
use crate::kms::{
    CrsGenRequest, CrsGenResult, DecryptionRequest, DecryptionResponse, DecryptionResponsePayload,
    Empty, FhePubKeyInfo, FheType, KeyGenPreprocRequest, KeyGenPreprocStatus,
    KeyGenPreprocStatusEnum, KeyGenRequest, KeyGenResult, ReencryptionRequest,
    ReencryptionResponse, RequestId,
};
use crate::rpc::central_rpc::{
    convert_key_response, retrieve_parameters, tonic_handle_potential_err, tonic_some_or_err,
    validate_decrypt_req, validate_reencrypt_req, validate_request_id,
};
use crate::rpc::rpc_types::PrivDataType;
use crate::rpc::rpc_types::{
    BaseKms, Plaintext, PubDataType, RawDecryption, SigncryptionPayload, CURRENT_FORMAT_VERSION,
};
use crate::storage::lazy_store_at_request_id;
use crate::storage::PublicStorage;
use crate::storage::{delete_at_request_id, read_all_data, store_at_request_id};
use crate::{anyhow_error_and_log, some_or_err};
use aes_prng::AesRng;
use alloy_sol_types::{Eip712Domain, SolStruct};
use anyhow::anyhow;
use distributed_decryption::algebra::base_ring::Z64;
use distributed_decryption::algebra::residue_poly::ResiduePoly128;
use distributed_decryption::choreography::NetworkingStrategy;
use distributed_decryption::execution::endpoints::decryption::{
    decrypt_using_noiseflooding, partial_decrypt_using_noiseflooding, Small,
};
use distributed_decryption::execution::endpoints::keygen::{
    distributed_keygen_z128, PrivateKeySet,
};
use distributed_decryption::execution::online::preprocessing::orchestrator::PreprocessingOrchestrator;
use distributed_decryption::execution::online::preprocessing::redis::RedisConf;
use distributed_decryption::execution::online::preprocessing::{
    create_memory_factory, create_redis_factory, DKGPreprocessing, PreprocessorFactory,
};
use distributed_decryption::execution::runtime::party::{Identity, Role, RoleAssignment};
use distributed_decryption::execution::runtime::session::{
    BaseSessionStruct, DecryptionMode, ParameterHandles, SessionParameters, SmallSession,
};
use distributed_decryption::execution::small_execution::agree_random::RealAgreeRandomWithAbort;
use distributed_decryption::execution::small_execution::prss::PRSSSetup;
use distributed_decryption::execution::tfhe_internals::parameters::{
    Ciphertext64, DKGParams, DKGParamsRegular, DKGParamsSnS,
};
use distributed_decryption::execution::tfhe_internals::switch_and_squash::SwitchAndSquashKey;
use distributed_decryption::execution::zk::ceremony::{
    compute_witness_dim, Ceremony, RealCeremony,
};
use distributed_decryption::networking::grpc::GrpcNetworkingManager;
use distributed_decryption::session_id::SessionId;
use itertools::Itertools;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use tfhe::{FheUint16, FheUint32, FheUint4, FheUint64, FheUint8};
use tokio::sync::{Mutex, RwLock, RwLockReadGuard};
use tokio::task::AbortHandle;
use tokio::time::Instant;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use super::meta_store::{HandlerStatus, MetaStore};

// Jump between the webserver being externally visible and the webserver used to execute DDec
// TODO this should eventually be specified a bit better
pub const PORT_JUMP: u16 = 100;
pub const DECRYPTION_MODE: DecryptionMode = DecryptionMode::PRSSDecrypt;

#[derive(Serialize, Deserialize, Clone)]
pub struct ThresholdConfig {
    pub url: String,
    pub base_port: u16,
    pub parties: usize,
    pub threshold: u8,
    pub dec_capacity: usize,
    pub min_dec_cache: usize,
    pub my_id: usize,
    pub timeout_secs: u64,
    pub preproc_redis_conf: Option<RedisConf>,
    pub num_sessions_preproc: Option<u16>,
}

impl ThresholdConfig {
    pub fn init_config(fname: &str) -> anyhow::Result<ThresholdConfig> {
        let config: ThresholdConfig = config::Config::builder()
            .add_source(config::File::with_name(fname))
            .add_source(config::Environment::with_prefix("KMS"))
            .build()?
            .try_deserialize()?;
        Ok(config)
    }
}

/// Initialize a threshold KMS server using the DDec initialization protocol.
/// This MUST be done before the server is started.
pub async fn threshold_server_init<
    PubS: PublicStorage + Sync + Send + 'static,
    PrivS: PublicStorage + Sync + Send + 'static,
>(
    config: ThresholdConfig,
    public_storage: PubS,
    private_storage: PrivS,
) -> anyhow::Result<ThresholdKms<PubS, PrivS>> {
    //If no RedisConf is provided, we just use in-memory storage for the preprocessing buckets.
    //NOTE: This should probably only be allowed for testing
    let factory = match config.preproc_redis_conf {
        None => create_memory_factory(),
        Some(conf) => create_redis_factory(format!("PARTY_{}", config.my_id), &conf),
    };
    let num_sessions_preproc = if let Some(x) = config.num_sessions_preproc {
        if x < MINIMUM_SESSIONS_PREPROC {
            MINIMUM_SESSIONS_PREPROC
        } else {
            x
        }
    } else {
        MINIMUM_SESSIONS_PREPROC
    };
    let mut kms = ThresholdKms::new(
        config.parties,
        config.threshold,
        config.dec_capacity,
        config.min_dec_cache,
        &config.url,
        config.base_port,
        config.my_id,
        factory,
        num_sessions_preproc,
        public_storage,
        private_storage,
    )
    .await?;

    tracing::info!("Initializing threshold KMS server for {}...", config.my_id);
    kms.init().await?;

    tracing::info!(
        "Initialization done! Starting threshold KMS server for {} ...",
        config.my_id
    );
    Ok(kms)
}

/// Starts threshold KMS server. Its port will be `base_port`+`my_id``.
/// This MUST be done after the server has been initialized.
pub async fn threshold_server_start<
    PubS: PublicStorage + Sync + Send + 'static,
    PrivS: PublicStorage + Sync + Send + 'static,
>(
    url: String,
    base_port: u16,
    timeout_secs: u64,
    kms_server: ThresholdKms<PubS, PrivS>,
) -> anyhow::Result<()> {
    let my_id = kms_server.my_id;
    let port = base_port + (my_id as u16);
    let socket: std::net::SocketAddr = format!("{}:{}", url, port).parse()?;
    tracing::info!("Starting server {my_id}");
    Server::builder()
        .timeout(tokio::time::Duration::from_secs(timeout_secs))
        .add_service(CoordinatorEndpointServer::new(kms_server))
        .serve(socket)
        .await?;
    Ok(())
}

// TODO should be moved to rpc_types.rs
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
    pub fhe_keys: HashMap<RequestId, ThresholdFheKeys>,
    pub sig_sk: PrivateSigKey,
    pub sig_pk: PublicSigKey,
}

// Servers needed, request digest, and resultant plaintext
type DecMetaStore = (u32, Vec<u8>, Plaintext);
// Servers needed, request digest, fhe type of encryption and resultant partial decryption
type ReencMetaStore = (u32, Vec<u8>, FheType, Vec<u8>);
// Hashmap of `PubDataType` to the corresponding `FhePubKeyInfo` information for all the different
// public keys
type DkgMetaStore = HashMap<PubDataType, FhePubKeyInfo>;
// digest (the 160-bit hex-encoded value, computed using compute_info/handle) and the signature on
// the handle
type CrsMetaStore = (String, Vec<u8>);
type BucketMetaStore = Box<dyn DKGPreprocessing<ResiduePoly128>>;

pub struct ThresholdKms<
    PubS: PublicStorage + Sync + Send + 'static,
    PrivS: PublicStorage + Sync + Send + 'static,
> {
    // NOTE: To avoid deadlocks the fhe_keys SHOULD NOT be written to while holding a meta storage
    // mutex!
    fhe_keys: Arc<RwLock<HashMap<RequestId, ThresholdFheKeys>>>,
    base_kms: BaseKmsStruct,
    threshold: u8,
    my_id: usize,
    role_assignments: RoleAssignment,
    networking_strategy: NetworkingStrategy,
    abort_handle: AbortHandle,
    // TODO eventually add mode to allow for nlarge as well.
    prss_setup: Option<PRSSSetup<ResiduePoly128>>,
    preproc_buckets: Arc<RwLock<MetaStore<BucketMetaStore>>>,
    preproc_factory: Arc<Mutex<Box<dyn PreprocessorFactory>>>,
    num_sessions_preproc: u16,
    // NOTE: To avoid deadlocks the public_storage MUST ALWAYS be accessed BEFORE the private_storage when both are needed concurrently
    public_storage: Arc<Mutex<PubS>>,
    private_storage: Arc<Mutex<PrivS>>,
    crs_meta_store: Arc<RwLock<MetaStore<CrsMetaStore>>>,
    dkg_pubinfo_meta_store: Arc<RwLock<MetaStore<DkgMetaStore>>>,
    dec_meta_store: Arc<RwLock<MetaStore<DecMetaStore>>>,
    reenc_meta_store: Arc<RwLock<MetaStore<ReencMetaStore>>>,
}

impl<PubS: PublicStorage + Sync + Send + 'static, PrivS: PublicStorage + Sync + Send + 'static>
    ThresholdKms<PubS, PrivS>
{
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        parties: usize,
        threshold: u8,
        dec_capacity: usize,
        min_dec_cache: usize,
        url: &str,
        base_port: u16,
        my_id: usize,
        preproc_factory: Box<dyn PreprocessorFactory>,
        num_sessions_preproc: u16,
        public_storage: PubS,
        private_storage: PrivS,
    ) -> anyhow::Result<Self> {
        let sks: HashMap<RequestId, PrivateSigKey> =
            read_all_data(&private_storage, &PrivDataType::SigningKey.to_string()).await?;
        let sk: PrivateSigKey = some_or_err(
            sks.values().collect_vec().first(),
            "There is no private signing key stored".to_string(),
        )?
        .to_owned()
        .to_owned();
        let key_info: HashMap<RequestId, ThresholdFheKeys> =
            read_all_data(&private_storage, &PrivDataType::FheKeyInfo.to_string()).await?;
        let cs: HashMap<RequestId, CrsMetaStore> =
            read_all_data(&private_storage, &PrivDataType::CrsInfo.to_string()).await?;
        let cs_w_status: HashMap<RequestId, HandlerStatus<CrsMetaStore>> = cs
            .iter()
            .map(|(id, crs)| (id.to_owned(), HandlerStatus::Done(crs.to_owned())))
            .collect();

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

        tracing::info!("Starting ddec for {}.", own_identity);
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
        let base_kms = BaseKmsStruct::new(sk);
        Ok(ThresholdKms {
            fhe_keys: Arc::new(RwLock::new(key_info)),
            base_kms,
            threshold,
            my_id,
            role_assignments: role_assignment,
            networking_strategy,
            abort_handle: ddec_handle.abort_handle(),
            prss_setup: None,
            preproc_buckets: Arc::new(RwLock::new(MetaStore::new_unlimited())),
            preproc_factory: Arc::new(Mutex::new(preproc_factory)),
            num_sessions_preproc,
            public_storage: Arc::new(Mutex::new(public_storage)),
            private_storage: Arc::new(Mutex::new(private_storage)),
            crs_meta_store: Arc::new(RwLock::new(MetaStore::new_from_map(cs_w_status))),
            dkg_pubinfo_meta_store: Arc::new(RwLock::new(MetaStore::new_unlimited())),
            dec_meta_store: Arc::new(RwLock::new(MetaStore::new(dec_capacity, min_dec_cache))),
            reenc_meta_store: Arc::new(RwLock::new(MetaStore::new(dec_capacity, min_dec_cache))),
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
        tracing::info!("Starting PRSS for {}.", own_identity);
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

    pub fn my_id(&self) -> usize {
        self.my_id
    }

    pub fn shutdown(&self) {
        self.abort_handle.abort();
    }
}

impl<PubS: PublicStorage + Sync + Send + 'static, PrivS: PublicStorage + Sync + Send + 'static>
    BaseKms for ThresholdKms<PubS, PrivS>
{
    fn verify_sig<T: Serialize + AsRef<[u8]>>(
        payload: &T,
        signature: &der_types::Signature,
        verification_key: &PublicSigKey,
    ) -> bool {
        BaseKmsStruct::verify_sig(payload, signature, verification_key)
    }

    fn sign<T: Serialize + AsRef<[u8]>>(&self, msg: &T) -> anyhow::Result<der_types::Signature> {
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
impl<PubS: PublicStorage + Sync + Send + 'static, PrivS: PublicStorage + Sync + Send + 'static>
    ThresholdKms<PubS, PrivS>
{
    /// Helper method for decryption which carries out the actual threshold decryption using noise
    /// flooding.
    async fn inner_decrypt(
        session: &mut SmallSession<ResiduePoly128>,
        protocol: &mut Small,
        ct: &[u8],
        fhe_type: FheType,
        key_handle: &RequestId,
        fhe_keys: RwLockReadGuard<'_, HashMap<RequestId, ThresholdFheKeys>>,
    ) -> anyhow::Result<Z64> {
        let low_level_ct = fhe_type.deserialize_to_low_level(ct)?;
        let keys = match fhe_keys.get(key_handle) {
            Some(keys) => keys,
            None => {
                return Err(anyhow_error_and_log(format!(
                    "Key handle {key_handle} does not exist"
                )))
            }
        };
        let raw_decryption = match decrypt_using_noiseflooding(
            session,
            protocol,
            &keys.sns_key,
            low_level_ct,
            &keys.private_keys,
            DECRYPTION_MODE,
            session.own_identity(),
        )
        .await
        {
            Ok((partial_dec, time)) => {
                let raw_decryption = match partial_dec.get(&session.session_id().to_string()) {
                    Some(raw_decryption) => *raw_decryption,
                    None => {
                        return Err(anyhow!(
                            "Decryption with session ID {} could not be retrived",
                            session.session_id().to_string()
                        ))
                    }
                };
                tracing::info!(
                    "Decryption completed. Inner thread took {:?} ms",
                    time.as_millis()
                );
                raw_decryption
            }
            Err(e) => return Err(anyhow!("Failed decryption with noiseflooding: {e}")),
        };
        Ok(raw_decryption)
    }

    /// Helper method for reencryptin which carries out the actual threshold decryption using noise
    /// flooding.
    #[allow(clippy::too_many_arguments)]
    async fn inner_reencrypt(
        session: &mut SmallSession<ResiduePoly128>,
        protocol: &mut Small,
        rng: &mut (impl CryptoRng + RngCore),
        ct: &[u8],
        fhe_type: FheType,
        link: Vec<u8>,
        key_handle: &RequestId,
        client_enc_key: &PublicEncKey,
        client_verf_key: &PublicSigKey,
        sig_key: Arc<PrivateSigKey>,
        fhe_keys: RwLockReadGuard<'_, HashMap<RequestId, ThresholdFheKeys>>,
    ) -> anyhow::Result<Vec<u8>> {
        let low_level_ct = fhe_type.deserialize_to_low_level(ct)?;
        let keys = match fhe_keys.get(key_handle) {
            Some(keys) => keys,
            None => return Err(anyhow!("Could not deserialize meta store")),
        };
        let partial_signcryption = match partial_decrypt_using_noiseflooding(
            session,
            protocol,
            &keys.sns_key,
            low_level_ct,
            &keys.private_keys,
            DECRYPTION_MODE,
        )
        .await
        {
            Ok((partial_dec_map, time)) => {
                let partial_signcryption = match partial_dec_map
                    .get(&session.session_id().to_string())
                {
                    Some(partial_dec) => {
                        let partial_dec_serialized = serde_asn1_der::to_vec(&partial_dec)?;
                        let signcryption_msg = SigncryptionPayload {
                            raw_decryption: RawDecryption::new(partial_dec_serialized, fhe_type),
                            link,
                        };
                        let enc_res = signcrypt(
                            rng,
                            &serde_asn1_der::to_vec(&signcryption_msg)?,
                            client_enc_key,
                            client_verf_key,
                            &sig_key,
                        )?;
                        serde_asn1_der::to_vec(&enc_res)?
                    }
                    None => {
                        return Err(anyhow!(
                            "Reencryption with session ID {} could not be retrived",
                            session.session_id().to_string()
                        ))
                    }
                };
                tracing::info!(
                    "Reencryption completed. Inner thread took {:?} ms",
                    time.as_millis()
                );
                partial_signcryption
            }
            Err(e) => return Err(anyhow!("Failed reencryption with noiseflooding: {e}")),
        };
        Ok(partial_signcryption)
    }

    async fn inner_crs_gen(&self, req_id: &RequestId, witness_dim: usize) -> anyhow::Result<()> {
        {
            let mut guarded_meta_store = self.crs_meta_store.write().await;
            guarded_meta_store.insert(req_id)?;
        }

        let session_id = SessionId(req_id.clone().try_into()?);
        let mut session = self.prepare_ddec_data_from_sessionid(session_id)?;
        let meta_store = Arc::clone(&self.crs_meta_store);
        let public_storage = Arc::clone(&self.public_storage);
        let private_storage = Arc::clone(&self.private_storage);
        let owned_req_id = req_id.to_owned();

        // we need to clone the signature key because it needs to be given
        // the thread that spawns the CRS ceremony
        let sig_key = self.base_kms.sig_key.clone();

        // we do not need to hold the handle,
        // the result of the computation is tracked the crs_meta_store
        let _handle = tokio::spawn(async move {
            let crs_start_timer = Instant::now();
            let real_ceremony = RealCeremony::default();
            let res_pp = real_ceremony
                .execute::<Z64, _, _>(&mut session, witness_dim)
                .await;
            let res_info_pp =
                res_pp.and_then(|pp| compute_info_from_key(&sig_key, &pp).map(|info| (info, pp)));
            let f = || async {
                // we take these two locks at the same time in case there are races
                // on return, the two locks should be dropped in the correct order also
                let mut pub_storage = public_storage.lock().await;
                let mut priv_storage = private_storage.lock().await;

                let (info, pp) = match res_info_pp {
                    Ok(info_pp) => info_pp,
                    Err(e) => {
                        let mut guarded_meta_store = meta_store.write().await;
                        // We cannot do much if updating the storage fails at this point...
                        let _ = guarded_meta_store
                            .update(&owned_req_id, HandlerStatus::Error(e.to_string()));
                        return;
                    }
                };

                let crs_meta_data = (info.key_handle, info.signature);
                if store_at_request_id(
                    &mut (*priv_storage),
                    &owned_req_id,
                    &crs_meta_data,
                    &PrivDataType::CrsInfo.to_string(),
                )
                .await
                .is_ok()
                // Only store the CRS if no other server has already stored it
                    && lazy_store_at_request_id(
                        &mut (*pub_storage),
                        &owned_req_id,
                        &pp,
                        &PubDataType::CRS.to_string(),
                    )
                    .await
                    .is_ok()
                {
                    let mut guarded_meta_store = meta_store.write().await;
                    // We cannot do much if updating the storage fails at this point...
                    let _ = guarded_meta_store
                        .update(&owned_req_id, HandlerStatus::Done(crs_meta_data));
                } else {
                    // Try to delete stored data to avoid anything dangling
                    // Ignore any failure to delete something. It might be because the data exist.
                    // In any case, we can't do much
                    let _ = delete_at_request_id(
                        &mut (*pub_storage),
                        &owned_req_id,
                        &PubDataType::CRS.to_string(),
                    )
                    .await;
                    let _ = delete_at_request_id(
                        &mut (*priv_storage),
                        &owned_req_id,
                        &PrivDataType::CrsInfo.to_string(),
                    )
                    .await;
                    {
                        let mut guarded_meta_store = meta_store.write().await;
                        // We cannot do much if updating the storage fails at this point...
                        let _ = guarded_meta_store.update(
                            &owned_req_id,
                            HandlerStatus::Error(format!(
                                "failed to store data to public storage for ID {}",
                                owned_req_id
                            )),
                        );
                    }
                }
            };
            let _ = f().await;

            let crs_stop_timer = Instant::now();
            let elapsed_time = crs_stop_timer.duration_since(crs_start_timer);
            tracing::info!(
                "CRS stored. CRS ceremony time was {:?} ms",
                (elapsed_time).as_millis()
            );
        });
        Ok(())
    }

    fn prepare_ddec_data_from_requestid(
        &self,
        request_id: &RequestId,
    ) -> anyhow::Result<SmallSession<ResiduePoly128>> {
        self.prepare_ddec_data_from_sessionid(SessionId(request_id.clone().try_into()?))
    }

    fn prepare_ddec_data_from_sessionid(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<SmallSession<ResiduePoly128>> {
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
        Ok(session)
    }

    async fn launch_dkg_preproc(
        &self,
        dkg_params: DKGParams,
        request_id: RequestId,
    ) -> anyhow::Result<()> {
        {
            let mut guarded_meta_store = self.preproc_buckets.write().await;
            guarded_meta_store.insert(&request_id)?;
        }

        fn create_sessions(
            base_sessions: Vec<BaseSessionStruct<AesRng, SessionParameters>>,
            prss_setup: PRSSSetup<ResiduePoly128>,
        ) -> Vec<SmallSession<ResiduePoly128>> {
            base_sessions
                .into_iter()
                .map(|base_session| {
                    let prss_state = prss_setup.new_prss_session_state(base_session.session_id());
                    SmallSession::new_from_prss_state(base_session, prss_state).unwrap()
                })
                .collect_vec()
        }
        //Derive a sequence of sessionId from request_id
        let session_id: u128 = request_id.clone().try_into()?;
        let own_identity = self.own_identity()?;
        let my_id = self.my_id;
        let base_sessions: Vec<_> = (session_id..session_id + self.num_sessions_preproc as u128)
            .map(|sid| {
                let session_id = SessionId(sid);
                let params = SessionParameters::new(
                    self.threshold,
                    session_id,
                    own_identity.clone(),
                    self.role_assignments.clone(),
                )?;
                let networking =
                    (self.networking_strategy)(session_id, self.role_assignments.clone());

                BaseSessionStruct::new(params, networking, self.base_kms.new_rng()?)
            })
            .try_collect()?;

        let factory = Arc::clone(&self.preproc_factory);
        let bucket_store = Arc::clone(&self.preproc_buckets);

        let prss_setup =
            tonic_some_or_err(self.prss_setup.clone(), "No PRSS setup exists".to_string())?;
        //NOTE: For now we just discard the handle, we can check status with get_preproc_status
        // endpoint
        let _handle = tokio::spawn(async move {
            let sessions = create_sessions(base_sessions, prss_setup);
            let orchestrator = {
                let mut factory_guard = factory.lock().await;
                let factory = factory_guard.as_mut();
                PreprocessingOrchestrator::<ResiduePoly128>::new(factory, dkg_params).unwrap()
            };
            tracing::info!("Starting Preproc Orchestration on P[{my_id}]");
            let preproc_result = orchestrator
                .orchestrate_small_session_dkg_processing(sessions)
                .await;
            //write the preproc handle to the bucket store
            let handle_update = match preproc_result {
                Ok((_, preproc_handle)) => HandlerStatus::Done(preproc_handle),
                Err(error) => HandlerStatus::Error(error.to_string()),
            };
            let mut guarded_meta_store = bucket_store.write().await;
            // We cannot do much if updating the storage fails at this point...
            let _ = guarded_meta_store.update(&request_id, handle_update);
            tracing::info!("Preproc Finished P[{my_id}]");
        });
        Ok(())
    }

    async fn launch_dkg(
        &self,
        dkg_params: DKGParams,
        mut preproc_handle: Box<dyn DKGPreprocessing<ResiduePoly128>>,
        req_id: RequestId,
    ) -> anyhow::Result<()> {
        //Update status
        {
            let mut guarded_meta_store = self.dkg_pubinfo_meta_store.write().await;
            guarded_meta_store.insert(&req_id)?;
        }

        //Create the base session necessary to run the DKG
        let mut base_session = {
            let session_id = SessionId(req_id.clone().try_into()?);
            let own_identity = self.own_identity()?;
            let params = SessionParameters::new(
                self.threshold,
                session_id,
                own_identity,
                self.role_assignments.clone(),
            )?;
            let networking = (self.networking_strategy)(session_id, self.role_assignments.clone());
            BaseSessionStruct::new(params, networking, self.base_kms.new_rng()?)?
        };

        //Clone all the Arcs to give them to the tokio thread
        let meta_store = Arc::clone(&self.dkg_pubinfo_meta_store);
        let public_storage = Arc::clone(&self.public_storage);
        let private_storage = Arc::clone(&self.private_storage);
        let sig_key = Arc::clone(&self.base_kms.sig_key);
        let fhe_keys = Arc::clone(&self.fhe_keys);

        //Start the async dkg job
        // TODO the following code could be simplified with a helper method similar to inner_decrypt
        let _handle = tokio::spawn(async move {
            //Actually do the dkg
            let dkg_res =
                distributed_keygen_z128(&mut base_session, preproc_handle.as_mut(), dkg_params)
                    .await;

            //Make sure the dkg ended nicely
            let (pub_key_set, private_keys) = match dkg_res {
                Ok((pk, sk)) => (pk, sk),
                Err(e) => {
                    //If dkg errored out, update status
                    let mut guarded_meta_storage = meta_store.write().await;
                    // We cannot do much if updating the storage fails at this point...
                    let _ =
                        guarded_meta_storage.update(&req_id, HandlerStatus::Error(e.to_string()));
                    return;
                }
            };

            //Make sure we do have a SnS key
            let sns_key = match pub_key_set.sns_key.clone() {
                Some(sns_key) => sns_key,
                None => {
                    //If sns key is missing, update status
                    let mut guarded_meta_storage = meta_store.write().await;
                    // We cannot do much if updating the storage fails at this point...
                    let _ = guarded_meta_storage
                        .update(&req_id, HandlerStatus::Error("Missing SNS key".to_string()));
                    return;
                }
            };

            //Compute all the info required for storing
            let pub_key_info = compute_info_from_key(&sig_key, &pub_key_set.public_key);
            let serv_key_info = compute_info_from_key(&sig_key, &pub_key_set.server_key);
            let sns_key_info = compute_info_from_key(&sig_key, &sns_key);
            //Make sure we did manage to compute the info
            let info = match (pub_key_info, serv_key_info, sns_key_info) {
                (Ok(pub_key_info), Ok(serv_key_info), Ok(sns_key_info)) => {
                    let mut info = HashMap::new();
                    info.insert(PubDataType::PublicKey, pub_key_info);
                    info.insert(PubDataType::ServerKey, serv_key_info);
                    //Do we really have to do it also for sns key ?
                    //afaict central does it, but then not used in store_public_keys
                    info.insert(PubDataType::SnsKey, sns_key_info);
                    info
                }
                _ => {
                    //If failed to compute some info, update status
                    let mut guarded_meta_storage = meta_store.write().await;
                    // We cannot do much if updating the storage fails at this point...
                    let _ = guarded_meta_storage.update(
                        &req_id,
                        HandlerStatus::Error("Failed to compute key info".to_string()),
                    );
                    return;
                }
            };

            //Take lock on all the storage at once, so we either update everything or nothing
            let mut pub_storage = public_storage.lock().await;
            let mut priv_storage = private_storage.lock().await;

            let private_key_data = ThresholdFheKeys {
                private_keys,
                sns_key: sns_key.clone(),
            };
            //Try to store the new data
            if store_at_request_id(
                &mut (*priv_storage),
                &req_id,
                &private_key_data,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await
            .is_ok()
            // Only store the public keys if no other server has already stored them
                && lazy_store_at_request_id(
                    &mut (*pub_storage),
                    &req_id,
                    &pub_key_set.public_key,
                    &PubDataType::PublicKey.to_string(),
                ).await
                .is_ok()
                && lazy_store_at_request_id(
                    &mut (*pub_storage),
                    &req_id,
                    &pub_key_set.server_key,
                    &PubDataType::ServerKey.to_string(),
                )
                .await
                .is_ok()
                && lazy_store_at_request_id(
                    &mut (*pub_storage),
                    &req_id,
                    &sns_key,
                    &PubDataType::SnsKey.to_string(),
                )
                .await
                .is_ok()
            {
                {
                    let mut guarded_fhe_keys = fhe_keys.write().await;
                    guarded_fhe_keys.insert(req_id.clone(), private_key_data);
                }
                //If everything succeeded, update state and store private key
                {
                    let mut guarded_meta_storage = meta_store.write().await;
                    // We cannot do much if updating the storage fails at this point...
                    let _ = guarded_meta_storage.update(&req_id, HandlerStatus::Done(info));
                }
                tracing::info!("Finished DKG for Request Id {req_id}.");
            } else {
                // Try to delete stored data to avoid anything dangling
                // Ignore any failure to delete something. It might be because the data exist. In
                // any case, we can't do much
                let _ = delete_at_request_id(
                    &mut (*pub_storage),
                    &req_id,
                    &PubDataType::PublicKey.to_string(),
                )
                .await;
                let _ = delete_at_request_id(
                    &mut (*pub_storage),
                    &req_id,
                    &PubDataType::ServerKey.to_string(),
                )
                .await;
                let _ = delete_at_request_id(
                    &mut (*pub_storage),
                    &req_id,
                    &PubDataType::SnsKey.to_string(),
                )
                .await;
                let _ = delete_at_request_id(
                    &mut (*priv_storage),
                    &req_id,
                    &PrivDataType::FheKeyInfo.to_string(),
                )
                .await;
                //If writing to public store failed, update status
                {
                    let mut guarded_meta_storage = meta_store.write().await;
                    // We cannot do much if updating the storage fails at this point...
                    let _ = guarded_meta_storage.update(
                        &req_id,
                        HandlerStatus::Error(
                            "Failed to write the public key to public store".to_string(),
                        ),
                    );
                }
            }
        });
        Ok(())
    }
}

#[tonic::async_trait]
impl<PubS: PublicStorage + Sync + Send + 'static, PrivS: PublicStorage + Sync + Send + 'static>
    CoordinatorEndpoint for ThresholdKms<PubS, PrivS>
{
    async fn key_gen_preproc(
        &self,
        request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
        let inner = request.into_inner();
        let request_id = tonic_some_or_err(
            inner.request_id.clone(),
            "Request ID is not set".to_string(),
        )?;

        // ensure the request ID is valid
        if !request_id.is_valid() {
            tracing::warn!("Request ID {} is not valid!", request_id.to_string());
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Request ID {} is not valid!", request_id),
            ));
        }

        //Retrieve the DKG parameters
        let params = tonic_handle_potential_err(
            retrieve_parameters(inner.params).await,
            "Parameter choice is not recognized".to_string(),
        )?;

        let dkg_params = DKGParams::WithSnS(DKGParamsSnS {
            regular_params: DKGParamsRegular {
                sec: SEC_PAR,
                ciphertext_parameters: params.ciphertext_parameters,
                flag: true,
            },
            sns_params: params.sns_parameters,
        });

        //Ensure there's no entry in preproc buckets for that request_id
        let entry_exists = {
            let map = self.preproc_buckets.read().await;
            map.exists(&request_id)
        };

        //If the entry did not exist before, start the preproc
        if !entry_exists {
            tracing::info!("Starting preproc generation for Request ID {}", request_id);
            tonic_handle_potential_err(self.launch_dkg_preproc(dkg_params, request_id.clone()).await, format!("Error launching dkg preprocessing for Request ID {request_id} and parameters {:?}",dkg_params))?;
        } else {
            tracing::warn!(
                "Tried to generate preproc multiple times for the same Request ID {} -- skipped it!",
                request_id
            );
        }
        Ok(Response::new(Empty {}))
    }

    async fn get_preproc_status(
        &self,
        request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<KeyGenPreprocStatus>, Status> {
        let inner = request.into_inner();
        let request_id = tonic_some_or_err(
            inner.request_id.clone(),
            "Request ID is not set".to_string(),
        )?;
        let response = {
            let map = self.preproc_buckets.read().await;
            match map.retrieve(&request_id) {
                None => {
                    tracing::warn!(
                        "Requesting status for request id that does not exist {request_id}"
                    );
                    KeyGenPreprocStatusEnum::Missing
                }
                Some(HandlerStatus::Error(e)) => {
                    tracing::warn!(
                        "Error while generating keygen preproc for request id {request_id} : {e}"
                    );
                    KeyGenPreprocStatusEnum::Error
                }
                Some(HandlerStatus::Started) => {
                    tracing::info!("Preproc for request id {request_id} is in progress.");
                    KeyGenPreprocStatusEnum::InProgress
                }
                Some(HandlerStatus::Done(_)) => {
                    tracing::info!("Preproc for request id {request_id} is finished.");
                    KeyGenPreprocStatusEnum::Finished
                }
            }
        };
        Ok(Response::new(KeyGenPreprocStatus {
            result: response.into(),
        }))
    }

    async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
        let inner = request.into_inner();
        let request_id = tonic_some_or_err(
            inner.request_id.clone(),
            "Request ID is not set".to_string(),
        )?;
        // ensure the request ID is valid
        if !request_id.is_valid() {
            tracing::warn!("Request ID {} is not valid!", request_id.to_string());
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Request ID {} is not valid!", request_id),
            ));
        }

        let storage = Arc::clone(&self.public_storage);
        {
            let storage = storage.lock().await;
            // TODO I don't think we need to do this check since the key will only be stored if it
            // is already persisted in dkg_pubinfo_meta_store
            if tonic_handle_potential_err(
                storage
                    .data_exists(&tonic_handle_potential_err(
                        storage.compute_url(
                            &request_id.to_string(),
                            &PubDataType::PublicKey.to_string(),
                        ),
                        "Could not compute url for public key".to_string(),
                    )?)
                    .await,
                "Could not validate if the public key exist".to_string(),
            )? || tonic_handle_potential_err(
                storage
                    .data_exists(&tonic_handle_potential_err(
                        storage.compute_url(
                            &request_id.to_string(),
                            &PubDataType::ServerKey.to_string(),
                        ),
                        "Could not compute url for server key".to_string(),
                    )?)
                    .await,
                "Could not validate if the server key exist".to_string(),
            )? || tonic_handle_potential_err(
                storage
                    .data_exists(&tonic_handle_potential_err(
                        storage
                            .compute_url(&request_id.to_string(), &PubDataType::SnsKey.to_string()),
                        "Could not compute url for SnS key".to_string(),
                    )?)
                    .await,
                "Could not validate if the SnS key exist".to_string(),
            )? {
                tracing::warn!(
                    "Keys with request ID {} already exist!",
                    request_id.to_string()
                );
                return Err(tonic::Status::new(
                    tonic::Code::AlreadyExists,
                    format!("Keys with request ID {} already exist!", request_id),
                ));
            }
        }

        //Retrieve kg params and preproc_id
        let params = tonic_handle_potential_err(
            retrieve_parameters(inner.params).await,
            "Parameter choice is not recognized".to_string(),
        )?;
        let dkg_params = DKGParams::WithSnS(DKGParamsSnS {
            regular_params: DKGParamsRegular {
                sec: SEC_PAR,
                ciphertext_parameters: params.ciphertext_parameters,
                flag: true,
            },
            sns_params: params.sns_parameters,
        });

        let preproc_id = tonic_some_or_err(
            inner.preproc_id.clone(),
            "Request ID is not set".to_string(),
        )?;

        //separate scope to get mutex on preproc storage
        let preproc_entry = {
            let mut map = self.preproc_buckets.write().await;
            let preproc = map.delete(&preproc_id);
            handle_res_mapping(preproc, &preproc_id, "Preprocessing")?
        };
        tonic_handle_potential_err(
            self.launch_dkg(dkg_params, preproc_entry, request_id.clone())
                .await,
            format!("Error launching dkg for request ID {request_id}"),
        )?;

        //Always answer with Empty
        Ok(Response::new(Empty {}))
    }

    async fn get_key_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<KeyGenResult>, Status> {
        let request_id = request.into_inner();
        validate_request_id(&request_id)?;
        let guarded_meta_store = self.dkg_pubinfo_meta_store.read().await;
        let res = handle_res_mapping(
            guarded_meta_store.retrieve(&request_id).cloned(),
            &request_id,
            "DKG",
        )?;
        Ok(Response::new(KeyGenResult {
            request_id: Some(request_id),
            key_results: convert_key_response(res),
        }))
    }

    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let inner = request.into_inner();
        let (
            ciphertext,
            fhe_type,
            link,
            client_enc_key,
            client_verf_key,
            servers_needed,
            key_id,
            req_id,
        ) = tonic_handle_potential_err(
            validate_reencrypt_req(&inner).await,
            format!("Invalid reencryption request {:?}", inner),
        )?;
        {
            let mut guarded_meta_store = self.reenc_meta_store.write().await;
            tonic_handle_potential_err(
                guarded_meta_store.insert(&req_id),
                "Could not insert reencryption request".to_string(),
            )?;
        }

        let mut session = tonic_handle_potential_err(
            self.prepare_ddec_data_from_requestid(&req_id),
            "Could not prepare ddec data".to_string(),
        )?;
        let mut protocol = Small::new(session.clone());
        let meta_store = Arc::clone(&self.reenc_meta_store);
        let fhe_keys = Arc::clone(&self.fhe_keys);
        let mut rng = tonic_handle_potential_err(
            self.base_kms.new_rng(),
            "Could not get a new RNG".to_string(),
        )?;
        let sig_key = Arc::clone(&self.base_kms.sig_key);

        // we do not need to hold the handle,
        // the result of the computation is tracked the crs_meta_store
        let _handle = tokio::spawn(async move {
            let mut guarded_meta_store = meta_store.write().await;
            let fhe_keys_rlock = fhe_keys.read().await;
            match Self::inner_reencrypt(
                &mut session,
                &mut protocol,
                &mut rng,
                &ciphertext,
                fhe_type,
                link.clone(),
                &key_id,
                &client_enc_key,
                &client_verf_key,
                sig_key,
                fhe_keys_rlock,
            )
            .await
            {
                Ok(partial_dec) => {
                    // We cannot do much if updating the storage fails at this point...
                    let _ = guarded_meta_store.update(
                        &req_id,
                        HandlerStatus::Done((servers_needed, link, fhe_type, partial_dec)),
                    );
                }
                Result::Err(e) => {
                    // We cannot do much if updating the storage fails at this point...
                    let _ = guarded_meta_store.update(
                        &req_id,
                        HandlerStatus::Error(format!("Failed decryption: {e}")),
                    );
                }
            }
        });
        Ok(Response::new(Empty {}))
    }

    async fn get_reencrypt_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let request_id = request.into_inner();
        if !request_id.is_valid() {
            tracing::warn!(
                "The value {} is not a valid request ID!",
                request_id.to_string()
            );
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("The value {} is not a valid request ID!", request_id),
            ));
        }
        // Retrieve the ReencMetaStore object
        let (servers_needed, link, fhe_type, signcrypted_ciphertext) = {
            let guarded_meta_store = self.reenc_meta_store.read().await;
            handle_res_mapping(
                guarded_meta_store.retrieve(&request_id).cloned(),
                &request_id,
                "Reencryption",
            )?
        };
        let server_verf_key = tonic_handle_potential_err(
            serde_asn1_der::to_vec(&self.get_verf_key()),
            "Could not serialize server verification key".to_string(),
        )?;
        Ok(Response::new(ReencryptionResponse {
            version: CURRENT_FORMAT_VERSION,
            servers_needed,
            signcrypted_ciphertext,
            fhe_type: fhe_type.into(),
            digest: link,
            verification_key: server_verf_key,
        }))
    }

    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        tracing::info!("Received a new request!");
        let inner = request.into_inner();
        let (ciphertext, fhe_type, req_digest, servers_needed, key_id, req_id) =
            tonic_handle_potential_err(
                validate_decrypt_req(&inner),
                format!("Invalid key in request {:?}", inner),
            )?;

        {
            let mut guarded_meta_store = self.dec_meta_store.write().await;
            tonic_handle_potential_err(
                guarded_meta_store.insert(&req_id),
                "Could not insert decryption into meta store".to_string(),
            )?;
        }

        let mut session = tonic_handle_potential_err(
            self.prepare_ddec_data_from_requestid(&req_id),
            "Could not prepare ddec data for reencryption".to_string(),
        )?;
        let mut protocol = Small::new(session.clone());
        let meta_store = Arc::clone(&self.dec_meta_store);
        let fhe_keys = Arc::clone(&self.fhe_keys);

        // we do not need to hold the handle,
        // the result of the computation is tracked by the dec_meta_store
        let _handle = tokio::spawn(async move {
            let mut guarded_meta_store = meta_store.write().await;
            {
                let fhe_keys_rlock = fhe_keys.read().await;
                match Self::inner_decrypt(
                    &mut session,
                    &mut protocol,
                    &ciphertext,
                    fhe_type,
                    &key_id,
                    fhe_keys_rlock,
                )
                .await
                {
                    Ok(raw_decryption) => {
                        let plaintext = Plaintext::new(raw_decryption.0 as u128, fhe_type);
                        // We cannot do much if updating the storage fails at this point...
                        let _ = guarded_meta_store.update(
                            &req_id,
                            HandlerStatus::Done((
                                servers_needed,
                                req_digest.clone(),
                                plaintext.clone(),
                            )),
                        );
                    }
                    Result::Err(e) => {
                        // We cannot do much if updating the storage fails at this point...
                        let _ = guarded_meta_store.update(
                            &req_id,
                            HandlerStatus::Error(format!("Failed decryption: {e}")),
                        );
                    }
                }
            }
        });
        Ok(Response::new(Empty {}))
    }

    async fn get_decrypt_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        let request_id = request.into_inner();
        if !request_id.is_valid() {
            tracing::warn!(
                "The value {} is not a valid request ID!",
                request_id.to_string()
            );
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("The value {} is not a valid request ID!", request_id),
            ));
        }
        let (servers_needed, req_digest, plaintext) = {
            let guarded_meta_store = self.dec_meta_store.read().await;
            handle_res_mapping(
                guarded_meta_store.retrieve(&request_id).cloned(),
                &request_id,
                "Decryption",
            )?
        };
        let decrypted_bytes = tonic_handle_potential_err(
            serde_asn1_der::to_vec(&plaintext),
            format!(
                "Could not convert plaintext to bytes in request with ID {:?}",
                request_id
            ),
        )?;
        let server_verf_key = tonic_handle_potential_err(
            serde_asn1_der::to_vec(&self.get_verf_key()),
            "Could not serialize server verification key".to_string(),
        )?;
        let sig_payload = DecryptionResponsePayload {
            version: CURRENT_FORMAT_VERSION,
            servers_needed,
            plaintext: decrypted_bytes,
            verification_key: server_verf_key,
            digest: req_digest,
        };

        let sig_payload_vec = tonic_handle_potential_err(
            serde_asn1_der::to_vec(&sig_payload),
            format!("Could not convert payload to bytes {:?}", sig_payload),
        )?;

        let sig = tonic_handle_potential_err(
            self.sign(&sig_payload_vec),
            format!("Could not sign payload {:?}", sig_payload),
        )?;
        Ok(Response::new(DecryptionResponse {
            signature: sig.sig.to_vec(),
            payload: Some(sig_payload),
        }))
    }

    async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
        let req_inner = request.into_inner();
        tracing::info!(
            "Starting crs generation on kms for request ID {:?}",
            req_inner.request_id
        );

        let fhe_params = crate::rpc::central_rpc::retrieve_parameters(req_inner.params)
            .await
            .map_err(|e| {
                tonic::Status::new(
                    tonic::Code::NotFound,
                    format!("Can not retrieve fhe parameters with error {e}"),
                )
            })?
            .ciphertext_parameters;
        let witness_dim = tonic_handle_potential_err(
            compute_witness_dim(&fhe_params),
            "witness dimension computation failed".to_string(),
        )?;

        let req_id = req_inner.request_id.ok_or(tonic::Status::new(
            tonic::Code::InvalidArgument,
            "missing request ID in CRS generation",
        ))?;
        self.inner_crs_gen(&req_id, witness_dim)
            .await
            .map_err(|e| tonic::Status::new(tonic::Code::Aborted, e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    async fn get_crs_gen_result(
        &self,
        request: Request<RequestId>,
    ) -> Result<Response<CrsGenResult>, Status> {
        let request_id = request.into_inner();
        let guarded_meta_store = self.crs_meta_store.read().await;
        let (digest, signature) = handle_res_mapping(
            guarded_meta_store.retrieve(&request_id).cloned(),
            &request_id,
            "CRS generation",
        )?;
        Ok(Response::new(CrsGenResult {
            request_id: Some(request_id),
            crs_results: Some(FhePubKeyInfo {
                key_handle: digest,
                signature,
            }),
        }))
    }
}

// TODO should we move this to meta_store.rs?
/// Helper method for retrieving the result of a request from an appropriate meta store
/// [req_id] is the request ID to retrieve
/// [request_type] is a free-form string used only for error logging the origin of the failure
fn handle_res_mapping<T>(
    handle: Option<HandlerStatus<T>>,
    req_id: &RequestId,
    request_type: &str,
) -> Result<T, Status> {
    match handle {
        None => {
            let msg = format!(
                "Could not retrieve {request_type} with request ID {}. It does not exist",
                req_id
            );
            tracing::warn!(msg);
            Err(tonic::Status::new(tonic::Code::NotFound, msg))
        }
        Some(HandlerStatus::Started) => {
            let msg = format!(
                    "Could not retrieve {request_type} with request ID {} since it is not completed yet",
                    req_id
                );
            tracing::warn!(msg);
            Err(tonic::Status::new(tonic::Code::Unavailable, msg))
        }
        Some(HandlerStatus::Error(e)) => {
            let msg = format!(
                    "Could not retrieve {request_type} with request ID {} since it finished with an error: {}",
                    req_id, e
                );
            tracing::warn!(msg);
            Err(tonic::Status::new(tonic::Code::Unavailable, msg))
        }
        Some(HandlerStatus::Done(res)) => Ok(res),
    }
}

#[test]
fn test_threshold_config() {
    let config = ThresholdConfig::init_config("config/default_1").unwrap();
    assert_eq!(config.url, "127.0.0.1");
    assert_eq!(config.base_port, 50000);
    assert_eq!(config.parties, 4);
    assert_eq!(config.threshold, 1);
    assert_eq!(config.num_sessions_preproc, Some(2));
    assert!(config.preproc_redis_conf.is_none());
}
