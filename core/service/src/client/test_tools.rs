//! Legacy test infrastructure for non-isolated tests
//!
//! # TODO: Future Refactoring
//!
//! This module contains legacy test setup functions that are still used by non-isolated tests.
//! These tests use shared test material and manual server setup instead of the modern builder pattern.
//!
//! ## For New Tests:
//! **Use the modern testing infrastructure instead:**
//! ```rust
//! use crate::testing::prelude::*;
//!
//! #[tokio::test]
//! async fn my_test() -> Result<()> {
//!     let env = ThresholdTestEnv::builder()
//!         .with_test_name("my_test")
//!         .with_party_count(4)
//!         .with_backup_vault()        // Optional
//!         .with_custodian_keychain()  // Optional
//!         .build()
//!         .await?;
//!     
//!     // Use env.clients, env.servers, env.material_dir
//!     Ok(())
//! }
//! ```

use crate::client::client_wasm::Client;
use crate::conf::{init_conf, CoreConfig, Keychain, SecretSharingKeychain};
use crate::consts::{DEC_CAPACITY, DEFAULT_PROTOCOL, DEFAULT_URL, MAX_TRIES, MIN_DEC_CACHE};
use crate::engine::base::BaseKmsStruct;
use crate::engine::centralized::central_kms::RealCentralizedKms;
use crate::engine::threshold::service::new_real_threshold_kms;
use crate::engine::{run_server, Shutdown};
use crate::testing::utils::file_backup_vault;
use crate::testing::utils::setup::ensure_testing_material_exists;
use crate::util::rate_limiter::RateLimiterConfig;
use crate::vault::storage::{
    crypto_material::get_core_signing_key, file::FileStorage, Storage, StorageType,
};
use crate::vault::storage::{make_storage, StorageExt};
use crate::vault::Vault;
use crate::{
    conf::{
        threshold::{PeerConf, ThresholdPartyConf},
        ServiceEndpoint,
    },
    util::random_free_port::get_listeners_random_free_ports,
};
use futures_util::FutureExt;
use itertools::Itertools;
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
use kms_grpc::rpc_types::KMSType;
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use threshold_fhe::networking::grpc::GrpcServer;
use tonic::server::NamedService;
use tonic::transport::{Channel, Uri};
use tonic_health::pb::health_client::HealthClient;
use tonic_health::pb::HealthCheckRequest;
use tonic_health::ServingStatus;

#[cfg(feature = "slow_tests")]
use crate::testing::utils::setup::ensure_default_material_exists;

// Put gRPC size limit to 100 MB.
// We need a high limit because ciphertexts may be large after SnS.
const GRPC_MAX_MESSAGE_SIZE: usize = 100 * 1024 * 1024;

pub async fn setup_threshold_no_client<
    PubS: Storage + Clone + Sync + Send + 'static,
    PrivS: StorageExt + Clone + Sync + Send + 'static,
>(
    threshold: u8,
    pub_storage: Vec<PubS>,
    priv_storage: Vec<PrivS>,
    vaults: Vec<Option<Vault>>,
    run_prss: bool,
    rate_limiter_conf: Option<RateLimiterConfig>,
    decryption_mode: Option<DecryptionMode>,
) -> HashMap<u32, ServerHandle> {
    let mut handles = Vec::new();
    tracing::info!("Spawning servers...");
    let num_parties = priv_storage.len();
    let ip_addr = DEFAULT_URL.parse().unwrap();
    let service_listeners = get_listeners_random_free_ports(&ip_addr, num_parties)
        .await
        .unwrap();
    let mpc_listeners = get_listeners_random_free_ports(&ip_addr, num_parties)
        .await
        .unwrap();

    let service_ports = service_listeners
        .iter()
        .map(|listener_and_port| listener_and_port.1)
        .collect_vec();
    let mpc_ports = mpc_listeners
        .iter()
        .map(|listener_and_port| listener_and_port.1)
        .collect_vec();

    tracing::info!("service ports: {:?}", service_ports);
    tracing::info!("MPC ports: {:?}", mpc_ports);
    let mpc_confs = mpc_ports
        .into_iter()
        .enumerate()
        .map(|(i, port)| PeerConf {
            party_id: i + 1,
            address: ip_addr.to_string(),
            mpc_identity: None,
            port,
            tls_cert: None,
            verification_address: None,
        })
        .collect_vec();

    // use NoiseFloodSmall unless some other DecryptionMode was set as parameter
    let decryption_mode = decryption_mode.unwrap_or_default();

    // a vector of sender that will trigger shutdown of core/threshold servers
    let mut mpc_shutdown_txs = Vec::new();

    for (i, (mpc_listener, _mpc_port), cur_vault) in
        itertools::izip!(1..=num_parties, mpc_listeners.into_iter(), vaults)
    {
        let cur_pub_storage = pub_storage[i - 1].to_owned();
        let cur_priv_storage = priv_storage[i - 1].to_owned();
        let service_config = ServiceEndpoint {
            listen_address: ip_addr.to_string(),
            listen_port: service_ports[i - 1],
            timeout_secs: 60u64,
            grpc_max_message_size: GRPC_MAX_MESSAGE_SIZE,
        };
        let mpc_conf = mpc_confs.clone();

        // create channels that will trigger core/threshold shutdown
        let (mpc_core_tx, mpc_core_rx): (
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        ) = tokio::sync::oneshot::channel();
        mpc_shutdown_txs.push(mpc_core_tx);
        // Make a configuration based on the default, but customized with the needed changes for the test setup
        // Use CARGO_MANIFEST_DIR to get absolute path to config file
        let config_path = format!("{}/config/default_1", env!("CARGO_MANIFEST_DIR"));
        let mut core_config: CoreConfig = init_conf(&config_path).expect("config must parse");
        let threshold_party_config = ThresholdPartyConf {
            listen_address: mpc_conf[i - 1].address.clone(),
            listen_port: mpc_conf[i - 1].port,
            threshold,
            dec_capacity: DEC_CAPACITY,
            min_dec_cache: MIN_DEC_CACHE,
            my_id: Some(i),
            preproc_redis: None,
            // Add some parallelism so CI runs a bit faster
            // since it uses large machines
            num_sessions_preproc: Some(5),
            tls: None,
            peers: Some(mpc_conf),
            core_to_core_net: None,
            decryption_mode,
        };
        core_config.threshold = Some(threshold_party_config);
        core_config.rate_limiter_conf = rate_limiter_conf.clone();

        handles.push(tokio::spawn(async move {
            let sk = get_core_signing_key(&cur_priv_storage).await.unwrap();
            let base_kms = BaseKmsStruct::new(KMSType::Threshold, sk).unwrap();

            // TODO pass in cert_paths for testing TLS
            let server = new_real_threshold_kms(
                core_config,
                cur_pub_storage,
                cur_priv_storage,
                cur_vault,
                None,
                mpc_listener,
                base_kms,
                None,
                false,
                run_prss,
                mpc_core_rx.map(drop),
            )
            .await;
            (i, server, service_config)
        }));
    }
    assert_eq!(handles.len(), num_parties);
    // Wait for the server to start
    tracing::info!("Client waiting for server");
    let mut servers = Vec::with_capacity(num_parties);
    for cur_handle in handles {
        let (i, kms_server_res, service_config) =
            cur_handle.await.expect("Server {i} failed to start");
        match kms_server_res {
            Ok((kms_server, health_service, _metastore_status_service)) => {
                servers.push((i, kms_server, service_config, health_service))
            }
            Err(e) => panic!("Failed to start server {i} with error {e:?}"),
        }
    }
    tracing::info!("Servers initialized. Starting servers...");
    let mut server_handles = HashMap::new();
    for (
        ((i, cur_server, service_config, cur_health_service), cur_mpc_shutdown),
        (service_listener, _service_port),
    ) in servers
        .into_iter()
        .zip_eq(mpc_shutdown_txs)
        .zip_eq(service_listeners.into_iter())
    {
        let cur_arc_server = Arc::new(cur_server);
        let arc_server_clone = Arc::clone(&cur_arc_server);
        let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            run_server(
                service_config,
                service_listener,
                cur_arc_server,
                Arc::new(crate::grpc::MetaStoreStatusServiceImpl::new(
                    None, None, None, None, None, None,
                )),
                cur_health_service,
                server_shutdown_rx.map(drop),
            )
            .await
            .expect("Failed to start threshold server");
        });
        server_handles.insert(
            i as u32,
            ServerHandle::new_threshold(
                arc_server_clone,
                service_ports[i - 1],
                mpc_confs[i - 1].port,
                server_shutdown_tx,
                cur_mpc_shutdown,
            ),
        );
        // Wait until MPC server is ready, this should happen as soon as the MPC server boots up
        let threshold_service_name = <GrpcServer as NamedService>::NAME;
        await_server_ready(threshold_service_name, mpc_confs[i - 1].port).await;
        // Observe that we don't check that the core server is ready here. The reason is that it depends on whether PRSS has been executed or loaded from disc.
        // Thus if requests are send to the core without PRSS being executed, then a failure will happen.
    }
    server_handles
}

/// Setup threshold servers with per-server peer configuration.
///
/// This function allows each server to have its own peer list, enabling party resharing tests
/// where different servers participate in different MPC contexts.
///
/// # Arguments
/// * `server_configs` - Vec of (my_id, threshold, peers, peer_server_indices) for each server
///   - `my_id`: The MPC party ID this server will act as
///   - `threshold`: The threshold value for this server
///   - `peers`: The peer configuration (party_id will be used as-is)
///   - `peer_server_indices`: Maps each peer index to the physical server index for port lookup
/// * `pub_storage` - Public storage for each server
/// * `priv_storage` - Private storage for each server
/// * `vaults` - Optional backup vaults for each server
/// * `run_prss` - Whether to run PRSS initialization
/// * `rate_limiter_conf` - Optional rate limiter configuration
/// * `decryption_mode` - Optional decryption mode
///
/// # Example
/// ```ignore
/// // Setup 6 servers for party resharing:
/// // - Context 1: servers 0-3 (indices) as parties 1-4
/// // - Context 2: servers 4,5,2,3 (indices) as parties 1,2,3,4
/// let peers_ctx1 = vec![peer1, peer2, peer3, peer4];
/// let peers_ctx2 = vec![peer1, peer2, peer3, peer4]; // Same party IDs, different physical servers
/// let server_configs = vec![
///     (1, 1, peers_ctx1.clone(), vec![0, 1, 2, 3]),  // Server 0: party 1, peers at servers 0,1,2,3
///     (2, 1, peers_ctx1.clone(), vec![0, 1, 2, 3]),  // Server 1: party 2
///     (3, 1, peers_ctx1.clone(), vec![0, 1, 2, 3]),  // Server 2: party 3
///     (4, 1, peers_ctx1.clone(), vec![0, 1, 2, 3]),  // Server 3: party 4
///     (1, 1, peers_ctx2.clone(), vec![4, 5, 2, 3]),  // Server 4: party 1, peers at servers 4,5,2,3
///     (2, 1, peers_ctx2.clone(), vec![4, 5, 2, 3]),  // Server 5: party 2
/// ];
/// ```
pub async fn setup_threshold_with_custom_peers<
    PubS: Storage + Clone + Sync + Send + 'static,
    PrivS: Storage + Clone + Sync + Send + 'static,
>(
    server_configs: Vec<(usize, u8, Vec<PeerConf>, Vec<usize>)>, // (my_id, threshold, peers, peer_server_indices)
    pub_storage: Vec<PubS>,
    priv_storage: Vec<PrivS>,
    vaults: Vec<Option<Vault>>,
    run_prss: bool,
    rate_limiter_conf: Option<RateLimiterConfig>,
    decryption_mode: Option<DecryptionMode>,
) -> HashMap<u32, ServerHandle> {
    let mut handles = Vec::new();
    tracing::info!("Spawning servers with custom peer configs...");
    let num_servers = server_configs.len();
    let ip_addr = DEFAULT_URL.parse().unwrap();
    let service_listeners = get_listeners_random_free_ports(&ip_addr, num_servers)
        .await
        .unwrap();
    let mpc_listeners = get_listeners_random_free_ports(&ip_addr, num_servers)
        .await
        .unwrap();

    let service_ports: Vec<u16> = service_listeners
        .iter()
        .map(|listener_and_port| listener_and_port.1)
        .collect_vec();
    let mpc_ports: Vec<u16> = mpc_listeners
        .iter()
        .map(|listener_and_port| listener_and_port.1)
        .collect_vec();

    tracing::info!("service ports: {:?}", service_ports);
    tracing::info!("MPC ports: {:?}", mpc_ports);

    // use NoiseFloodSmall unless some other DecryptionMode was set as parameter
    let decryption_mode = decryption_mode.unwrap_or_default();

    // a vector of sender that will trigger shutdown of core/threshold servers
    let mut mpc_shutdown_txs = Vec::new();

    for (
        idx,
        ((my_id, threshold, peers, peer_server_indices), (mpc_listener, _mpc_port), cur_vault),
    ) in itertools::izip!(server_configs.iter(), mpc_listeners.into_iter(), vaults).enumerate()
    {
        let cur_pub_storage = pub_storage[idx].to_owned();
        let cur_priv_storage = priv_storage[idx].to_owned();
        let service_config = ServiceEndpoint {
            listen_address: ip_addr.to_string(),
            listen_port: service_ports[idx],
            timeout_secs: 60u64,
            grpc_max_message_size: GRPC_MAX_MESSAGE_SIZE,
        };

        // Update peer addresses with actual allocated ports using the server index mapping
        let mut updated_peers = peers.clone();
        for (peer_idx, peer) in updated_peers.iter_mut().enumerate() {
            if peer_idx < peer_server_indices.len() {
                let server_idx = peer_server_indices[peer_idx];
                peer.port = mpc_ports[server_idx];
                peer.address = ip_addr.to_string();
            }
        }

        // create channels that will trigger core/threshold shutdown
        let (mpc_core_tx, mpc_core_rx): (
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        ) = tokio::sync::oneshot::channel();
        mpc_shutdown_txs.push(mpc_core_tx);

        let config_path = format!("{}/config/default_1", env!("CARGO_MANIFEST_DIR"));
        let mut core_config: CoreConfig = init_conf(&config_path).expect("config must parse");
        let threshold_party_config = ThresholdPartyConf {
            listen_address: ip_addr.to_string(),
            listen_port: mpc_ports[idx],
            threshold: *threshold,
            dec_capacity: DEC_CAPACITY,
            min_dec_cache: MIN_DEC_CACHE,
            my_id: Some(*my_id),
            preproc_redis: None,
            num_sessions_preproc: Some(5),
            tls: None,
            peers: Some(updated_peers),
            core_to_core_net: None,
            decryption_mode,
        };
        core_config.threshold = Some(threshold_party_config);
        core_config.rate_limiter_conf = rate_limiter_conf.clone();

        let my_id_copy = *my_id;
        let server_idx = idx; // Track the physical server index
        handles.push(tokio::spawn(async move {
            let sk = get_core_signing_key(&cur_priv_storage).await.unwrap();
            let base_kms = BaseKmsStruct::new(KMSType::Threshold, sk).unwrap();

            let server = new_real_threshold_kms(
                core_config,
                cur_pub_storage,
                cur_priv_storage,
                cur_vault,
                None,
                mpc_listener,
                base_kms,
                None,
                false,
                run_prss,
                mpc_core_rx.map(drop),
            )
            .await;
            (server_idx, my_id_copy, server, service_config)
        }));
    }
    assert_eq!(handles.len(), num_servers);

    tracing::info!("Client waiting for servers...");
    let mut servers = Vec::with_capacity(num_servers);
    for cur_handle in handles {
        let (server_idx, my_id, kms_server_res, service_config) =
            cur_handle.await.expect("Server failed to start");
        match kms_server_res {
            Ok((kms_server, health_service, _metastore_status_service)) => servers.push((
                server_idx,
                my_id,
                kms_server,
                service_config,
                health_service,
            )),
            Err(e) => {
                panic!("Failed to start server {my_id} (index {server_idx}) with error {e:?}")
            }
        }
    }

    tracing::info!("Servers initialized. Starting servers...");
    let mut server_handles = HashMap::new();
    for (
        ((server_idx, _my_id, cur_server, service_config, cur_health_service), cur_mpc_shutdown),
        (service_listener, _service_port),
    ) in servers
        .into_iter()
        .zip_eq(mpc_shutdown_txs)
        .zip_eq(service_listeners.into_iter())
    {
        let cur_arc_server = Arc::new(cur_server);
        let arc_server_clone = Arc::clone(&cur_arc_server);
        let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            run_server(
                service_config,
                service_listener,
                cur_arc_server,
                Arc::new(crate::grpc::MetaStoreStatusServiceImpl::new(
                    None, None, None, None, None, None,
                )),
                cur_health_service,
                server_shutdown_rx.map(drop),
            )
            .await
            .expect("Failed to start threshold server");
        });
        // Use server_idx+1 as the key (1-indexed physical server ID)
        server_handles.insert(
            (server_idx + 1) as u32,
            ServerHandle::new_threshold(
                arc_server_clone,
                service_ports[server_idx],
                mpc_ports[server_idx],
                server_shutdown_tx,
                cur_mpc_shutdown,
            ),
        );
        // Wait until MPC server is ready
        let threshold_service_name = <GrpcServer as NamedService>::NAME;
        await_server_ready(threshold_service_name, mpc_ports[server_idx]).await;
    }
    server_handles
}

/// try to connect to a URI and retry every 200ms for 50 times before giving up after 5 seconds.
pub async fn connect_with_retry(uri: Uri) -> Channel {
    tracing::info!("Client connecting to {}", uri);
    let mut channel = Channel::builder(uri.clone())
        .tcp_nodelay(true)
        .connect()
        .await;
    let mut tries = 0usize;
    loop {
        match channel {
            Ok(_) => {
                break;
            }
            Err(_) => {
                tracing::info!("Retrying: Client connection to {}", uri);
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                channel = Channel::builder(uri.clone())
                    .tcp_nodelay(true)
                    .connect()
                    .await;
                tries += 1;
                if tries > MAX_TRIES {
                    break;
                }
            }
        }
    }
    match channel {
        Ok(channel) => {
            tracing::info!("Client connected to {}", uri);
            channel
        }
        Err(e) => {
            tracing::error!("Client unable to connect to {}: Error {:?}", uri, e);
            panic!("Client unable to connect to {uri}: Error {e:?}")
        }
    }
}

pub(crate) async fn check_port_is_closed(port: u16) {
    let addr = std::net::SocketAddr::new(
        DEFAULT_URL.parse().expect("Default URL cannot be parsed"),
        port,
    );
    // try for 10 seconds to wait for the ports to close
    for _ in 0..10 {
        let res = tokio::net::TcpListener::bind(addr).await;
        match res {
            Ok(listener) => {
                drop(listener);
                // port is closed if we can bind again
                break;
            }
            Err(_) => {
                tracing::warn!("port {} is still not closed, retrying", addr);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }
}

/// Helper struct for managing servers in testing
pub struct ServerHandle {
    pub server: Arc<dyn Shutdown>,
    // The service port is the port that is used to connect to the core server
    pub service_port: u16,
    // In the threshold setting the mpc port is the port that is used to connect to the other MPC parties
    pub mpc_port: Option<u16>,
    // The handle to shut down the core service which is receiving the external requests
    pub service_shutdown_tx: tokio::sync::oneshot::Sender<()>,
    // The handle to shut down the optional MPC server
    pub mpc_shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl ServerHandle {
    pub fn new_threshold(
        server: Arc<dyn Shutdown>,
        service_port: u16,
        mpc_port: u16,
        service_shutdown_tx: tokio::sync::oneshot::Sender<()>,
        mpc_shutdown_tx: tokio::sync::oneshot::Sender<()>,
    ) -> Self {
        Self {
            server,
            service_port,
            mpc_port: Some(mpc_port),
            service_shutdown_tx,
            mpc_shutdown_tx: Some(mpc_shutdown_tx),
        }
    }

    pub fn new_centralized(
        server: Arc<dyn Shutdown>,
        service_port: u16,
        service_shutdown_tx: tokio::sync::oneshot::Sender<()>,
    ) -> Self {
        Self {
            server,
            service_port,
            mpc_port: None,
            service_shutdown_tx,
            mpc_shutdown_tx: None,
        }
    }

    pub fn service_port(&self) -> u16 {
        self.service_port
    }

    pub fn mpc_port(&self) -> Option<u16> {
        self.mpc_port
    }

    pub async fn assert_shutdown(self) {
        // Call shutdown so we can await the server to shut down even though sending the shutdown signal already calls this
        let shutdown_handle = self
            .server
            .shutdown()
            .expect("Failed to execute core service server shutdown");
        shutdown_handle
            .await
            .expect("Failed to await core service server shutdown completion");
        // Shut down the core server
        // The receiver should not be closed, that's why we unwrap
        self.service_shutdown_tx
            .send(())
            .expect("Could not send shut down signal to  core server");

        if let Some(chan) = self.mpc_shutdown_tx {
            // Shut down MPC server
            chan.send(())
                .expect("Could not send shut down signal to the MPC server");
        }

        // Validate that both the MPC and server are fully closed
        check_port_is_closed(self.service_port).await;
        if let Some(mpc_port) = self.mpc_port {
            check_port_is_closed(mpc_port).await;
        }
    }
}

pub async fn setup_threshold<
    PubS: Storage + Clone + Sync + Send + 'static,
    PrivS: StorageExt + Clone + Sync + Send + 'static,
>(
    threshold: u8,
    pub_storage: Vec<PubS>,
    priv_storage: Vec<PrivS>,
    vaults: Vec<Option<Vault>>,
    run_prss: bool,
    rate_limiter_conf: Option<RateLimiterConfig>,
    decryption_mode: Option<DecryptionMode>,
) -> (
    HashMap<u32, ServerHandle>,
    HashMap<u32, CoreServiceEndpointClient<Channel>>,
) {
    let num_parties = priv_storage.len();
    // Setup the threshold scheme with lazy PRSS generation
    let server_handles = setup_threshold_no_client::<PubS, PrivS>(
        threshold,
        pub_storage,
        priv_storage,
        vaults,
        run_prss,
        rate_limiter_conf,
        decryption_mode,
    )
    .await;
    assert_eq!(server_handles.len(), num_parties);
    let mut client_handles = HashMap::new();

    for (i, server_handle) in &server_handles {
        let url = format!(
            "{DEFAULT_PROTOCOL}://{DEFAULT_URL}:{}",
            server_handle.service_port()
        );
        let uri = Uri::from_str(&url).unwrap();
        let channel = connect_with_retry(uri).await;
        client_handles.insert(*i, CoreServiceEndpointClient::new(channel));
    }
    tracing::info!("Client connected to servers");
    (server_handles, client_handles)
}

/// Configuration for optional threshold test setup parameters
#[cfg(any(test, feature = "testing"))]
#[derive(Default)]
pub struct ThresholdTestConfig<'a> {
    pub run_prss: bool,
    pub rate_limiter_conf: Option<RateLimiterConfig>,
    pub decryption_mode: Option<DecryptionMode>,
    pub test_material_path: Option<&'a std::path::Path>,
}

/// Setup_threshold that supports isolated test material
/// Note: The test_material_path in config is kept for API compatibility but not used.
/// Tests should set up their own isolated material using TestMaterialManager before calling this.
#[cfg(any(test, feature = "testing"))]
pub async fn setup_threshold_isolated<
    PubS: Storage + Clone + Sync + Send + 'static,
    PrivS: Storage + Clone + Sync + Send + 'static,
>(
    threshold: u8,
    pub_storage: Vec<PubS>,
    priv_storage: Vec<PrivS>,
    vaults: Vec<Option<Vault>>,
    config: ThresholdTestConfig<'_>,
) -> (
    HashMap<u32, ServerHandle>,
    HashMap<u32, CoreServiceEndpointClient<Channel>>,
) {
    let num_parties = priv_storage.len();

    // Setup the threshold scheme
    let server_handles = setup_threshold_no_client::<PubS, PrivS>(
        threshold,
        pub_storage,
        priv_storage,
        vaults,
        config.run_prss,
        config.rate_limiter_conf,
        config.decryption_mode,
    )
    .await;

    assert_eq!(server_handles.len(), num_parties);
    let mut client_handles = HashMap::new();

    for (i, server_handle) in &server_handles {
        let url = format!(
            "{DEFAULT_PROTOCOL}://{DEFAULT_URL}:{}",
            server_handle.service_port()
        );
        let uri = Uri::from_str(&url).unwrap();
        let channel = connect_with_retry(uri).await;
        client_handles.insert(*i, CoreServiceEndpointClient::new(channel));
    }

    (server_handles, client_handles)
}

/// Setup a client and a server running with non-persistent storage.
pub async fn setup_centralized_no_client<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
>(
    pub_storage: PubS,
    priv_storage: PrivS,
    backup_vault: Option<Vault>,
    rate_limiter_conf: Option<RateLimiterConfig>,
) -> ServerHandle {
    let ip_addr = DEFAULT_URL.parse().unwrap();
    // we use port numbers above 40001 so that it's easy to identify
    // which cores are running in the centralized mode from the logs
    let (listener, listen_port) = get_listeners_random_free_ports(&ip_addr, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let sk = get_core_signing_key(&priv_storage).await.unwrap();
    let (kms, health_service) = RealCentralizedKms::new(
        pub_storage,
        priv_storage,
        backup_vault,
        None,
        sk,
        rate_limiter_conf,
    )
    .await
    .map_err(|e| {
        eprintln!("Failed to create KMS: {:?}", e);
        e
    })
    .expect("Could not create KMS");
    let arc_kms = Arc::new(kms);
    let arc_kms_clone = Arc::clone(&arc_kms);
    tokio::spawn(async move {
        let config = ServiceEndpoint {
            listen_address: ip_addr.to_string(),
            listen_port,
            timeout_secs: 360,
            grpc_max_message_size: GRPC_MAX_MESSAGE_SIZE,
        };

        run_server(
            config,
            listener,
            arc_kms,
            Arc::new(crate::grpc::MetaStoreStatusServiceImpl::new(
                None, None, None, None, None, None,
            )),
            health_service,
            rx.map(drop),
        )
        .await
        .expect("Could not start server");
    });
    let service_name = <CoreServiceEndpointServer<
            RealCentralizedKms<FileStorage, FileStorage>,
        > as NamedService>::NAME;
    await_server_ready(service_name, listen_port).await;
    ServerHandle::new_centralized(arc_kms_clone, listen_port, tx)
}

pub(crate) async fn setup_centralized<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
>(
    pub_storage: PubS,
    priv_storage: PrivS,
    backup_vault: Option<Vault>,
    rate_limiter_conf: Option<RateLimiterConfig>,
) -> (
    ServerHandle,
    CoreServiceEndpointClient<tonic::transport::Channel>,
) {
    let server_handle =
        setup_centralized_no_client(pub_storage, priv_storage, backup_vault, rate_limiter_conf)
            .await;
    let url = format!(
        "{DEFAULT_PROTOCOL}://{DEFAULT_URL}:{}",
        server_handle.service_port
    );
    let uri = Uri::from_str(&url).unwrap();
    let channel = connect_with_retry(uri).await;
    let client = CoreServiceEndpointClient::new(channel);
    (server_handle, client)
}

/// Centralized setup that supports isolated test material
/// Note: The test_material_path parameter is kept for API compatibility but not used.
/// Tests should set up their own isolated material using TestMaterialManager before calling this.
#[cfg(any(test, feature = "testing"))]
pub async fn setup_centralized_isolated<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
>(
    pub_storage: PubS,
    priv_storage: PrivS,
    backup_vault: Option<Vault>,
    rate_limiter_conf: Option<RateLimiterConfig>,
    _test_material_path: Option<&std::path::Path>,
) -> (
    ServerHandle,
    CoreServiceEndpointClient<tonic::transport::Channel>,
) {
    let server_handle =
        setup_centralized_no_client(pub_storage, priv_storage, backup_vault, rate_limiter_conf)
            .await;
    let url = format!(
        "{DEFAULT_PROTOCOL}://{DEFAULT_URL}:{}",
        server_handle.service_port
    );
    let uri = Uri::from_str(&url).unwrap();
    let channel = connect_with_retry(uri).await;
    let client = CoreServiceEndpointClient::new(channel);

    (server_handle, client)
}

/// Read the centralized keys for testing from `centralized_key_path` and construct a KMS
/// server, client end-point connection (which is needed to communicate with the server) and
/// an internal client (for constructing requests and validating responses).
pub async fn central_handle_w_vault(
    param: &DKGParams,
    rate_limiter_conf: Option<RateLimiterConfig>,
    backup_vault: Option<Vault>,
    test_data_path: Option<&Path>,
) -> (ServerHandle, CoreServiceEndpointClient<Channel>, Client) {
    let priv_storage = FileStorage::new(test_data_path, StorageType::PRIV, None).unwrap();
    let pub_storage = FileStorage::new(test_data_path, StorageType::PUB, None).unwrap();

    ensure_testing_material_exists(test_data_path).await;
    #[cfg(feature = "slow_tests")]
    ensure_default_material_exists().await;

    let (kms_server, kms_client) =
        setup_centralized(pub_storage, priv_storage, backup_vault, rate_limiter_conf).await;
    let pub_storage = HashMap::from_iter([(
        1,
        FileStorage::new(test_data_path, StorageType::PUB, None).unwrap(),
    )]);
    let client_storage = FileStorage::new(test_data_path, StorageType::CLIENT, None).unwrap();
    let internal_client = Client::new_client(client_storage, pub_storage, param, None)
        .await
        .unwrap();
    (kms_server, kms_client, internal_client)
}

/// Read the centralized keys for testing from `centralized_key_path` and construct a KMS
/// server, client end-point connection (which is needed to communicate with the server) and
/// an internal client (for constructing requests and validating responses).
pub async fn centralized_handles(
    param: &DKGParams,
    rate_limiter_conf: Option<RateLimiterConfig>,
) -> (ServerHandle, CoreServiceEndpointClient<Channel>, Client) {
    let backup_proxy_storage = make_storage(None, StorageType::BACKUP, None, None).unwrap();
    let backup_vault = Vault {
        storage: backup_proxy_storage,
        keychain: None,
    };
    // Use default location for storage
    central_handle_w_vault(param, rate_limiter_conf, Some(backup_vault), None).await
}

pub async fn centralized_custodian_handles(
    param: &DKGParams,
    rate_limiter_conf: Option<RateLimiterConfig>,
    test_data_path: Option<&Path>,
    pub_storage_prefix: Option<&str>,
    backup_storage_prefix: Option<&str>,
) -> (ServerHandle, CoreServiceEndpointClient<Channel>, Client) {
    let backup_vault = file_backup_vault(
        Some(&Keychain::SecretSharing(SecretSharingKeychain {})),
        test_data_path,
        test_data_path,
        pub_storage_prefix,
        backup_storage_prefix,
    )
    .await;
    central_handle_w_vault(param, rate_limiter_conf, Some(backup_vault), test_data_path).await
}
/// Wait for a server to be ready for requests. I.e. wait until it enters the SERVING state.
/// Note that this method may panic if the server does not become ready within a certain time frame.
pub async fn await_server_ready(service_name: &str, port: u16) {
    let mut wrapped_client = get_health_client(port).await;
    let mut client_tries = 1;
    while wrapped_client.is_err() {
        if client_tries >= MAX_TRIES {
            panic!("Failed to start health client on server {service_name} on port {port}");
        }
        wrapped_client = get_health_client(port).await;
        client_tries += 1;
    }
    // We can safely unwrap here since we know the wrapped client does not contain an error
    let mut client = wrapped_client.unwrap();
    let mut status = get_status(&mut client, service_name).await;
    let mut service_tries = 1;
    while status.is_err()
        || status
            .clone()
            .is_ok_and(|status| status == ServingStatus::NotServing as i32)
    {
        if service_tries >= MAX_TRIES {
            panic!(
                "Failed to get health status on {service_name} on port {port}. Status: {status:?}"
            );
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        status = get_status(&mut client, service_name).await;
        service_tries += 1;
    }
}

pub(crate) async fn get_health_client(port: u16) -> anyhow::Result<HealthClient<Channel>> {
    let server_address = &format!("{DEFAULT_PROTOCOL}://{DEFAULT_URL}:{port}");
    let channel_builder = Channel::from_shared(server_address.to_string())?;
    let channel = channel_builder.connect().await?;
    Ok(HealthClient::new(channel))
}

pub(crate) async fn get_status(
    health_client: &mut HealthClient<Channel>,
    service_name: &str,
) -> Result<i32, tonic::Status> {
    let request = tonic::Request::new(HealthCheckRequest {
        service: service_name.to_string(),
    });
    let response = health_client.check(request).await?;
    Ok(response.into_inner().status)
}

// ============================================================================
// TEST UTILITIES FOR ISOLATED TESTS
// ============================================================================

/// Convert Eip712Domain to Eip712DomainMsg for gRPC requests
#[cfg(any(test, feature = "testing"))]
pub fn domain_to_msg(domain: &alloy_dyn_abi::Eip712Domain) -> kms_grpc::kms::v1::Eip712DomainMsg {
    kms_grpc::kms::v1::Eip712DomainMsg {
        name: domain
            .name
            .as_ref()
            .map(|n| n.to_string())
            .unwrap_or_default(),
        version: domain
            .version
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_default(),
        chain_id: domain
            .chain_id
            .map(|id| id.to_string().into_bytes())
            .unwrap_or_default(),
        verifying_contract: domain
            .verifying_contract
            .map(|addr| addr.to_string())
            .unwrap_or_default(),
        salt: domain.salt.map(|s| s.to_vec()),
    }
}
