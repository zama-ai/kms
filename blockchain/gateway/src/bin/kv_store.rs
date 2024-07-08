use actix_web::web;
use gateway::config::{init_conf_with_trace_gateway, GatewayConfig};
use gateway::service::kvstore::evictor;
use gateway::service::kvstore::initialize_storage;
use gateway::service::kvstore::Storage;
use gateway::service::kvstore::{get, put};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let _config: GatewayConfig = init_conf_with_trace_gateway("config/gateway").map_err(|e| {
        tracing::error!("Failed to initialize gateway config: {:?}", e);
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to initialize gateway config",
        )
    })?;

    tokio::fs::create_dir_all(".store").await.unwrap();

    let storage: Storage = Arc::new(Mutex::new(HashMap::new()));
    let storage_data = web::Data::new(storage.clone());

    // Initialize storage with existing files
    initialize_storage(storage.clone()).await;

    tokio::spawn(evictor(storage));

    let payload_limit = 50 * 1024 * 1024; // 50 MB

    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .app_data(web::PayloadConfig::new(payload_limit))
            .app_data(storage_data.clone())
            .service(put)
            .service(get)
    })
    .bind("0.0.0.0:8088")?
    .run()
    .await
}
