use actix_web::web;
use gateway::config::{init_conf_with_trace_gateway, GatewayConfig};
use gateway::service::kvstore::evictor;
use gateway::service::kvstore::initialize_storage;
use gateway::service::kvstore::Storage;
use gateway::service::kvstore::{get, home, list, put, status};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing::info!("Setting up KV store...");

    let _config: GatewayConfig = init_conf_with_trace_gateway("config/gateway").map_err(|e| {
        let error_str = format!("Failed to initialize gateway config: {:?}", e);
        tracing::error!(error_str);
        std::io::Error::new(std::io::ErrorKind::Other, error_str)
    })?;

    tokio::fs::create_dir_all(".store").await.unwrap();

    let storage: Storage = Arc::new(Mutex::new(HashMap::new()));
    let storage_data = web::Data::new(storage.clone());

    // Initialize storage with existing files
    initialize_storage(storage.clone()).await;

    tokio::spawn(evictor(storage));

    let payload_limit = 50 * 1024 * 1024; // 50 MB

    tracing::info!("Starting KV store server ...");
    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .app_data(web::PayloadConfig::new(payload_limit))
            .app_data(storage_data.clone())
            .service(put)
            .service(home)
            .service(list)
            .route("/status", web::get().to(status))
            .route("/status", web::head().to(status)) // Need to allow HEAD for status
            // check using --spider
            .service(get)
    })
    .bind("0.0.0.0:8088")?
    .run()
    .await
}
