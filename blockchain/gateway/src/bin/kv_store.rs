use actix_web::web;
use gateway::config::telemetry::init_tracing;
use gateway::config::{GatewayConfig, Settings};
use gateway::service::kvstore::evictor;
use gateway::service::kvstore::initialize_storage;
use gateway::service::kvstore::Storage;
use gateway::service::kvstore::{get, put};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config: GatewayConfig = Settings::builder()
        .path(Some("config/gateway"))
        .build()
        .init_conf()
        .unwrap();
    init_tracing(config.tracing.to_owned()).unwrap();

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
