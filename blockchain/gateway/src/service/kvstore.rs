use actix_web::get;
use actix_web::post;
use actix_web::{web, HttpResponse, Responder};
use byteorder::{BigEndian, ByteOrder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::fs as tokio_fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::time::Duration;

pub type Storage = Arc<Mutex<HashMap<String, tokio::time::Instant>>>;

#[get("/home")]
pub async fn home() -> impl Responder {
    HttpResponse::Ok().body("<h1>KV-Store</h1>")
}

#[post("/store")]
pub async fn put(req_body: String, storage: web::Data<Storage>) -> impl Responder {
    tracing::debug!("📦 Received ciphertext: {}", req_body);
    let data = hex::decode(req_body).expect("Hex decoding received ct");
    let combined_identifier = store(data, storage).await;
    HttpResponse::Ok().body(combined_identifier)
}

#[derive(Serialize, Deserialize)]
struct Status {}

pub async fn status() -> impl Responder {
    tracing::debug!("Status check");
    HttpResponse::Ok().json(Status {})
}

async fn store(data: Vec<u8>, storage: web::Data<Storage>) -> String {
    tracing::info!("📦 Storing ciphertext...");
    let data_size = data.len();
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash_result = hasher.finalize();
    let hex_hash = hex::encode(hash_result);

    // Encode the size as a 4-byte array
    let mut size_bytes = [0u8; 4];
    BigEndian::write_u32(&mut size_bytes, data_size as u32);

    // Prepend the size bytes to the hash
    let combined_identifier = format!("{}{}", hex::encode(size_bytes), hex_hash);
    let store_path = format!(".store/{}", combined_identifier);
    println!("store_path: {:?}", store_path);

    let mut file = tokio_fs::File::create(&store_path).await.unwrap();
    file.write_all(&data).await.unwrap();

    let eviction_time = tokio::time::Instant::now() + Duration::from_secs(300);
    storage
        .lock()
        .await
        .insert(combined_identifier.clone(), eviction_time);

    tracing::info!("📦 Ciphertext stored: {}", combined_identifier);

    combined_identifier
}

#[get("/store/{fingerprint}")]
pub async fn get(path: web::Path<String>, storage: web::Data<Storage>) -> impl Responder {
    let combined_identifier = path.into_inner();
    tracing::info!("📦 Retrieving ciphertext: {}", combined_identifier);
    let size_hex = &combined_identifier[..8];
    let _hash = &combined_identifier[8..];

    // Decode the size
    let size_bytes = hex::decode(size_hex).expect("Decoding hex size");
    let data_size = BigEndian::read_u32(&size_bytes);
    tracing::info!("Data size: {}", data_size);

    let store_path = format!(".store/{}", combined_identifier);
    tracing::info!("store_path: {:?}", store_path);

    let now = tokio::time::Instant::now();
    if let Some(eviction_time) = storage.lock().await.get(&combined_identifier) {
        if now < *eviction_time {
            match tokio_fs::read(&store_path).await {
                Ok(data) => {
                    tracing::trace!("data: {:?}", hex::encode(data.clone()));
                    HttpResponse::Ok().body(hex::encode(data))
                }
                Err(_) => HttpResponse::NotFound().body("Data not found"),
            }
        } else {
            HttpResponse::NotFound().body("Data evicted")
        }
    } else {
        HttpResponse::NotFound().body("Data not found")
    }
}

pub async fn evictor(storage: Storage) {
    loop {
        let now = tokio::time::Instant::now();
        let mut to_evict = Vec::new();

        {
            let storage_lock = storage.lock().await;
            for (key, &eviction_time) in storage_lock.iter() {
                if now >= eviction_time {
                    to_evict.push(key.clone());
                }
            }
        }

        for key in to_evict {
            let _ = storage.lock().await.remove(&key);
            let _ = tokio_fs::remove_file(format!(".store/{}", key)).await;
            tracing::info!("🗑️ Evicted ciphertext: {}", key);
        }

        tokio::time::sleep(Duration::from_secs(300)).await;
    }
}

pub async fn initialize_storage(storage: Storage) {
    if let Ok(mut entries) = tokio_fs::read_dir(".store").await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Ok(file_name) = entry.file_name().into_string() {
                let eviction_time = tokio::time::Instant::now() + Duration::from_secs(300);
                storage
                    .lock()
                    .await
                    .insert(file_name.clone(), eviction_time);
            }
        }
    }
}

// Not sure how relevant having this is
// It's useful for debugging but we might not want to list all cipher-texts
// in a production environment
#[get("/list")]
pub async fn list(storage: web::Data<Storage>) -> impl Responder {
    let result = storage
        .lock()
        .await
        .iter()
        .fold(String::new(), |a, b| format!("{}\n{:?}", a, b));
    HttpResponse::Ok().body(result)
}
