//! Peak heap consumed by one `Storage::store_data` into S3, as a function of payload size.
//!
//! This exists to answer a concrete review question: how much did peak memory actually change
//! when S3 key writes moved from "serialize the whole object into a `Vec`, then `PutObject`" to
//! the streaming multipart writer, and does normal operation pay anything for it?
//!
//! What it reports per payload size is `extra`: the heap the store needs *on top of* the object
//! it is storing, which is exactly the buffering the storage layer adds. Expect it to track the
//! serialized size on the buffered implementation and to flatten out at roughly
//! `(3 + PART_CHANNEL_CAPACITY) * S3_MULTIPART_PART_SIZE` once the streaming path engages.
//! Below `S3_MULTIPART_PART_SIZE` both implementations take the same single-PUT path, so the
//! smallest size doubles as the "normal operation is unaffected" check.
//!
//! # Running it
//!
//! Needs a real S3 endpoint: the in-process mock cannot serve the multipart path, because
//! `build_multipart_upload_client` derives a client from the caller's config and that strips the
//! mock transport. The compose stack already ships a MinIO for this:
//!
//! ```text
//! make start-compose-threshold          # brings up dev-s3-mock on :9000
//! export KMS_BENCH_S3_ENDPOINT=http://127.0.0.1:9000
//! export KMS_BENCH_S3_BUCKET=kms
//! export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_REGION=us-east-1
//! cargo bench -p kms --bench s3_store_peak_memory
//! ```
//!
//! Without `KMS_BENCH_S3_ENDPOINT` and `KMS_BENCH_S3_BUCKET` it prints why it is skipping and
//! exits successfully, so it stays harmless in a plain `cargo bench`.
//!
//! Override the sizes with `KMS_BENCH_SIZES_MIB=4,32,256,1024`.
//!
//! # Getting the "before" number
//!
//! The bench measures whatever it is compiled against, so the buffered baseline comes from
//! running the same file on a branch without the streaming writer:
//!
//! ```text
//! git switch -c bench-baseline main
//! git checkout <this-branch> -- core/service/benches core/service/Cargo.toml
//! cargo bench -p kms --bench s3_store_peak_memory
//! ```

use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use kms_grpc::RequestId;
use kms_lib::vault::storage::{Storage, StorageType, s3::S3Storage};
use peak_alloc::PeakAlloc;
use serde::{Deserialize, Serialize};
use tfhe::Versionize;
use tfhe::named::Named;
use tfhe_versionable::VersionsDispatch;

/// Tracks the whole process, including the uploader thread's part buffers, which is the
/// point: the streaming writer moves allocation off the calling task and onto that thread.
#[global_allocator]
static PEAK: PeakAlloc = PeakAlloc;

const DEFAULT_SIZES_MIB: &[usize] = &[4, 32, 256, 1024];
const MIB: usize = 1024 * 1024;

#[derive(Serialize, Deserialize, Versionize)]
#[versionize(BenchPayloadVersions)]
struct BenchPayload {
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize, VersionsDispatch)]
enum BenchPayloadVersions {
    V0(BenchPayload),
}

impl Named for BenchPayload {
    const NAME: &'static str = "BenchPayload";
}

/// Non-constant bytes so nothing downstream can collapse the payload.
fn payload(len: usize) -> BenchPayload {
    BenchPayload {
        data: (0..len).map(|i| (i % 251) as u8).collect(),
    }
}

fn sizes_mib() -> Vec<usize> {
    match std::env::var("KMS_BENCH_SIZES_MIB") {
        Ok(raw) => raw
            .split(',')
            .map(|s| {
                s.trim().parse().unwrap_or_else(|e| {
                    panic!("KMS_BENCH_SIZES_MIB entry {s:?} is not a size: {e}")
                })
            })
            .collect(),
        Err(_) => DEFAULT_SIZES_MIB.to_vec(),
    }
}

/// Point a client at the local MinIO. Path-style addressing because MinIO does not serve
/// virtual-hosted buckets on a bare host:port.
fn s3_client(endpoint: String) -> S3Client {
    let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
    let access_key = std::env::var("AWS_ACCESS_KEY_ID").expect("AWS_ACCESS_KEY_ID must be set");
    let secret_key =
        std::env::var("AWS_SECRET_ACCESS_KEY").expect("AWS_SECRET_ACCESS_KEY must be set");
    let conf = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(region))
        .endpoint_url(endpoint)
        .force_path_style(true)
        .credentials_provider(Credentials::new(
            access_key,
            secret_key,
            None,
            None,
            "kms-bench",
        ))
        .build();
    S3Client::from_conf(conf)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // Multi-thread on purpose: the production runtime is multi-thread, which is the flavor
    // where the serializer runs under `block_in_place`.
    let (Ok(endpoint), Ok(bucket)) = (
        std::env::var("KMS_BENCH_S3_ENDPOINT"),
        std::env::var("KMS_BENCH_S3_BUCKET"),
    ) else {
        println!(
            "skipping: set KMS_BENCH_S3_ENDPOINT and KMS_BENCH_S3_BUCKET to run this bench \
             (see the module docs for the compose-provided MinIO)"
        );
        return;
    };

    let mut storage = S3Storage::new(
        s3_client(endpoint),
        bucket,
        StorageType::PUB,
        Some("bench-peak-memory"),
    )
    .expect("failed to build the S3 storage");

    println!("payload_mib  resident_bytes  peak_bytes  extra_bytes  extra_mib");
    for (i, mib) in sizes_mib().into_iter().enumerate() {
        let data = payload(mib * MIB);
        // A fresh id per size, and per run of a given size, so a leftover object from an
        // earlier run cannot turn the store into a no-op that measures nothing.
        let req_id = RequestId::from_bytes([i as u8 + 1; 32]);
        // `store_data` refuses to overwrite, so an object left behind by an interrupted run
        // would turn the store into a no-op that measures nothing. Clear it first.
        let _ = storage.delete_data(&req_id, BenchPayload::NAME).await;

        // Reset to the current load, so `peak_usage` is measured against a baseline that
        // already includes the resident payload; the difference is the storage layer's own
        // buffering.
        PEAK.reset_peak_usage();
        let resident = PEAK.current_usage();
        storage
            .store_data(&data, &req_id, BenchPayload::NAME)
            .await
            .expect("store failed");
        let peak = PEAK.peak_usage();

        let extra = peak.saturating_sub(resident);
        println!(
            "{mib:>11}  {resident:>14}  {peak:>10}  {extra:>11}  {:>9.1}",
            extra as f64 / MIB as f64
        );

        storage
            .delete_data(&req_id, BenchPayload::NAME)
            .await
            .expect("cleanup failed");
        drop(data);
    }
}
