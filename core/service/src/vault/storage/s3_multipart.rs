//! Streaming multipart upload of serialized objects to S3.
//!
//! [`s3_put_versioned`] is the entry point: payloads that fit in one part
//! buffer go out as a single `PutObject`; larger ones stream through an
//! [`S3PartWriter`] into a bounded part queue drained by a dedicated uploader
//! thread, so peak memory stays at O(part size) instead of O(object size).

use super::s3::s3_put_blob;
use crate::consts::SAFE_SER_SIZE_LIMIT;
use aws_sdk_s3::{
    Client as S3Client,
    error::ProvideErrorMetadata,
    primitives::ByteStream,
    types::{ChecksumAlgorithm, CompletedMultipartUpload, CompletedPart},
};
use serde::Serialize;
use std::sync::mpsc;
use tfhe::{Versionize, named::Named, safe_serialization::safe_serialize};
use tokio::sync::oneshot;

/// Serialized bytes buffered per multipart part. 16 MiB keeps peak memory at
/// O(part size) while a maximal 2 GiB (`SAFE_SER_SIZE_LIMIT`) object still
/// yields only 128 parts, far below the S3 limit of 10,000.
pub(super) const S3_MULTIPART_PART_SIZE: usize = 16 * 1024 * 1024;

/// S3's minimum size for every multipart part except the last.
pub(super) const S3_MULTIPART_MIN_PART_SIZE: usize = 5 * 1024 * 1024;

const _: () = assert!(S3_MULTIPART_PART_SIZE >= S3_MULTIPART_MIN_PART_SIZE);

// A maximal `SAFE_SER_SIZE_LIMIT` payload must fit within S3's 10,000-part cap
// at this part size. Guards the production config (128 parts today) at compile
// time so a future bump to the size limit or drop in part size fails the build
// instead of surfacing only at `CompleteMultipartUpload`, after the whole
// object has been uploaded.
const _: () = assert!(SAFE_SER_SIZE_LIMIT.div_ceil(S3_MULTIPART_PART_SIZE as u64) <= 10_000);

/// Queue depth between the serializing task and the uploader thread. Bounds
/// in-flight memory at `(3 + capacity) * part_size` — 64 MiB today — for the
/// buffer being filled, the one in a blocking send, the queued one, and the one
/// being shipped. Fewer coexist unless the upload is the bottleneck.
const PART_CHANNEL_CAPACITY: usize = 1;

/// Upload id (if the multipart upload was created) plus the uploaded parts or
/// the first upload error.
type MultipartUploadResult = (Option<String>, anyhow::Result<Vec<CompletedPart>>);

/// Channel ends connecting an [`S3PartWriter`] to its uploader thread.
struct MultipartPipeline {
    part_tx: mpsc::SyncSender<Vec<u8>>,
    result_rx: oneshot::Receiver<MultipartUploadResult>,
}

/// Outcome of a finished serialization stream: either the whole payload fit in
/// one buffer (store it with a single PUT) or the multipart pipeline ran.
enum PartWriterOutcome {
    Single(Vec<u8>),
    Multipart(oneshot::Receiver<MultipartUploadResult>),
}

/// Builds the S3 client that serves one multipart upload, called at most once and
/// only when the payload actually outgrows the first part buffer.
///
/// Deferred so the single-PUT path — most writes by count — never builds a client
/// it does not use. Tests pass a mock client straight through: deriving one from a
/// config strips the mock transport.
pub(super) type UploaderClientFactory = Box<dyn FnOnce() -> S3Client + Send>;

/// `std::io::Write` sink that buffers serialized bytes into `part_size` chunks
/// and, once the payload outgrows the first chunk, streams them to S3 as a
/// multipart upload.
///
/// The serializer runs on the calling async task (it borrows the element, so
/// it cannot move into `spawn_blocking`) — under `block_in_place` on
/// multi-thread runtimes, inline otherwise (see [`s3_put_versioned`]) — while
/// a dedicated uploader thread drains the bounded part queue, so
/// serialization and upload overlap without unbounded buffering.
///
/// `make_client` builds the upload's own S3 client (see [`UploaderClientFactory`])
/// rather than the writer deriving one itself, so the uploader never inherits
/// anything from the caller's client implicitly — and so a payload that never
/// spills never builds a client at all.
pub(super) struct S3PartWriter {
    make_client: Option<UploaderClientFactory>,
    bucket: String,
    key: String,
    part_size: usize,
    buf: Vec<u8>,
    total_written: u64,
    pipeline: Option<MultipartPipeline>,
}

impl S3PartWriter {
    pub(super) fn new(
        make_client: UploaderClientFactory,
        bucket: &str,
        key: &str,
        part_size: usize,
    ) -> Self {
        // Callers pass `S3_MULTIPART_PART_SIZE` or a test constant, so this
        // cannot fire in correct execution. Not a `debug_assert`: in release
        // S3 would only reject an undersized part at CompleteMultipartUpload,
        // once the whole object has already been uploaded.
        assert!(part_size >= S3_MULTIPART_MIN_PART_SIZE);
        Self {
            make_client: Some(make_client),
            bucket: bucket.to_string(),
            key: key.to_string(),
            part_size,
            buf: Vec::new(),
            total_written: 0,
            pipeline: None,
        }
    }

    /// Ship the full buffer to the uploader thread, spawning it on first use.
    fn spill(&mut self) -> std::io::Result<()> {
        if self.pipeline.is_none() {
            let (part_tx, part_rx) = mpsc::sync_channel(PART_CHANNEL_CAPACITY);
            let (result_tx, result_rx) = oneshot::channel();
            // Consumed here, so a failed spawn below must not leave a panicking retry.
            let make_client = self.make_client.take().ok_or_else(|| {
                std::io::Error::other("the S3 uploader thread already failed to spawn")
            })?;
            let (client, bucket, key) = (make_client(), self.bucket.clone(), self.key.clone());
            // A child span, not the request span: `tracing-opentelemetry` counts
            // busy time per span, so entering the request span here would bill it
            // the whole upload and defer its export until this thread exits.
            let span = tracing::info_span!("s3_multipart_upload", key = %self.key);
            std::thread::Builder::new()
                .name("s3-multipart-upload".to_string())
                .spawn(move || {
                    let _guard = span.entered();
                    run_multipart_uploader(client, bucket, key, part_rx, result_tx)
                })
                .map_err(|e| {
                    std::io::Error::other(format!("failed to spawn the S3 uploader thread: {e}"))
                })?;
            tracing::info!(
                "Streaming multipart upload engaged for key {} ({} byte parts)",
                self.key,
                self.part_size
            );
            self.pipeline = Some(MultipartPipeline { part_tx, result_rx });
        }
        let part = std::mem::replace(&mut self.buf, Vec::with_capacity(self.part_size));
        let pipeline = self.pipeline.as_ref().expect("pipeline installed above");
        pipeline.part_tx.send(part).map_err(|_| {
            std::io::Error::other("S3 multipart uploader stopped; it reports the root cause")
        })
    }

    /// Finish the stream. The non-empty tail part is sent only when
    /// serialization succeeded; closing the channel lets the uploader exit.
    fn finish(mut self, serialization_ok: bool) -> PartWriterOutcome {
        match self.pipeline.take() {
            None => PartWriterOutcome::Single(self.buf),
            Some(pipeline) => {
                if serialization_ok && !self.buf.is_empty() {
                    // A send error means the uploader already failed; that
                    // error arrives through the result channel.
                    let _ = pipeline.part_tx.send(std::mem::take(&mut self.buf));
                }
                drop(pipeline.part_tx);
                PartWriterOutcome::Multipart(pipeline.result_rx)
            }
        }
    }
}

impl std::io::Write for S3PartWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        // Spill only once bytes arrive *past* a full buffer, so a payload of exactly
        // one part stays on the single-PUT path. The `min` below caps growth, making
        // `>=` equality today; it stays correct if that ever changes.
        debug_assert!(
            self.buf.len() <= self.part_size,
            "write must never grow buf past part_size"
        );
        if self.buf.len() >= self.part_size {
            self.spill()?;
        }
        let n = std::cmp::min(self.part_size - self.buf.len(), data.len());
        self.buf.extend_from_slice(&data[..n]);
        self.total_written += n as u64;
        Ok(n)
    }

    // Never flush a partial buffer: every part but the last must be at least
    // `S3_MULTIPART_MIN_PART_SIZE`, and only `finish` knows which is last.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Builds the S3 client that serves one streaming multipart upload.
///
/// The uploader runs on its own thread and runtime (see
/// [`run_multipart_uploader`]), so it must not share transport or cached
/// credentials with `base_config`'s client: those are driven by the caller's
/// runtime, which on the current-thread flavor is frozen inside the serializer
/// for the whole upload, and on any flavor would otherwise serve this upload's
/// parts through the pool and single-flighting identity cache every other
/// storage operation is contending for.
///
/// Endpoint, region and the credentials *provider* are inherited — the caller's
/// config is the only source of those. Note the provider is the one piece of the
/// caller's machinery `set_http_client(None)` does not isolate: it carries its
/// own transport for fetching credentials. Everything else the upload depends on
/// is either pinned below or, for the identity load timeout, kept in step with
/// the rest of the service through a shared constant.
pub(super) fn build_multipart_upload_client(base_config: &aws_sdk_s3::Config) -> S3Client {
    let mut config = base_config.to_builder();
    // Sharing the caller's HTTP client could hand out pooled connections that
    // are driven by the caller's runtime, which can sit blocked in the
    // serializer while this upload runs; force a fresh pool instead.
    config.set_http_client(None);
    // Same for the identity cache: the caller's lazy cache single-flights
    // credential refreshes, so waiting here on a refresh started by a task on
    // the caller's (blocked) runtime would deadlock the pipeline. The
    // credentials provider behind the fresh cache is still shared.
    //
    // The load timeout has to be restated rather than inherited — a
    // `SharedIdentityCache` cannot be read back off the config — and this cache
    // is always cold, so every upload pays a real credential load against it.
    // Leaving it at the SDK default of 5 s would make large stores the only
    // operation in the process without the tuned budget (see
    // [`crate::vault::aws::IDENTITY_LOAD_TIMEOUT`]).
    config.set_identity_cache(
        aws_sdk_s3::config::IdentityCache::lazy()
            .load_timeout(crate::vault::aws::IDENTITY_LOAD_TIMEOUT)
            .build(),
    );
    // Bound each attempt so a black-holed connection cannot pin the uploader
    // — and the serializer blocked in `send` — forever. 600 s still clears a
    // 16 MiB part at ~27 KiB/s.
    config.set_timeout_config(Some(
        aws_sdk_s3::config::timeout::TimeoutConfig::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .operation_attempt_timeout(std::time::Duration::from_secs(600))
            .build(),
    ));
    // Pin checksum calculation so an ambient `when_required` setting (env or
    // profile) cannot strip the per-part CRC32 that the declared algorithm in
    // `run_multipart_uploader` obliges every part to carry.
    config.set_request_checksum_calculation(Some(
        aws_sdk_s3::config::RequestChecksumCalculation::WhenSupported,
    ));
    S3Client::from_conf(config.build())
}

/// Uploads parts received over `part_rx` to a new multipart upload of
/// `bucket`/`key`, reporting the outcome over `result_tx`.
///
/// Runs on a dedicated OS thread with its own current-thread runtime. Dropping
/// `part_rx` on error unblocks the serializing side with a send error.
///
/// The thread must start unconditionally, because the serializer blocks on the
/// bounded part channel and would stall until the uploader drains it.
/// `tokio::spawn` never runs on a current-thread runtime (the serializer holds
/// the only thread), and `spawn_blocking` queues while its pool is saturated —
/// as does `block_in_place`'s own core handoff. The cost is one OS thread
/// outside the tokio/rayon split, live only during a >1-part store.
fn run_multipart_uploader(
    client: S3Client,
    bucket: String,
    key: String,
    part_rx: mpsc::Receiver<Vec<u8>>,
    result_tx: oneshot::Sender<MultipartUploadResult>,
) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = result_tx.send((
                None,
                Err(anyhow::anyhow!("failed to build S3 uploader runtime: {e}")),
            ));
            return;
        }
    };

    // The SDK adds a CRC32 checksum to every part under `WhenSupported`;
    // declaring the algorithm up front keeps create/upload/complete consistent.
    let created = rt.block_on(
        client
            .create_multipart_upload()
            .bucket(&bucket)
            .key(&key)
            .checksum_algorithm(ChecksumAlgorithm::Crc32)
            .send(),
    );
    let upload_id = match created {
        Ok(out) => match out.upload_id {
            Some(id) => id,
            None => {
                let _ = result_tx.send((
                    None,
                    Err(anyhow::anyhow!("S3 returned no upload id for key {key}")),
                ));
                return;
            }
        },
        Err(err) => {
            tracing::error!("{:?} {:?}", err.meta(), err.code());
            let _ = result_tx.send((
                None,
                Err(anyhow::anyhow!(
                    "AWS error creating multipart upload for key {key}: {err}"
                )),
            ));
            return;
        }
    };

    let mut parts = Vec::new();
    // Parts are numbered from 1; the serialized-size limit caps the count far
    // below S3's maximum of 10,000.
    while let Ok(part_buf) = part_rx.recv() {
        let part_number = parts.len() as i32 + 1;
        match rt.block_on(
            client
                .upload_part()
                .bucket(&bucket)
                .key(&key)
                .upload_id(&upload_id)
                .part_number(part_number)
                .body(ByteStream::from(part_buf))
                .send(),
        ) {
            Ok(out) => parts.push(
                CompletedPart::builder()
                    .part_number(part_number)
                    .set_e_tag(out.e_tag)
                    .set_checksum_crc32(out.checksum_crc32)
                    .build(),
            ),
            Err(err) => {
                tracing::error!("{:?} {:?}", err.meta(), err.code());
                // Returning drops `part_rx`, which fails the serializer's next
                // send and unwinds the store operation.
                let _ = result_tx.send((
                    Some(upload_id),
                    Err(anyhow::anyhow!(
                        "AWS error uploading part {part_number} for key {key}: {err}"
                    )),
                ));
                return;
            }
        }
    }
    let _ = result_tx.send((Some(upload_id), Ok(parts)));
}

/// Best-effort abort of a multipart upload; failures are only logged, leaving
/// the orphaned parts for a bucket `AbortIncompleteMultipartUpload` lifecycle
/// rule (if configured) to reclaim.
async fn abort_multipart_upload_best_effort(
    s3_client: &S3Client,
    bucket: &str,
    key: &str,
    upload_id: &str,
) {
    tracing::warn!("Aborting multipart upload {upload_id} for key {key}");
    if let Err(err) = s3_client
        .abort_multipart_upload()
        .bucket(bucket)
        .key(key)
        .upload_id(upload_id)
        .send()
        .await
    {
        tracing::error!(
            "Failed to abort multipart upload {upload_id} for key {key}: {:?} {:?}",
            err.meta(),
            err.code()
        );
    }
}

/// Safe-serializes `data` (versioned) and stores it under `key` in `bucket`,
/// returning the total number of serialized bytes.
///
/// Payloads that fit in one `part_size` buffer are stored with a single
/// `PutObject` through `s3_client`; larger ones are streamed as an S3 multipart
/// upload, so the full serialized blob never exists in memory. `make_uploader`
/// builds the client driving the part-shipping half of that
/// (`CreateMultipartUpload` and `UploadPart`, which run on the uploader thread);
/// completing and aborting go through `s3_client`, since those happen on this
/// task once the serializer is done and so carry no risk of waiting on the
/// caller's blocked runtime.
/// Visibility is all-or-nothing: the object appears only once
/// `CompleteMultipartUpload` succeeds. Reported failures abort the upload
/// best-effort; a panic or a cancelled future can still leave an incomplete
/// upload behind for a bucket lifecycle rule (if configured) to reclaim.
///
/// `make_uploader` is called at most once and never on the single-PUT path; see
/// [`UploaderClientFactory`].
pub(super) async fn s3_put_versioned<T: Serialize + Versionize + Named>(
    s3_client: &S3Client,
    make_uploader: UploaderClientFactory,
    bucket: &str,
    key: &str,
    data: &T,
    part_size: usize,
    size_limit: u64,
) -> anyhow::Result<u64> {
    let mut writer = S3PartWriter::new(make_uploader, bucket, key, part_size);
    // The serializer borrows `data`, so it cannot move into `spawn_blocking`;
    // it runs on this task, blocking in `spill` at upload pace once the
    // payload exceeds one part (see [`run_blocking`]).
    let ser_result = run_blocking(|| safe_serialize(data, &mut writer, size_limit)).map_err(|e| {
        anyhow::anyhow!(
            "failed to serialize {} for key {key}: {e}",
            <T as Named>::NAME
        )
    });
    s3_finish_put(s3_client, bucket, key, writer, ser_result).await
}

/// Run blocking pipeline work off the async scheduler: under `block_in_place`
/// on multi-thread runtimes so the worker's other tasks keep running;
/// `block_in_place` panics on current-thread runtimes (tests), where the work
/// simply runs inline and blocks the runtime while the uploader thread makes
/// progress on its own.
///
/// Not `thread_handles::spawn_compute_bound`: that requires a `'static + Send`
/// closure and dispatches to rayon, while this closure borrows the element
/// being serialized (non-`'static`, must stay on this thread) and blocks at
/// upload pace on the part channel — I/O-paced waiting the rayon compute pool
/// is not budgeted for.
fn run_blocking<R>(f: impl FnOnce() -> R) -> R {
    if tokio::runtime::Handle::current().runtime_flavor()
        == tokio::runtime::RuntimeFlavor::MultiThread
    {
        tokio::task::block_in_place(f)
    } else {
        f()
    }
}

/// Complete the store fed through an [`S3PartWriter`]: a single PUT for
/// payloads that never spilled, otherwise complete or abort the multipart
/// upload depending on `ser_result` and the uploader outcome. Returns the
/// total number of bytes written to `writer`.
pub(super) async fn s3_finish_put(
    s3_client: &S3Client,
    bucket: &str,
    key: &str,
    writer: S3PartWriter,
    ser_result: anyhow::Result<()>,
) -> anyhow::Result<u64> {
    let total_written = writer.total_written;
    let serialization_ok = ser_result.is_ok();
    // Once the pipeline is engaged, the tail-part send in `finish` blocks on
    // the bounded channel just like `spill`, so it needs the same
    // off-scheduler treatment as the serializer; the single-PUT path cannot
    // block and skips that overhead.
    let outcome = if writer.pipeline.is_some() {
        run_blocking(move || writer.finish(serialization_ok))
    } else {
        writer.finish(serialization_ok)
    };
    match outcome {
        PartWriterOutcome::Single(buf) => {
            ser_result?;
            s3_put_blob(s3_client, bucket, key, buf).await?;
        }
        PartWriterOutcome::Multipart(result_rx) => {
            let (upload_id, upload_result) = result_rx.await.map_err(|_| {
                anyhow::anyhow!(
                    "S3 multipart uploader thread died for key {key}; an incomplete \
                     multipart upload may linger unless a bucket lifecycle rule reaps it"
                )
            })?;
            let parts = match (upload_result, ser_result) {
                (Ok(parts), Ok(())) => parts,
                // The uploader error is the root cause: its failure closes the
                // part channel, which the serializer then sees as a write error.
                (Err(upload_err), _) => {
                    if let Some(id) = &upload_id {
                        abort_multipart_upload_best_effort(s3_client, bucket, key, id).await;
                    }
                    return Err(upload_err);
                }
                (Ok(_), Err(ser_err)) => {
                    if let Some(id) = &upload_id {
                        abort_multipart_upload_best_effort(s3_client, bucket, key, id).await;
                    }
                    return Err(ser_err);
                }
            };
            // The uploader only reports Ok after the channel closed, i.e. once
            // every part (including the tail sent by `finish`) was uploaded.
            let upload_id = upload_id.expect("upload id accompanies uploaded parts");
            let part_count = parts.len();
            let completed = CompletedMultipartUpload::builder()
                .set_parts(Some(parts))
                .build();
            if let Err(err) = s3_client
                .complete_multipart_upload()
                .bucket(bucket)
                .key(key)
                .upload_id(&upload_id)
                .multipart_upload(completed)
                .send()
                .await
            {
                tracing::error!("{:?} {:?}", err.meta(), err.code());
                abort_multipart_upload_best_effort(s3_client, bucket, key, &upload_id).await;
                return Err(anyhow::anyhow!(
                    "AWS error completing multipart upload for key {key}: {err}"
                ));
            }
            tracing::info!(
                "Completed multipart upload of {total_written} bytes in {part_count} parts for key {key}"
            );
        }
    }
    Ok(total_written)
}

/// Unit tests for [`S3PartWriter`]'s buffering. Unlike the storage-level suite in
/// `s3.rs`, these need no S3 service at all — no mock, no MinIO, no credentials:
/// they assert on the writer's local state
/// only, so they also run without the `testing` feature that gates the mock. The
/// single-PUT paths never spill, and the one spilling test points the (spawned,
/// retry-disabled) uploader at a refused local port and never awaits it.
#[cfg(test)]
mod part_writer_tests {
    use super::*;
    use aws_sdk_s3::config::Region;
    use std::io::Write;

    fn refused_config() -> aws_sdk_s3::Config {
        aws_sdk_s3::config::Builder::new()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test",
                "test",
                None,
                None,
                "part-writer-test",
            ))
            // Nothing listens here, so a spilled part's upload fails at once.
            .endpoint_url("http://127.0.0.1:1")
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
            .force_path_style(true)
            .build()
    }

    fn writer(part_size: usize) -> S3PartWriter {
        // Same shape as production: the client is built by the factory, so the
        // non-spilling tests below build no client at all.
        S3PartWriter::new(
            Box::new(|| build_multipart_upload_client(&refused_config())),
            "bucket",
            "key",
            part_size,
        )
    }

    /// A single write fills the buffer up to `part_size` but never spills: a
    /// spill fires only when more bytes arrive after the buffer is full, and a
    /// write caps at the remaining capacity so the buffer never overflows.
    #[test]
    fn write_fills_to_part_size_without_spilling() {
        let part_size = S3_MULTIPART_MIN_PART_SIZE;
        let mut w = writer(part_size);
        let n = w.write(&vec![0u8; part_size + 100]).unwrap();
        assert_eq!(n, part_size, "a write caps at the remaining part capacity");
        assert_eq!(w.buf.len(), part_size);
        assert!(w.pipeline.is_none(), "filling the buffer must not spill");
        assert_eq!(w.total_written, part_size as u64);
    }

    /// A payload that fits in one buffer finishes on the single-PUT fast path.
    #[test]
    fn sub_part_payload_finishes_single() {
        let mut w = writer(S3_MULTIPART_MIN_PART_SIZE);
        w.write_all(&[0u8; 1024]).unwrap();
        assert!(w.pipeline.is_none());
        assert_eq!(w.total_written, 1024);
        match w.finish(true) {
            PartWriterOutcome::Single(buf) => assert_eq!(buf.len(), 1024),
            PartWriterOutcome::Multipart(_) => panic!("small payload must stay single-PUT"),
        }
    }

    /// The single-PUT path must not build an uploader client at all. Every write in
    /// normal operation takes this path, and building a client there costs a TLS
    /// connector (~55 µs measured) that is then thrown away.
    #[test]
    fn single_put_never_builds_an_uploader_client() {
        let part_size = S3_MULTIPART_MIN_PART_SIZE;
        let mut w = S3PartWriter::new(
            Box::new(|| panic!("the uploader client must not be built on the single-PUT path")),
            "bucket",
            "key",
            part_size,
        );
        w.write_all(&vec![0u8; part_size]).unwrap();
        match w.finish(true) {
            PartWriterOutcome::Single(buf) => assert_eq!(buf.len(), part_size),
            PartWriterOutcome::Multipart(_) => panic!("exact-part payload must stay single-PUT"),
        }
    }

    /// A payload of exactly one part also stays single-PUT: serialization ends
    /// before any further write can trigger the spill-on-next-write rule.
    #[test]
    fn exact_part_payload_finishes_single() {
        let part_size = S3_MULTIPART_MIN_PART_SIZE;
        let mut w = writer(part_size);
        w.write_all(&vec![0u8; part_size]).unwrap();
        assert!(w.pipeline.is_none());
        match w.finish(true) {
            PartWriterOutcome::Single(buf) => assert_eq!(buf.len(), part_size),
            PartWriterOutcome::Multipart(_) => panic!("exact-part payload must stay single-PUT"),
        }
    }

    /// One byte past a full buffer spills the full `part_size` part and engages
    /// the pipeline, leaving only the overflow buffered. `finish` is
    /// intentionally not called: with the pipeline engaged its tail send would
    /// block on the (dead) uploader; dropping the writer closes the channel and
    /// lets the uploader thread exit.
    #[test]
    fn crossing_part_boundary_engages_pipeline() {
        let part_size = S3_MULTIPART_MIN_PART_SIZE;
        let mut w = writer(part_size);
        w.write_all(&vec![0u8; part_size]).unwrap();
        assert!(
            w.pipeline.is_none(),
            "a full-but-not-exceeded buffer has not spilled yet"
        );
        w.write_all(&[7u8; 1]).unwrap();
        assert!(
            w.pipeline.is_some(),
            "exceeding one part must engage the multipart pipeline"
        );
        assert_eq!(w.buf.len(), 1, "only the overflow byte stays buffered");
        assert_eq!(w.total_written, part_size as u64 + 1);
    }
}
