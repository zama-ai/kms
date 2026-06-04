use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io::Write;
use std::path::{Path, PathBuf};
use tfhe::named::Named;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::{Unversionize, Versionize};

use crate::consts::SAFE_SER_SIZE_LIMIT;

/// Write some bytes to a file without serialization. Works for ASCII text without extra thought too.
pub async fn write_bytes<P: AsRef<Path>>(file_path: P, bytes: &[u8]) -> anyhow::Result<()> {
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = file_path.as_ref().parent() {
        tokio::fs::create_dir_all(p).await?
    };
    tokio::fs::write(file_path, bytes).await?;
    Ok(())
}

/// Best-effort cleanup for the sibling temp file used by
/// [`safe_write_element_versioned`]. On drop it removes the temp file unless it
/// has been [`disarm`](TempFileGuard::disarm)ed (which only happens after a
/// successful rename), so a failed write — at any of the create / serialize /
/// flush / rename steps — never strands an orphaned `.<name>.partial.*` file.
struct TempFileGuard {
    path: Option<PathBuf>,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    /// Disarm the guard once the temp file has been renamed into place, so the
    /// now-persisted file is not removed.
    fn disarm(mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            // Best-effort: the primary error (if any) has already propagated to
            // the caller, so a failure to clean up here must not mask it.
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// This is a wrapper around safe_serialize versioned for the async use case.
///
/// The serialization is streamed straight to disk (into a sibling temp file that
/// is then atomically renamed into place) instead of going through an in-memory
/// `Vec<u8>`. For production FHE keys the serialized blob is ~tens of GiB, and
/// buffering it in memory would roughly double peak RSS at write time by holding
/// the full serialized copy alongside `element`. The serialize+write is run
/// inline (synchronously): `safe_serialize` borrows `element`, so it cannot be
/// moved into `spawn_blocking`, and `block_in_place` would panic on the
/// current-thread runtimes used by the storage tests. Key writes happen once per
/// keygen, so briefly blocking the worker thread here is acceptable.
///
/// On any write error (create / serialize / flush / rename) the temp file is
/// removed before returning (see [`TempFileGuard`]); without this, repeated
/// failures (e.g. disk full / permission issues) would accumulate hidden,
/// uniquely-named partials and waste disk space.
pub async fn safe_write_element_versioned<
    T: Serialize + Versionize + Named + Send,
    P: AsRef<Path>,
>(
    file_path: P,
    element: &T,
) -> anyhow::Result<()> {
    let file_path = file_path.as_ref();
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = file_path.parent() {
        tokio::fs::create_dir_all(p).await?
    };
    // Write to a sibling temp file first, then atomically rename into place, so a
    // crash mid-write cannot leave a partially-serialized key file at `file_path`.
    // The temp name is dot-prefixed (hidden): if a crash leaves one behind, directory
    // listings skip it (e.g. `FileStorage::all_data_ids` ignores dot-files but parses
    // every other name as a `RequestId`, so a non-hidden leftover would break listing).
    // The name also carries a per-writer suffix (process id + a process-local counter)
    // so two concurrent writers to the same `file_path` cannot create, interleave, and
    // rename the same temp file. A fixed name is not safe here: this function is also
    // called outside the storage layer (e.g. `kms-custodian`), and the storage-layer
    // mutex is per-instance, so it guards neither separate processes nor separate
    // storage instances pointed at the same directory.
    let tmp_path = {
        let file_name = file_path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("invalid file path: {}", file_path.display()))?;
        // Unique among all live writers: the pid distinguishes processes and the
        // counter distinguishes concurrent writes within this process.
        static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut name = std::ffi::OsString::from(".");
        name.push(file_name);
        name.push(format!(".partial.{}.{seq}", std::process::id()));
        match file_path.parent() {
            Some(parent) => parent.join(name),
            None => PathBuf::from(name),
        }
    };
    // Remove the temp file on any early return below (a failed create / serialize /
    // flush / rename); only a successful rename disarms it.
    let cleanup = TempFileGuard::new(tmp_path.clone());
    {
        let file = std::fs::File::create(&tmp_path)
            .map_err(|e| anyhow::anyhow!("failed to create {}: {e}", tmp_path.display()))?;
        let mut writer = std::io::BufWriter::new(file);
        safe_serialize(element, &mut writer, SAFE_SER_SIZE_LIMIT)?;
        writer
            .flush()
            .map_err(|e| anyhow::anyhow!("failed to flush {}: {e}", tmp_path.display()))?;
    }
    tokio::fs::rename(&tmp_path, file_path).await?;
    // The temp file has become `file_path`; keep it instead of removing it.
    cleanup.disarm();
    Ok(())
}

pub async fn safe_read_element_versioned<
    T: DeserializeOwned + Unversionize + Named + Send,
    P: AsRef<Path>,
>(
    file_path: P,
) -> anyhow::Result<T> {
    let mut buf = std::io::Cursor::new(tokio::fs::read(file_path.as_ref()).await.map_err(|e| {
        anyhow::anyhow!(
            "failed to read file path at {} due to {e}",
            file_path.as_ref().display()
        )
    })?);
    safe_deserialize(&mut buf, SAFE_SER_SIZE_LIMIT).map_err(|e| anyhow::anyhow!(e))
}

/// Writing a generic element to a file by serializing it. This is hidden behind the testing flag to ensure only the safe and versioned writing method
/// is used in production code.
#[cfg(any(test, feature = "testing"))]
pub async fn write_element<T: serde::Serialize, P: AsRef<Path>>(
    file_path: P,
    element: &T,
) -> anyhow::Result<()> {
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = file_path.as_ref().parent() {
        tokio::fs::create_dir_all(p).await?
    };
    let serialized_data = bc2wrap::serialize(element)?;
    tokio::fs::write(file_path, serialized_data.as_slice()).await?;
    Ok(())
}

/// Reading a generic element to a file. This is hidden behind the testing flag to ensure only the safe and versioned reading method
/// is used in production code.
#[cfg(any(test, feature = "testing"))]
pub async fn read_element<T: DeserializeOwned + Serialize, P: AsRef<Path>>(
    file_path: P,
) -> anyhow::Result<T> {
    let read_element = tokio::fs::read(file_path).await?;
    // This is gated behind a testing flag, so we can use the unsafe deserialization here
    // (Might be useful to deserialize keys which may be huge)
    Ok(bc2wrap::deserialize_unsafe(read_element.as_slice())?)
}

#[cfg(test)]
mod tests {
    use crate::util::file_handling::{
        read_element, safe_read_element_versioned, safe_write_element_versioned, write_bytes,
        write_element,
    };
    use crate::vault::storage::tests::TestType;
    use tokio::fs::remove_file;

    #[tokio::test]
    async fn read_write_text() {
        let msg = "Jeg ælsker ☕!".to_owned();
        let file_name = tempfile::tempdir()
            .unwrap()
            .path()
            .join("read-write-test.txt");
        write_bytes(&file_name, msg.as_bytes()).await.unwrap();
        let read_element: String =
            String::from_utf8(tokio::fs::read(&file_name).await.unwrap()).unwrap();
        assert_eq!(read_element, msg);
    }

    #[tokio::test]
    async fn read_write_element() {
        let msg = "I am a teacup!".to_owned();
        let file_name = "temp/test_element.bin".to_string();
        write_element(file_name.clone(), &msg.clone())
            .await
            .unwrap();
        let read_element: String = read_element(file_name.clone()).await.unwrap();
        assert_eq!(read_element, msg);
        remove_file(file_name).await.unwrap();
    }

    // Sunshine: a versioned element written with `safe_write_element_versioned`
    // round-trips through `safe_read_element_versioned`.
    #[tokio::test]
    async fn safe_write_then_read_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("element");
        let element = TestType { i: 7 };
        safe_write_element_versioned(&path, &element).await.unwrap();
        let read_back: TestType = safe_read_element_versioned(&path).await.unwrap();
        assert_eq!(read_back, element);
    }

    // A successful write must leave only the final file behind: the dot-prefixed
    // `.<name>.partial.*` temp file is renamed into place, not left as litter.
    #[tokio::test]
    async fn safe_write_leaves_no_partial_tempfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("element");
        safe_write_element_versioned(&path, &TestType { i: 1 })
            .await
            .unwrap();
        assert!(path.exists());
        let leftovers: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".partial"))
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
    }

    // A failed write must not strand a `.<name>.partial.*` temp file. Here the
    // final rename fails because the destination is an existing directory; the
    // cleanup guard must still remove the partial that was already written.
    #[tokio::test]
    async fn safe_write_cleans_up_partial_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        // Make the destination an existing directory so the final rename fails
        // (a file cannot be renamed on top of a directory).
        let path = dir.path().join("element");
        std::fs::create_dir(&path).unwrap();

        let res = safe_write_element_versioned(&path, &TestType { i: 3 }).await;
        assert!(res.is_err(), "write onto an existing directory should fail");

        let leftovers: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".partial"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "failed write left partial temp files: {leftovers:?}"
        );
    }

    // A path with no file name component is rejected before any file is touched.
    #[tokio::test]
    async fn safe_write_rejects_path_without_filename() {
        let res = safe_write_element_versioned(std::path::Path::new("/"), &TestType { i: 0 }).await;
        assert!(res.is_err());
    }

    // Concurrent writers targeting the same path must not collide on the temp file:
    // every write succeeds and the destination is left as a complete, valid element
    // (one writer's value), never a corrupted interleaving. Run on a multi-thread
    // runtime so the inline blocking I/O of the writers actually overlaps.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_writes_to_same_path_are_not_corrupted() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::sync::Arc::new(dir.path().join("element"));
        let mut handles = Vec::new();
        for i in 0..8u32 {
            let path = std::sync::Arc::clone(&path);
            handles.push(tokio::spawn(async move {
                safe_write_element_versioned(path.as_path(), &TestType { i }).await
            }));
        }
        for h in handles {
            // No write may fail with a spurious collision error.
            h.await.unwrap().unwrap();
        }
        // The destination deserializes to one of the written values, i.e. it is a
        // complete element rather than a mix of several writers' bytes.
        let read_back: TestType = safe_read_element_versioned(path.as_path()).await.unwrap();
        assert!(read_back.i < 8, "unexpected value {}", read_back.i);
        let leftovers: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".partial"))
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
    }

    // If the write fails before the rename (here: the sibling temp file cannot be
    // created because the parent directory is read-only), a pre-existing destination
    // must be left untouched rather than truncated or partially overwritten.
    #[cfg(unix)]
    #[tokio::test]
    async fn safe_write_failure_keeps_existing_destination() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("element");

        // Seed the destination with a known-good element.
        let original = TestType { i: 111 };
        safe_write_element_versioned(&path, &original)
            .await
            .unwrap();

        // Make the parent read-only so the temp file cannot be created.
        let saved = std::fs::metadata(dir.path()).unwrap().permissions();
        let mut read_only = saved.clone();
        read_only.set_mode(0o555);
        std::fs::set_permissions(dir.path(), read_only).unwrap();

        // Self-guard: if files can still be created here (e.g. running as root, which
        // ignores directory permissions) the failure can't be induced, so skip the
        // negative assertion rather than fail spuriously.
        let probe = dir.path().join(".probe");
        let perms_enforced = std::fs::File::create(&probe).is_err();
        let _ = std::fs::remove_file(&probe);
        let write_result = if perms_enforced {
            Some(safe_write_element_versioned(&path, &TestType { i: 222 }).await)
        } else {
            None
        };

        // Always restore permissions so the tempdir can be cleaned up.
        std::fs::set_permissions(dir.path(), saved).unwrap();

        if let Some(res) = write_result {
            assert!(
                res.is_err(),
                "write should fail when the temp can't be created"
            );
        }
        // The destination still holds the original element, never a partial file.
        let read_back: TestType = safe_read_element_versioned(&path).await.unwrap();
        assert_eq!(read_back, original);
    }
}
