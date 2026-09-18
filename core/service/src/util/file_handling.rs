use serde::Serialize;
use serde::de::DeserializeOwned;
use std::path::Path;
use tfhe::named::Named;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::{Unversionize, Versionize};

use crate::consts::SAFE_SER_SIZE_LIMIT;

/// Writes bytes without serialization and atomically replaces the destination.
/// The bytes are synced in a sibling temporary file before the rename. Errors leave the
/// destination unchanged and remove the temporary file. This does not sync the parent directory.
pub async fn write_bytes<P: AsRef<Path>>(file_path: P, bytes: &[u8]) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let file_path = file_path.as_ref();
    if file_path.file_name().is_none() {
        anyhow::bail!("invalid file path: {}", file_path.display());
    }
    let parent = match file_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => {
            tokio::fs::create_dir_all(p).await?;
            p
        }
        _ => Path::new("."),
    };
    let tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| anyhow::anyhow!("failed to create temp file in {}: {e}", parent.display()))?;
    let mut writer = tokio::fs::File::from_std(tmp.reopen()?);
    writer
        .write_all(bytes)
        .await
        .map_err(|e| anyhow::anyhow!("failed to write {}: {e}", tmp.path().display()))?;
    // Tokio can report a background write error on flush rather than on write_all.
    writer
        .flush()
        .await
        .map_err(|e| anyhow::anyhow!("failed to flush {}: {e}", tmp.path().display()))?;
    writer
        .sync_all()
        .await
        .map_err(|e| anyhow::anyhow!("failed to sync {}: {e}", tmp.path().display()))?;
    drop(writer);
    tmp.persist(file_path)
        .map_err(|e| anyhow::anyhow!("failed to persist {}: {e}", file_path.display()))?;
    Ok(())
}

/// This is a wrapper around safe_serialize versioned for the async use case.
///
/// Streams the serialization into a sibling temp file (synced, then atomically
/// renamed into place) rather than buffering the multi-GiB blob in memory.
/// Serialization runs inline: `safe_serialize` borrows `element`, so it cannot
/// move into `spawn_blocking`, and `block_in_place` panics on current-thread
/// runtimes. Key writes are rare enough that blocking here is acceptable.
/// On any error the temp file is removed (`NamedTempFile` deletes on drop).
pub async fn safe_write_element_versioned<
    T: Serialize + Versionize + Named + Send,
    P: AsRef<Path>,
>(
    file_path: P,
    element: &T,
) -> anyhow::Result<()> {
    let file_path = file_path.as_ref();
    if file_path.file_name().is_none() {
        anyhow::bail!("invalid file path: {}", file_path.display());
    }
    let parent = match file_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => {
            tokio::fs::create_dir_all(p).await?;
            p
        }
        _ => Path::new("."),
    };
    // Serialize into a sibling temp file, fsync it, then atomically rename it
    // over `file_path`, so a crash mid-write cannot leave a partial file there
    // (rename alone is not a durability barrier). The temp file must live in
    // the same directory (rename cannot cross filesystems); its dot-prefixed
    // name is skipped by directory listings (`FileStorage::all_data_ids`
    // parses every non-hidden name as a `RequestId`) and is unique per writer,
    // so concurrent writers to the same path cannot collide.
    let tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| anyhow::anyhow!("failed to create temp file in {}: {e}", parent.display()))?;
    let mut writer = std::io::BufWriter::new(tmp);
    safe_serialize(element, &mut writer, SAFE_SER_SIZE_LIMIT).map_err(|e| {
        anyhow::anyhow!(
            "failed to serialize into {}: {e}",
            writer.get_ref().path().display()
        )
    })?;
    let tmp = writer
        .into_inner()
        .map_err(|e| anyhow::anyhow!("failed to flush temp file: {e}"))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| anyhow::anyhow!("failed to sync {}: {e}", tmp.path().display()))?;
    // Capture the serialized size before `persist` consumes `tmp`, so it can be recorded only
    // after the write durably succeeds (keyed by the element's type name; see `observe_size`).
    let payload_size = tmp
        .as_file()
        .metadata()
        .map_err(|e| anyhow::anyhow!("failed to stat {}: {e}", tmp.path().display()))?
        .len();
    tmp.persist(file_path)
        .map_err(|e| anyhow::anyhow!("failed to persist {}: {e}", file_path.display()))?;
    observability::metrics::METRICS.observe_size(<T as Named>::NAME, payload_size as f64);
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

/// Write a generic element to a file by serializing it. This is hidden behind the testing flag to ensure only the
/// versioned writing method is used in production code.
///
/// Thin async wrapper around [`test_utils::write_element`] (blocking IO, fine under the testing flag).
#[cfg(any(test, feature = "testing"))]
pub async fn write_element<T: serde::Serialize, P: AsRef<Path>>(
    file_path: P,
    element: &T,
) -> anyhow::Result<()> {
    test_utils::write_element(file_path, element)
}

/// Read a generic element from a file. This is hidden behind the testing flag to ensure only the versioned reading
/// method is used in production code.
///
/// Thin async wrapper around [`test_utils::read_element`] (blocking IO, fine under the testing flag).
#[cfg(any(test, feature = "testing"))]
pub async fn read_element<T: DeserializeOwned + Serialize, P: AsRef<Path>>(
    file_path: P,
) -> anyhow::Result<T> {
    test_utils::read_element(file_path)
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

    /// Anything in `dir` other than `expected` is a stranded temp file.
    fn leftovers(dir: &std::path::Path, expected: &str) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != expected)
            .collect()
    }

    #[tokio::test]
    async fn safe_write_then_read_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("element");
        let element = TestType { i: 7 };
        safe_write_element_versioned(&path, &element).await.unwrap();
        let read_back: TestType = safe_read_element_versioned(&path).await.unwrap();
        assert_eq!(read_back, element);
        // Only the final file remains; the temp was renamed, not left behind.
        let stranded = leftovers(path.parent().unwrap(), "element");
        assert!(stranded.is_empty(), "leftover temp files: {stranded:?}");
    }

    /// A replacement leaves an already-open reader on the complete old file, not a truncated file.
    #[cfg(unix)]
    #[rstest::rstest]
    #[case::nonempty(b"replacement bytes".as_slice())]
    #[case::empty(b"".as_slice())]
    #[tokio::test]
    async fn raw_write_replaces_the_file_atomically(#[case] replacement: &[u8]) {
        use std::io::Read;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/element");
        write_bytes(&path, b"original bytes").await.unwrap();
        let mut original_file = std::fs::File::open(&path).unwrap();

        write_bytes(&path, replacement).await.unwrap();

        let mut original_bytes = Vec::new();
        original_file.read_to_end(&mut original_bytes).unwrap();
        assert_eq!(original_bytes, b"original bytes");
        assert_eq!(std::fs::read(&path).unwrap(), replacement);
        assert!(leftovers(path.parent().unwrap(), "element").is_empty());
    }

    /// A failed rename preserves the destination and removes the fully written temporary file.
    #[tokio::test]
    async fn raw_write_cleans_up_after_a_failed_rename() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("element");
        std::fs::create_dir(&path).unwrap();
        let control = path.join("keep");
        std::fs::write(&control, b"original bytes").unwrap();

        // The destination is a directory, so renaming a file over it must fail.
        assert!(write_bytes(&path, b"replacement bytes").await.is_err());

        assert_eq!(std::fs::read(&control).unwrap(), b"original bytes");
        assert!(leftovers(dir.path(), "element").is_empty());
        assert!(leftovers(&path, "keep").is_empty());
    }

    #[tokio::test]
    async fn safe_write_cleans_up_partial_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        // An existing directory at the destination makes the final rename fail.
        let path = dir.path().join("element");
        std::fs::create_dir(&path).unwrap();

        let res = safe_write_element_versioned(&path, &TestType { i: 3 }).await;
        assert!(res.is_err(), "write onto an existing directory should fail");

        let stranded = leftovers(dir.path(), "element");
        assert!(
            stranded.is_empty(),
            "failed write left partial temp files: {stranded:?}"
        );
    }

    // A path with no file name component is rejected before any file is touched.
    #[tokio::test]
    async fn safe_write_rejects_path_without_filename() {
        let res = safe_write_element_versioned(std::path::Path::new("/"), &TestType { i: 0 }).await;
        assert!(res.is_err());
    }

    // A write that fails before the rename must leave a pre-existing
    // destination untouched.
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

        // Root ignores directory permissions; skip the negative assertion if
        // the failure can't be induced.
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
