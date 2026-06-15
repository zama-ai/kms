use serde::Serialize;
use serde::de::DeserializeOwned;
use std::path::Path;
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
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = file_path.parent() {
        tokio::fs::create_dir_all(p).await?
    };
    // Serialize into a sibling temp file, fsync it, then atomically rename it
    // over `file_path`, so a crash mid-write cannot leave a partial file there
    // (rename alone is not a durability barrier). The temp file must live in
    // the same directory (rename cannot cross filesystems); its dot-prefixed
    // name is skipped by directory listings (`FileStorage::all_data_ids`
    // parses every non-hidden name as a `RequestId`) and is unique per writer,
    // so concurrent writers to the same path cannot collide.
    let parent = match file_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
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
    tmp.persist(file_path)
        .map_err(|e| anyhow::anyhow!("failed to persist {}: {e}", file_path.display()))?;
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
