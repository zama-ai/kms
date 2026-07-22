use serde::Serialize;
use serde::de::DeserializeOwned;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tfhe::named::Named;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::{Unversionize, Versionize};

use crate::consts::SAFE_SER_SIZE_LIMIT;

/// Process-wide sequence for partial-write temp names; together with the pid
/// it makes `.<name>.partial.<pid>.<seq>` unique among live writers.
static PARTIAL_SEQ: AtomicU64 = AtomicU64::new(0);

/// `.<final_name>.partial.<pid>.<seq>` — the temp-name grammar shared by the
/// writer and [`sweep_stale_partials`]; `OsStr` in and out because that is
/// what `Path::file_name` yields (the sweep only parses UTF-8 names).
pub(crate) fn partial_file_name(final_name: &OsStr, pid: u32, seq: u64) -> OsString {
    let mut name = OsString::from(".");
    name.push(final_name);
    name.push(format!(".partial.{pid}.{seq}"));
    name
}

/// Strictly parse a directory-entry name as a partial-write temp file,
/// returning the embedded writer pid. Parses from the end so a destination
/// name that itself contains ".partial." cannot confuse it.
fn parse_partial_owner_pid(file_name: &str) -> Option<u32> {
    let rest = file_name.strip_prefix('.')?;
    let (rest, seq) = rest.rsplit_once('.')?;
    seq.parse::<u64>().ok()?;
    let (rest, pid) = rest.rsplit_once('.')?;
    let pid = pid.parse::<u32>().ok()?;
    let name = rest.strip_suffix(".partial")?;
    if name.is_empty() {
        return None;
    }
    Some(pid)
}

/// Create the partial-write temp file for `final_name`, reclaiming a same-name
/// orphan on collision. Reclaiming is safe: pids are unique among live
/// processes and [`PARTIAL_SEQ`] is process-wide, so an existing file carrying
/// our own pid can only be a dead predecessor's leftover (e.g. the server
/// being pid 1 on every container restart).
fn create_partial_tempfile(
    parent: &Path,
    final_name: &OsStr,
    pid: u32,
    seq: u64,
) -> std::io::Result<tempfile::NamedTempFile> {
    let tmp_name = partial_file_name(final_name, pid, seq);
    let build = || {
        tempfile::Builder::new()
            .prefix(&tmp_name)
            .rand_bytes(0)
            .tempfile_in(parent)
    };
    match build() {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            tracing::warn!(
                "reclaiming orphaned partial file {} left by a dead process with reused pid {pid}",
                parent.join(&tmp_name).display()
            );
            if let Err(e) = std::fs::remove_file(parent.join(&tmp_name))
                // NotFound: a concurrent sweeper of the same root won the race.
                && e.kind() != std::io::ErrorKind::NotFound
            {
                return Err(e);
            }
            build()
        }
        res => res,
    }
}

/// Directory layout is at most `{root}/{data_type}/{epoch_id}/{file}`, i.e.
/// recursion depth 2; two extra levels of headroom.
const MAX_SWEEP_DEPTH: usize = 4;

/// Best-effort removal of `.<name>.partial.<pid>.<seq>` files orphaned under
/// `root` by hard-crashed processes (on a clean failure the temp file's drop
/// guard removes it). A file is deleted only if its embedded pid is dead, or
/// live but younger than the file — a writer's file cannot predate the writer,
/// while a pid reused after a crash (e.g. the server being pid 1 on every
/// container restart) carries a fresh start time. In-flight writes are thus
/// never touched, assuming all writers to `root` share this process' pid
/// namespace and clock. IO errors are logged and never propagated.
pub(crate) fn sweep_stale_partials(root: &Path) {
    let mut candidates: Vec<(PathBuf, u32)> = Vec::new();
    collect_partial_files(root, 0, &mut candidates);
    if candidates.is_empty() {
        return;
    }
    if !sysinfo::IS_SUPPORTED_SYSTEM {
        tracing::warn!(
            "cannot check process liveness on this platform; keeping {} partial file(s) under {}",
            candidates.len(),
            root.display()
        );
        return;
    }
    let mut pids: Vec<sysinfo::Pid> = candidates
        .iter()
        .map(|(_, pid)| sysinfo::Pid::from_u32(*pid))
        .collect();
    pids.sort_unstable();
    pids.dedup();
    // One batched liveness query for all encountered pids, our own included:
    // its start time is what ages out a dead predecessor's same-pid files.
    let mut system = sysinfo::System::new_with_specifics(sysinfo::RefreshKind::nothing());
    system.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&pids),
        false,
        sysinfo::ProcessRefreshKind::nothing(),
    );
    for (path, pid) in candidates {
        if may_be_in_flight(&system, pid, &path) {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => tracing::info!(
                "removed stale partial file {} orphaned by pid {pid}",
                path.display()
            ),
            // A concurrent sweeper of the same root won the race.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(
                "failed to remove stale partial file {}: {e}",
                path.display()
            ),
        }
    }
}

/// Whether `path` may be the in-flight write of a live process owning `pid`:
/// the pid is alive and the file is not older than that process. Start times
/// are whole seconds, so same-second counts as not older; an unknown start
/// time or mtime also counts as in-flight to stay on the safe side.
fn may_be_in_flight(system: &sysinfo::System, pid: u32, path: &Path) -> bool {
    let Some(process) = system.process(sysinfo::Pid::from_u32(pid)) else {
        return false;
    };
    let start = process.start_time();
    if start == 0 {
        return true;
    }
    let Ok(mtime) = std::fs::metadata(path).and_then(|m| m.modified()) else {
        return true;
    };
    mtime >= std::time::UNIX_EPOCH + std::time::Duration::from_secs(start)
}

/// Recursively collect partial-write files under `dir` for
/// [`sweep_stale_partials`]; depth-limited, does not follow symlinks, skips
/// unreadable entries.
fn collect_partial_files(dir: &Path, depth: usize, out: &mut Vec<(PathBuf, u32)>) {
    if depth > MAX_SWEEP_DEPTH {
        tracing::warn!(
            "partial-file sweep stopping at unexpected directory depth {depth} in {}",
            dir.display()
        );
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("partial-file sweep cannot read {}: {e}", dir.display());
            }
            return;
        }
    };
    for entry in entries {
        let Ok(entry) = entry else { continue };
        // `file_type` does not follow symlinks, so linked dirs are not recursed.
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_partial_files(&entry.path(), depth + 1, out);
        } else if file_type.is_file()
            && let Some(pid) = entry.file_name().to_str().and_then(parse_partial_owner_pid)
        {
            out.push((entry.path(), pid));
        }
    }
}

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
    let Some(file_name) = file_path.file_name() else {
        anyhow::bail!("invalid file path: {}", file_path.display());
    };
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = file_path.parent() {
        tokio::fs::create_dir_all(p).await?
    };
    // Serialize into a sibling temp file, fsync it, then atomically rename it
    // over `file_path`, so a crash mid-write cannot leave a partial file there
    // (rename alone is not a durability barrier). The temp file must live in
    // the same directory (rename cannot cross filesystems); its dot-prefixed
    // name (`.<name>.partial.<pid>.<seq>`) is skipped by directory listings
    // (`FileStorage::all_data_ids` parses every non-hidden name as a
    // `RequestId`), unique among live writers, and pid-attributable so
    // `sweep_stale_partials` can reclaim it if this process hard-crashes.
    let parent = match file_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let seq = PARTIAL_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = create_partial_tempfile(parent, file_name, std::process::id(), seq)
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
        create_partial_tempfile, parse_partial_owner_pid, partial_file_name, read_element,
        safe_read_element_versioned, safe_write_element_versioned, sweep_stale_partials,
        write_bytes, write_element,
    };
    use crate::vault::storage::tests::TestType;
    use std::ffi::OsStr;
    use tokio::fs::remove_file;

    /// Larger than any real pid (Linux `pid_max` <= 2^22, macOS ~10^5) yet
    /// still positive when converted to the platform's i32 pid representation.
    const NEVER_LIVE_PID: u32 = 999_999_999;

    fn plant_partial(dir: &std::path::Path, final_name: &str, pid: u32) -> std::path::PathBuf {
        let path = dir.join(partial_file_name(OsStr::new(final_name), pid, 0));
        std::fs::write(&path, b"partial junk").unwrap();
        path
    }

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

    // The writer and the sweep share the name grammar; a drift breaks the sweep.
    #[test]
    fn partial_name_roundtrip() {
        let name = partial_file_name(OsStr::new("element"), 123, 7);
        assert_eq!(name.to_str().unwrap(), ".element.partial.123.7");
        assert_eq!(parse_partial_owner_pid(name.to_str().unwrap()), Some(123));
    }

    #[test]
    fn parse_partial_rejects_non_matching() {
        for name in [
            "element",                  // regular data file
            ".hidden",                  // plain dotfile
            ".gitkeep",                 // plain dotfile
            ".tmpAbC123",               // old NamedTempFile naming
            ".name.partial.abc.1",      // non-numeric pid
            ".name.partial.12",         // missing seq
            ".partial.12.1",            // empty destination name
            ".name.partial.12.1x",      // non-numeric seq
            ".name.partial..1",         // empty pid
            ".n.partial.99999999999.1", // pid exceeds u32
            ".name.partiality.12.1",    // marker is a substring, not ".partial"
        ] {
            assert_eq!(parse_partial_owner_pid(name), None, "must reject {name}");
        }
        // A destination name containing ".partial." itself still parses to the
        // trailing pid, never to the embedded number.
        assert_eq!(
            parse_partial_owner_pid(".a.partial.1.b.partial.12.1"),
            Some(12)
        );
    }

    #[test]
    fn create_partial_tempfile_reclaims_same_name_orphan() {
        let dir = tempfile::tempdir().unwrap();
        let name = partial_file_name(OsStr::new("element"), 42, 7);
        std::fs::write(dir.path().join(&name), b"stale orphan").unwrap();

        let tmp = create_partial_tempfile(dir.path(), OsStr::new("element"), 42, 7).unwrap();
        assert_eq!(tmp.path().file_name().unwrap(), name.as_os_str());
        // The orphan was replaced by a fresh empty file, not appended to.
        assert_eq!(std::fs::metadata(tmp.path()).unwrap().len(), 0);
    }

    #[test]
    fn sweep_removes_dead_pid_partials_recursively() {
        let dir = tempfile::tempdir().unwrap();
        let type_dir = dir.path().join("t");
        let epoch_dir = type_dir.join("epoch1");
        std::fs::create_dir_all(&epoch_dir).unwrap();
        let orphans = [
            plant_partial(dir.path(), "a", NEVER_LIVE_PID),
            plant_partial(&type_dir, "b", NEVER_LIVE_PID),
            plant_partial(&epoch_dir, "c", NEVER_LIVE_PID),
        ];
        let keepers = [
            type_dir.join("realdata"),
            type_dir.join(".gitkeep"),
            type_dir.join(".tmpAbC123"),
        ];
        for keeper in &keepers {
            std::fs::write(keeper, b"keep me").unwrap();
        }

        sweep_stale_partials(dir.path());

        for orphan in &orphans {
            assert!(!orphan.exists(), "orphan not swept: {}", orphan.display());
        }
        for keeper in &keepers {
            assert!(keeper.exists(), "non-partial deleted: {}", keeper.display());
        }
    }

    #[test]
    fn sweep_keeps_own_pid_partials() {
        let dir = tempfile::tempdir().unwrap();
        // Another vault instance in this process may be mid-write.
        let inflight = plant_partial(dir.path(), "element", std::process::id());
        sweep_stale_partials(dir.path());
        assert!(inflight.exists());
    }

    #[test]
    fn sweep_removes_own_pid_partials_older_than_process_start() {
        let dir = tempfile::tempdir().unwrap();
        let orphan = plant_partial(dir.path(), "element", std::process::id());
        // Backdate to before this process started: a dead predecessor's
        // leftover carrying our reused pid (pid 1 on every container restart).
        std::fs::File::options()
            .write(true)
            .open(&orphan)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
            .unwrap();

        sweep_stale_partials(dir.path());
        assert!(!orphan.exists(), "predecessor's same-pid partial was kept");
    }

    // The sweep must never remove a live foreign process' in-flight write.
    #[cfg(unix)]
    #[test]
    fn sweep_keeps_live_foreign_pid_partials() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let inflight = plant_partial(dir.path(), "element", child.id());

        sweep_stale_partials(dir.path());
        let kept = inflight.exists();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(kept, "live foreign process' partial was removed");
    }

    #[cfg(unix)]
    #[test]
    fn sweep_removes_partial_of_exited_process() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        child.wait().unwrap();
        // Pid reuse between wait() and the sweep is practically impossible
        // (allocation is sequential); NEVER_LIVE_PID tests carry the
        // deterministic burden.
        let dir = tempfile::tempdir().unwrap();
        let orphan = plant_partial(dir.path(), "element", child.id());

        sweep_stale_partials(dir.path());
        assert!(!orphan.exists(), "dead process' partial was kept");
    }

    #[test]
    fn sweep_of_missing_root_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        sweep_stale_partials(&dir.path().join("does-not-exist"));
    }
}
