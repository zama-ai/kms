//! Shared fixtures for the Solana linker v1 test binaries.
//!
//! A single canonical request, mutated one field at a time. Tests read as "this request, except
//! for X", which is what makes a sensitivity suite reviewable: the reader can see that exactly one
//! thing changed.

// Each test binary compiles this module and uses a subset of it, including its re-exports.
#![allow(dead_code, unused_imports)]

use std::fs;
use std::path::{Path, PathBuf};

use hashing::{DomainSep, hash_element_w_size};
use kms_grpc::solana_binding::{SolanaUserDecryptBinding, SolanaUserDecryptBindingError};

/// The list-setting separator the KMS list hash prepends, ahead of the per-call separator.
/// Re-exported from the production crate so the tests hash with the real value, not a copy.
pub use hashing::DSEP_LIST;

/// A Solana-kind host chain id: bit 63 set, as every embedded handle chain id must be.
pub const CHAIN_ID: u64 = (1 << 63) | 12_345;

pub const PROGRAM_ID: [u8; 32] = [0x22; 32];
pub const RECEIVER: [u8; 32] = [0x33; 32];
pub const CONTEXT_ID: [u8; 32] = [0x44; 32];
pub const EPOCH_ID: [u8; 32] = [0x55; 32];

/// In production the request carries the 869-byte serialized `UnifiedPublicEncKey::MlKem512`
/// container (the 800-byte encapsulation key plus its framing), though the binding does not
/// enforce a width — that rule lives in the wallet permit and the connector.
pub const TRANSPORT_KEY_LEN: usize = 869;

/// A ciphertext handle embedding `chain_id`, with `discriminator` filling every other byte so
/// handles of one request stay distinguishable.
pub fn handle_for_chain(chain_id: u64, discriminator: u8) -> [u8; 32] {
    let mut handle = [discriminator; 32];
    handle[22..30].copy_from_slice(&chain_id.to_be_bytes());
    handle
}

/// A ciphertext handle on the canonical chain.
pub fn handle(discriminator: u8) -> [u8; 32] {
    handle_for_chain(CHAIN_ID, discriminator)
}

/// A deterministic transport key of the usual width.
pub fn transport_key() -> Vec<u8> {
    (0..TRANSPORT_KEY_LEN).map(|byte| byte as u8).collect()
}

/// The inputs of a Solana user-decryption request, as fields, so a test can change exactly one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub verifying_program_id: Vec<u8>,
    pub receiver_id: Vec<u8>,
    pub kms_context_id: Vec<u8>,
    pub kms_epoch_id: Vec<u8>,
    pub handles: Vec<[u8; 32]>,
    pub transport_key: Vec<u8>,
}

impl Request {
    /// The canonical two-handle request every variant deviates from.
    pub fn canonical() -> Self {
        Self {
            verifying_program_id: PROGRAM_ID.to_vec(),
            receiver_id: RECEIVER.to_vec(),
            kms_context_id: CONTEXT_ID.to_vec(),
            kms_epoch_id: EPOCH_ID.to_vec(),
            handles: vec![handle(1), handle(2)],
            transport_key: transport_key(),
        }
    }

    pub fn with_handles(mut self, handles: Vec<[u8; 32]>) -> Self {
        self.handles = handles;
        self
    }

    pub fn try_build(&self) -> Result<SolanaUserDecryptBinding, SolanaUserDecryptBindingError> {
        SolanaUserDecryptBinding::new(
            &self.verifying_program_id,
            &self.receiver_id,
            &self.kms_context_id,
            &self.kms_epoch_id,
            self.handles.iter().map(|handle| handle.as_slice()),
            &self.transport_key,
        )
    }

    pub fn build(&self) -> SolanaUserDecryptBinding {
        self.try_build().expect("a canonical Solana request")
    }

    pub fn link(&self) -> Vec<u8> {
        self.build().compute_link()
    }
}

/// SHAKE-256 with a 32-byte output, over `bytes` in full.
///
/// Expressed through the codebase's own helper rather than a second hashing dependency: the helper
/// computes `SHAKE256(separator ‖ element)`, so feeding it the input's first eight bytes as the
/// separator and the rest as the element hashes exactly `bytes`. The identity is verified by
/// `list_hash_helper_matches_the_specified_construction` rather than assumed.
pub fn shake256_32(bytes: &[u8]) -> Vec<u8> {
    let (separator, rest) = bytes.split_at(8);
    hash_element_w_size(
        &DomainSep::try_from(separator).expect("split at eight bytes"),
        rest,
        32,
    )
}

/// Root of the workspace, two levels above this crate.
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the workspace root is two levels above this crate")
}

/// Directories that hold build output or vendored data rather than source.
fn is_skipped(name: &str) -> bool {
    matches!(name, "target" | ".git" | "node_modules" | "data")
}

fn collect_rust_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        // An unreadable directory cannot hide a declaration that matters: anything invisible here
        // is equally invisible to the compiler.
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        if path.is_dir() {
            if !is_skipped(&name) {
                collect_rust_files(&path, files);
            }
        } else if name.ends_with(".rs") {
            files.push(path);
        }
    }
}

/// Every Rust source file in the workspace, as `(workspace-relative path, contents)`.
///
/// Source-scanning tests are only worth having if they cannot pass by finding nothing, so every
/// caller must assert something about the corpus itself — a count, or a set equality — and not
/// merely the absence of a match.
pub fn rust_sources() -> Vec<(String, String)> {
    let root = workspace_root();
    let mut files = Vec::new();
    collect_rust_files(&root, &mut files);
    files.sort();

    files
        .into_iter()
        .filter_map(|file| {
            let contents = fs::read_to_string(&file).ok()?;
            let relative = file
                .strip_prefix(&root)
                .expect("collected under the root")
                .to_string_lossy()
                .replace('\\', "/");
            Some((relative, contents))
        })
        .collect()
}
