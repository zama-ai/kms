//! Backward-compatibility coverage gate for `VersionsDispatch` enums.
//!
//! Adding a new versionable type requires (a) a `*Versioned` dispatch enum
//! with contiguous `V0..Vn` variants, and (b) at least one `.ron` fixture
//! entry under `backward-compatibility/data/`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use backward_compatibility::{
    TestMetadataDD, TestMetadataKMS, TestMetadataKmsGrpc, load::load_tests_metadata,
};
use serde::{Deserialize, de::DeserializeOwned};
use syn::{Attribute, Item, Path as SynPath};

#[derive(Deserialize)]
struct WorkspaceManifest {
    workspace: Workspace,
}

#[derive(Deserialize)]
struct Workspace {
    members: Vec<String>,
}

/// One `#[derive(VersionsDispatch)]` enum discovered during the workspace scan.
///
/// Carries just enough information to drive the two coverage checks:
/// `enum_name` (e.g. `FooVersioned`) is stripped of its `Versioned` suffix to
/// match against `.ron` fixture entries; `variants` is inspected for the
/// `V0..Vn` contiguity rule; `file` is reported back in error messages so the
/// offending source location is obvious.
#[derive(Debug)]
struct Dispatch {
    enum_name: String,
    variants: Vec<String>,
    file: PathBuf,
}

/// Types we deliberately don't require a direct `.ron` fixture for, because
/// they are transitively exercised as fields of a root type that *does* have
/// a fixture.
///
/// TODO(zama-ai/kms-internal#3028): this explicit list should go away after
/// we have a proper way to identify which structs need to be tested.
const ALLOW_UNCOVERED: &[&str] = &[
    // Field of UnifiedSigncryptionKeyOwned, UnifiedUnsigncryptionKeyOwned,
    // CustodianSetupMessagePayload, InternalCustodianSetupMessage, and
    // InternalCustodianContext. Covered via UnifiedSigncryptionKeyTest,
    // UnifiedUnsigncryptionKeyTest, InternalCustodianSetupMessageTest, and
    // InternalCustodianContextTest.
    "UnifiedPublicEncKey",
    // Field of UnifiedUnsigncryptionKeyOwned.
    // Covered via UnifiedUnsigncryptionKeyTest.
    "UnifiedPrivateEncKey",
    // Field of UnifiedCipher and UnifiedSigncryption.
    // Covered via UnifiedCipherTest and UnifiedSigncryptionTest.
    "PkeSchemeType",
    // Field of UnifiedSigncryption. (PrivateSigKey / PublicSigKey expose it
    // only via the HasSigningScheme trait method, not as a struct field.)
    // Covered via UnifiedSigncryptionTest.
    "SigningSchemeType",
    // Map value in RecoveryValidationMaterialPayload.cts and the actual
    // serialized fixture body produced by the OperatorBackupOutputTest
    // generator. Covered via OperatorBackupOutputTest and
    // RecoveryValidationMaterialTest.
    "InnerOperatorBackupOutput",
    // Plaintext that Operator::secret_share_and_signcrypt signcrypts into the
    // UnifiedSigncryption inside InnerOperatorBackupOutput; not a struct
    // field. Covered (in serialized-and-signcrypted form) via
    // OperatorBackupOutputTest.
    "BackupMaterial",
    // Field of RecoveryValidationMaterial.payload.
    // Covered via RecoveryValidationMaterialTest.
    "RecoveryValidationMaterialPayload",
    // safe_serialize'd into the protobuf CustodianSetupMessage.payload (then
    // unpacked into InternalCustodianSetupMessage on load).
    // Covered via InternalCustodianSetupMessageTest.
    "CustodianSetupMessagePayload",
    // Variant payload of KeyGenMetadata::Current.
    // Covered via KeyGenMetadataTest and KeyGenMetadataWithExtraDataTest.
    "KeyGenMetadataInner",
    // Variant payload of CrsGenMetadata::Current.
    // Covered via CrsGenMetadataTest and CrsGenMetadataWithExtraDataTest.
    "CrsGenMetadataInner",
    // Field of Share, BackupMaterial, InternalCustodianSetupMessage, and
    // InternalCustodianRecoveryOutput; map key in
    // RecoveryValidationMaterialPayload.{cts,commitments} and
    // InternalCustodianContext.custodian_nodes; transitively inside PRSSSetup
    // via PrssSet.parties. Covered via ShareTest, PRSSSetupTest, PrssSetTest,
    // PrssSetupCombinedTest, OperatorBackupOutputTest,
    // RecoveryValidationMaterialTest, InternalCustodianSetupMessageTest,
    // InternalCustodianContextTest, and InternalCustodianRecoveryOutputTest.
    "Role",
    // Field of ThresholdFheKeys.public_material.
    // Covered via ThresholdFheKeysTest.
    "PublicKeyMaterial",
    // Element type inside the Share<ResiduePoly<...>> collections used by all
    // secret-key shares (PrivateKeySet) and inside LweCiphertextShare.body.
    // Covered via ShareTest, PrivateKeySetTest, and ThresholdFheKeysTest.
    "ResiduePoly",
    // Variant payload of LweSecretKeyShareEnum, and direct field of
    // PrivateKeySet.{glwe_secret_key_share_sns_as_lwe,
    // glwe_sns_compression_key_as_lwe} (plus older PrivateKeySetV{1,2}
    // fields). Covered via PrivateKeySetTest and ThresholdFheKeysTest.
    "LweSecretKeyShare",
    // Field of PrivateKeySet.{lwe_encryption,lwe_compute,oprf}_secret_key_share.
    // Covered via PrivateKeySetTest and ThresholdFheKeysTest.
    "LweSecretKeyShareEnum",
    // Field of CompressionPrivateKeyShares.post_packing_ks_key and
    // SnsCompressionPrivateKeyShares.post_packing_ks_key, plus variant
    // payload of GlweSecretKeyShareEnum. Covered via PrivateKeySetTest and
    // ThresholdFheKeysTest.
    "GlweSecretKeyShare",
    // Field of PrivateKeySet.glwe_secret_key_share.
    // Covered via PrivateKeySetTest and ThresholdFheKeysTest.
    "GlweSecretKeyShareEnum",
    // Variant payload of CompressionPrivateKeySharesEnum.
    // Covered via PrivateKeySetTest and ThresholdFheKeysTest.
    "CompressionPrivateKeyShares",
    // Field of PrivateKeySet.glwe_secret_key_share_compression.
    // Covered via PrivateKeySetTest and ThresholdFheKeysTest.
    "CompressionPrivateKeySharesEnum",
];

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is core/service; go up two levels to the workspace root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("CARGO_MANIFEST_DIR has fewer than 2 ancestors")
        .to_path_buf()
}

// The repo currently uses plain paths (no globs), so direct TOML parsing is
// sufficient; if globs are introduced later, switch to
// `cargo metadata --format-version 1`.
fn workspace_members() -> Vec<PathBuf> {
    let root = repo_root();
    let text = std::fs::read_to_string(root.join("Cargo.toml"))
        .expect("failed to read workspace Cargo.toml");
    let manifest: WorkspaceManifest =
        toml::from_str(&text).expect("failed to parse workspace Cargo.toml");
    manifest
        .workspace
        .members
        .into_iter()
        .map(|m| root.join(m))
        .filter(|p| p.is_dir())
        .collect()
}

fn path_ends_with_ident(path: &SynPath, ident: &str) -> bool {
    path.segments
        .last()
        .is_some_and(|segment| segment.ident == ident)
}

/// Returns true if `attrs` contains a `#[derive(..., VersionsDispatch, ...)]`.
///
/// Matches on the trailing path segment so both `VersionsDispatch` and
/// fully-qualified forms like `tfhe_versionable::VersionsDispatch` are detected.
fn derives_versions_dispatch(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| {
        if !a.path().is_ident("derive") {
            return false;
        }
        let mut hit = false;
        let _ = a.parse_nested_meta(|m| {
            if path_ends_with_ident(&m.path, "VersionsDispatch") {
                hit = true;
            }
            Ok(())
        });
        hit
    })
}

/// Walks every workspace member and returns one [`Dispatch`] per enum that
/// derives `VersionsDispatch`.
///
/// `target/`, `tests/`, and hidden directories are skipped: build artifacts
/// would slow the scan, and integration-test files (including this one) may
/// contain dispatch-like fixtures that aren't part of the production surface.
///
/// Files that fail to read or parse are logged and skipped rather than
/// failing the test, so a single malformed file doesn't mask real coverage
/// gaps in the rest of the workspace.
fn collect_dispatches() -> Vec<Dispatch> {
    let mut out = Vec::new();
    for crate_dir in workspace_members() {
        for entry in walkdir::WalkDir::new(&crate_dir)
            .into_iter()
            .filter_entry(|e| {
                let n = e.file_name().to_string_lossy();
                // Skip build artifacts, integration-test dirs, hidden dirs.
                n != "target" && n != "tests" && !n.starts_with('.')
            })
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|x| x == "rs"))
        {
            let src = match std::fs::read_to_string(entry.path()) {
                Ok(s) => s,
                Err(err) => {
                    eprintln!("warning: skipping {}: {err}", entry.path().display());
                    continue;
                }
            };
            let parsed = match syn::parse_file(&src) {
                Ok(f) => f,
                Err(err) => {
                    eprintln!("warning: skipping {}: {err}", entry.path().display());
                    continue;
                }
            };
            for item in parsed.items {
                if let Item::Enum(e) = item {
                    if !derives_versions_dispatch(&e.attrs) {
                        continue;
                    }
                    out.push(Dispatch {
                        enum_name: e.ident.to_string(),
                        variants: e.variants.iter().map(|v| v.ident.to_string()).collect(),
                        file: entry.path().to_path_buf(),
                    });
                }
            }
        }
    }
    out
}

#[test]
fn versioned_enums_have_contiguous_variants() {
    let dispatches = collect_dispatches();
    assert!(
        !dispatches.is_empty(),
        "found no VersionsDispatch enums — scan paths likely wrong"
    );

    let mut violations = Vec::new();
    for d in &dispatches {
        for (i, v) in d.variants.iter().enumerate() {
            let expected = format!("V{i}");
            if v != &expected {
                violations.push(format!(
                    "{}::{}: variant #{i} is `{v}`, expected `{expected}`",
                    d.file.display(),
                    d.enum_name,
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "non-contiguous Vn variants:\n{}",
        violations.join("\n")
    );
}

/// Loads a `.ron` fixture file and returns the lowercased `metadata` field of
/// each testcase.
fn load_covered_names<M>(path: &Path) -> Vec<String>
where
    M: DeserializeOwned + std::fmt::Display,
{
    let testcases: Vec<backward_compatibility::Testcase<M>> = load_tests_metadata(path)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));
    testcases
        .iter()
        .map(|tc| tc.metadata.to_string().to_lowercase())
        .collect()
}

#[test]
fn versioned_enums_are_covered_by_ron_metadata() {
    let dispatches = collect_dispatches();
    let root = repo_root();

    // Compare names case-insensitively: the `.ron` files store variant names
    // chosen by the test author (e.g. `PrssSetupCombined`) which sometimes
    // smooth the casing of the underlying Rust type (`PRSSSetupCombined`).
    // `TestMetadata*` derive `strum::Display`, which renders an enum value as
    // just its variant name — exactly what we need to match against
    // `*Versioned` dispatch enums.
    let data_dir = root.join("backward-compatibility/data");
    let mut covered: BTreeSet<String> = BTreeSet::new();
    covered.extend(load_covered_names::<TestMetadataKMS>(
        &data_dir.join("kms.ron"),
    ));
    covered.extend(load_covered_names::<TestMetadataKmsGrpc>(
        &data_dir.join("kms-grpc.ron"),
    ));
    covered.extend(load_covered_names::<TestMetadataDD>(
        &data_dir.join("threshold-fhe.ron"),
    ));

    let mut missing: Vec<(String, PathBuf)> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for d in &dispatches {
        let underlying = d.enum_name.trim_end_matches("Versioned").to_string();
        if !seen.insert(underlying.clone()) {
            continue;
        }
        if ALLOW_UNCOVERED.contains(&underlying.as_str()) {
            continue;
        }
        if !covered.contains(&underlying.to_lowercase()) {
            missing.push((underlying, d.file.clone()));
        }
    }

    if !missing.is_empty() {
        let mut msg = String::from(
            "VersionsDispatch enums with no backward-compatibility coverage.\n\
             Add a metadata entry under backward-compatibility/data/*.ron\n\
             (and a generator entry in backward-compatibility/generate-vX.Y.Z/),\n\
             or add the type name to ALLOW_UNCOVERED with justification.\n\n",
        );
        for (name, file) in &missing {
            msg.push_str(&format!("  - {name} at {}\n", file.display()));
        }
        panic!("{msg}");
    }
}
