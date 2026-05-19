#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_span;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use rustc_hir::def_id::DefId;
use rustc_lint::LateContext;
use rustc_middle::ty::{Ty, TyKind};
use rustc_span::Span;

/// Name of the environment variable used to override the inventory output directory.
pub const INVENTORY_DIR_ENV: &str = "KMS_VERSIONED_CODEC_INVENTORY_DIR";

/// Source position of a linted expression.
#[derive(Clone, Debug)]
pub struct SourcePosition {
    /// Source file name as reported by rustc.
    pub file: String,
    /// One-based source line.
    pub line: usize,
    /// One-based source column.
    pub column: usize,
}

/// Returns a stable display position for a span.
pub fn source_position(cx: &LateContext<'_>, span: Span) -> SourcePosition {
    let source_map = cx.tcx.sess.source_map();
    let location = source_map.lookup_char_pos(span.lo());

    SourcePosition {
        file: location
            .file
            .name
            .prefer_local_unconditionally()
            .to_string(),
        line: location.line,
        column: location.col_display + 1,
    }
}

/// Gets the [`DefId`] of a type when the root is a named definition.
pub fn get_def_id_from_ty(ty: Ty<'_>) -> Option<DefId> {
    match ty.kind() {
        TyKind::Adt(adt_def, _) => Some(adt_def.did()),
        TyKind::Alias(alias_ty) => Some(alias_ty.kind.def_id()),
        TyKind::Dynamic(predicates, ..) => predicates.principal_def_id(),
        TyKind::FnDef(def_id, _)
        | TyKind::Foreign(def_id)
        | TyKind::Closure(def_id, ..)
        | TyKind::CoroutineClosure(def_id, _)
        | TyKind::Coroutine(def_id, _)
        | TyKind::CoroutineWitness(def_id, _) => Some(*def_id),
        _ => None,
    }
}

/// Peels references from a type until the root value type is reached.
pub fn peel_references(mut ty: Ty<'_>) -> Ty<'_> {
    while let TyKind::Ref(_, inner, _) = ty.kind() {
        ty = *inner;
    }
    ty
}

/// Returns true if the `DefId` belongs to one of the workspace crate names.
pub fn is_workspace_def(
    cx: &LateContext<'_>,
    def_id: DefId,
    workspace_crates: &BTreeSet<String>,
) -> bool {
    if def_id.is_local() {
        return true;
    }

    workspace_crates.contains(&cx.tcx.crate_name(def_id.krate).to_string())
}

/// Returns the rustc crate name for a definition.
pub fn def_crate_name(cx: &LateContext<'_>, def_id: DefId) -> String {
    cx.tcx.crate_name(def_id.krate).to_string()
}

/// Returns the output directory for generated inventory files.
pub fn inventory_dir() -> PathBuf {
    std::env::var(INVENTORY_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("target/kms-lints/versioned-codec-inventory"))
}

/// Returns the workspace crate names, normalized to rustc crate-name spelling.
pub fn workspace_crates() -> &'static BTreeSet<String> {
    static WORKSPACE_CRATES: OnceLock<BTreeSet<String>> = OnceLock::new();
    WORKSPACE_CRATES.get_or_init(load_workspace_crates)
}

fn load_workspace_crates() -> BTreeSet<String> {
    let metadata = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output();

    let Ok(metadata) = metadata else {
        return BTreeSet::new();
    };

    if !metadata.status.success() {
        return BTreeSet::new();
    }

    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&metadata.stdout) else {
        return BTreeSet::new();
    };

    let mut crates = BTreeSet::new();
    if let Some(packages) = json.get("packages").and_then(serde_json::Value::as_array) {
        for package in packages {
            if let Some(targets) = package.get("targets").and_then(serde_json::Value::as_array) {
                for target in targets {
                    if let Some(name) = target.get("name").and_then(serde_json::Value::as_str) {
                        crates.insert(normalize_crate_name(name));
                    }
                }
            }
        }
    }

    crates
}

fn normalize_crate_name(name: &str) -> String {
    name.replace('-', "_")
}
