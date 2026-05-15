//! Compile-time inventory of types passed to serialization / storage sinks.
//!
//! ## What this is
//!
//! A Dylint lint plugin (a Rust compiler plugin loaded by Dylint). Despite the
//! word "lint", its primary job is **not** to flag bad code: it observes every
//! call to a curated list of serialization and storage functions in the crate
//! being compiled, figures out which *root type* flows through each call, and
//! writes a JSON report to
//! `target/kms-lints/bc2wrap-type-inventory/<crate>.json`. Downstream tooling
//! reads that report to check that every persisted type is covered by
//! backward-compatibility tests.
//!
//! Why a compiler plugin? Because we need **post-typecheck** information.
//! Plain text-search can't tell you that a generic helper is monomorphized to
//! `MyKey` at one call site and `Vec<u8>` at another. Hooking into rustc as a
//! `LateLintPass` gives us fully resolved types after type inference, for free.
//!
//! ## Vocabulary
//!
//! - **Sink** — a function whose call sites we care about. Sinks are listed in
//!   `SINK_SPECS`. The current set covers the raw encode / decode helpers in
//!   the `bc2wrap` crate and the vault read / write helpers in this workspace.
//! - **Root type** — the top of the type tree handed to a sink. Fields are
//!   *not* recursed into: if a sink receives `&MyStruct { … }`, the root is
//!   `MyStruct`, full stop.
//! - **Extractor** — a `RootExtractor` tells the lint *where* in a call to
//!   look for the root. A sink may declare more than one (e.g. `write_all`
//!   records both its public-data and private-data roots).
//!
//! ## Categories
//!
//! Each recorded root is bucketed into a `RootCategory`:
//!
//! - `Local` — defined in a workspace crate. **These are the rows that matter
//!   for backward compatibility.**
//! - `Foreign` — defined in an external dependency. Recorded for visibility.
//! - `Generic` / `Unknown` — the concrete type isn't resolvable at this call
//!   site (e.g. a generic helper that hasn't been specialized yet). Every
//!   such occurrence emits a compile-time warning so the author can refactor
//!   the call to expose the concrete type.
//! - `Compound` / `Primitive` — tuples, arrays, ints, etc. Recorded but
//!   normally filtered out downstream.
//!
//! ## Pipeline (per crate)
//!
//! 1. `check_expr` runs on every expression in the crate. `sink_for_expr`
//!    tries to resolve it to a `(MatchedSink, args)` pair by matching the
//!    callee's `DefId` against `SINK_SPECS`. If nothing matches, we return.
//! 2. For each `RootExtractor` on the matched spec, `extract_root_type`
//!    returns one of:
//!    - `Root(ty)` — the concrete root. We classify it via `classify_root`
//!      and push a `CallRecord`.
//!    - `NoRoot` — the position is legitimately empty (e.g. a `None`
//!      argument). Skipped silently.
//!    - `Unresolved` — we expected a root and couldn't determine one. We
//!      push a synthetic `<unknown>` record and emit a warning.
//! 3. Once the whole crate has been linted, `check_crate_post` writes the
//!    JSON file (one per crate target). The file contains the full `calls`
//!    array plus a deduped `types` summary built by `summarize_types`.
//!
//! ### Running example
//!
//! Take this call site (lifted from the UI fixture):
//!
//! ```ignore
//! let payload = LocalPayload { _value: 7 };
//! let _ = bc2wrap::serialize(&payload);
//! ```
//!
//! 1. rustc visits the `Call` expression and invokes `check_expr`.
//! 2. `sink_for_expr` resolves the callee's `DefId` to `bc2wrap::serialize`
//!    and looks it up in `SINK_SPECS`, finding the entry whose extractors
//!    are `&[RootExtractor::Arg(0)]`.
//! 3. `extract_root_type` runs `Arg(0)`: it reads arg 0's type
//!    (`&LocalPayload`), peels the reference, and returns
//!    `Root(LocalPayload)`.
//! 4. `classify_root` sees an ADT defined in a workspace crate and returns
//!    `RootCategory::Local`.
//! 5. `record` pushes a `CallRecord` with `function = "serialize"`,
//!    `sink_path = "bc2wrap::serialize"`, `type_display = "LocalPayload"`,
//!    `category = Local`, and the source file / line / column of the call.
//! 6. After every other expression in the crate has been visited,
//!    `check_crate_post` collapses duplicate calls into the `types` summary
//!    and writes the JSON file.
//!
//! Replace `&payload` with a generic `value: &T` inside `fn f<T>(value: &T)`
//! and only step 4 changes: `classify_root` sees `ty.has_param()`, returns
//! `RootCategory::Generic`, and `record` additionally emits a compile-time
//! warning so the author can refactor the call site to expose a concrete
//! type. The call is still recorded, just under the generic bucket.
//!
//! ## How to add a new sink
//!
//! 1. Append an entry to `SINK_SPECS`: the function name, a `path_contains`
//!    substring that disambiguates same-named functions, and one or more
//!    extractors. The sink only matches functions defined in a workspace
//!    crate (via `is_workspace_def`) — there is no separate "owner" knob.
//! 2. If none of the existing `RootExtractor` variants captures where the
//!    root lives in your signature, add a variant and handle it in
//!    `extract_root_type`.
//! 3. Extend the UI fixture in `tests/bc2wrap_type_inventory/main.rs` and add
//!    an assertion in the `ui` test at the bottom of this file so the new
//!    sink is exercised by `cargo test`.
//!
//! ## Configuration
//!
//! Set `KMS_BC2WRAP_INVENTORY_DIR` to override the output directory. The
//! workspace crate set is always auto-detected via `cargo metadata`.

use std::collections::{BTreeMap, BTreeSet};

use kms_lints_common::{
    def_crate_name, get_def_id_from_ty, inventory_dir, is_workspace_def, peel_references,
    source_position, workspace_crates,
};
use rustc_hir::{Expr, ExprKind};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_middle::ty::{GenericArgsRef, Ty, TyKind, TypeVisitableExt};
use rustc_session::{declare_lint, impl_lint_pass};
use rustc_span::def_id::{DefId, LOCAL_CRATE};
use serde::Serialize;

const SINK_SPECS: &[SinkSpec] = &[
    SinkSpec {
        function: "serialize",
        path_contains: Some("bc2wrap"),
        extractors: &[RootExtractor::Arg(0)],
    },
    SinkSpec {
        function: "serialize_into",
        path_contains: Some("bc2wrap"),
        extractors: &[RootExtractor::Arg(0)],
    },
    SinkSpec {
        function: "deserialize_safe",
        path_contains: Some("bc2wrap"),
        extractors: &[RootExtractor::ReturnResultOk],
    },
    SinkSpec {
        function: "deserialize_unsafe",
        path_contains: Some("bc2wrap"),
        extractors: &[RootExtractor::ReturnResultOk],
    },
    SinkSpec {
        function: "store_versioned_at_request_id",
        path_contains: Some("vault::storage"),
        extractors: &[RootExtractor::Arg(2)],
    },
    SinkSpec {
        function: "store_versioned_at_request_and_epoch_id",
        path_contains: Some("vault::storage"),
        extractors: &[RootExtractor::Arg(3)],
    },
    SinkSpec {
        function: "read_versioned_at_request_id",
        path_contains: Some("vault::storage"),
        extractors: &[RootExtractor::FnGenericArg(1)],
    },
    SinkSpec {
        function: "read_versioned_at_request_and_epoch_id",
        path_contains: Some("vault::storage"),
        extractors: &[RootExtractor::FnGenericArg(1)],
    },
    SinkSpec {
        function: "write_all",
        path_contains: Some("vault::storage::crypto_material::base"),
        extractors: &[
            RootExtractor::OptionTupleRefFirst(2),
            RootExtractor::OptionTupleRefFirst(3),
        ],
    },
];

#[derive(Clone, Debug, Serialize)]
struct SourceLocation {
    file: String,
    line: usize,
    column: usize,
}

#[derive(Clone, Debug, Serialize)]
struct CallRecord {
    function: String,
    sink_path: String,
    type_display: String,
    def_path: Option<String>,
    owner_crate: Option<String>,
    category: RootCategory,
    source: SourceLocation,
}

#[derive(Clone, Debug, Serialize)]
struct TypeSummary {
    type_display: String,
    def_path: Option<String>,
    owner_crate: Option<String>,
    category: RootCategory,
    sink_paths: Vec<String>,
    call_count: usize,
}

#[derive(Clone, Debug, Serialize)]
struct Inventory {
    crate_name: String,
    target_name: String,
    calls: Vec<CallRecord>,
    types: Vec<TypeSummary>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum RootCategory {
    Local,
    Foreign,
    Generic,
    Compound,
    Primitive,
    Unknown,
}

#[derive(Clone, Debug)]
struct RootInfo {
    type_display: String,
    def_path: Option<String>,
    owner_crate: Option<String>,
    category: RootCategory,
}

type SummaryKey = (RootCategory, String, Option<String>);

#[derive(Clone, Debug)]
struct SummaryEntry {
    summary: TypeSummary,
    sink_paths: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug)]
struct SinkSpec {
    function: &'static str,
    path_contains: Option<&'static str>,
    extractors: &'static [RootExtractor],
}

#[derive(Clone, Copy, Debug)]
enum RootExtractor {
    Arg(usize),
    OptionTupleRefFirst(usize),
    ReturnResultOk,
    FnGenericArg(usize),
}

#[derive(Clone, Debug)]
struct MatchedSink<'tcx> {
    spec: &'static SinkSpec,
    sink_path: String,
    generic_args: Option<GenericArgsRef<'tcx>>,
}

#[derive(Clone, Copy, Debug)]
enum ExtractedRoot<'tcx> {
    Root(Ty<'tcx>),
    NoRoot,
    Unresolved,
}

/// Late pass lint collecting bc2wrap root type inventory data.
#[derive(Default)]
pub struct Bc2wrapTypeInventory {
    calls: Vec<CallRecord>,
}

declare_lint! {
    /// ### What it does
    /// Collects an inventory of workspace-local root types used by `bc2wrap` call sites.
    ///
    /// ### Why is this useful?
    /// Types serialized through `bc2wrap` are compatibility-sensitive. A compiler-aware
    /// inventory makes these roots visible without requiring marker traits on foreign types.
    pub BC2WRAP_TYPE_INVENTORY,
    Warn,
    "Collects root types used by bc2wrap serialization and deserialization"
}

impl_lint_pass!(Bc2wrapTypeInventory => [BC2WRAP_TYPE_INVENTORY]);

impl<'tcx> LateLintPass<'tcx> for Bc2wrapTypeInventory {
    // Record each resolved sink call as it is visited. The final JSON is emitted once the crate
    // has been fully checked so the summaries can be built from all call records.
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'_>) {
        let Some((sink, args)) = sink_for_expr(cx, expr) else {
            return;
        };

        for extractor in sink.spec.extractors {
            let root_info = match extract_root_type(*extractor, cx, expr, args, sink.generic_args) {
                ExtractedRoot::Root(root_ty) => classify_root(cx, root_ty),
                ExtractedRoot::NoRoot => continue,
                ExtractedRoot::Unresolved => RootInfo {
                    type_display: "<unknown>".to_string(),
                    def_path: None,
                    owner_crate: None,
                    category: RootCategory::Unknown,
                },
            };
            self.record(cx, expr, &sink, root_info);
        }
    }

    // Write one inventory file per crate target. Dylint also checks build scripts, but those do
    // not represent production bc2wrap call sites for this inventory.
    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        let crate_name = cx.tcx.crate_name(LOCAL_CRATE).to_string();
        if crate_name == "build_script_build" {
            return;
        }

        let target_name = crate_name.clone();
        let calls = std::mem::take(&mut self.calls);

        let inventory = build_inventory(crate_name.clone(), target_name, calls);
        let dir = inventory_dir();
        if let Err(error) = std::fs::create_dir_all(&dir) {
            eprintln!(
                "bc2wrap_type_inventory: failed to create {}: {error}",
                dir.display()
            );
            return;
        }

        let path = dir.join(format!("{crate_name}.json"));
        match serde_json::to_string_pretty(&inventory) {
            Ok(json) => {
                if let Err(error) = std::fs::write(&path, json) {
                    eprintln!(
                        "bc2wrap_type_inventory: failed to write {}: {error}",
                        path.display()
                    );
                    return;
                }
            }
            Err(error) => {
                eprintln!(
                    "bc2wrap_type_inventory: failed to encode JSON for {crate_name}: {error}"
                );
                return;
            }
        }

        if !inventory.calls.is_empty() {
            let local_types = count_types(&inventory.types, |category| {
                *category == RootCategory::Local
            });
            let generic_sinks = count_types(&inventory.types, |category| {
                matches!(*category, RootCategory::Generic | RootCategory::Unknown)
            });
            let skipped_roots = count_types(&inventory.types, |category| {
                !matches!(
                    *category,
                    RootCategory::Local | RootCategory::Generic | RootCategory::Unknown
                )
            });

            eprintln!(
                "bc2wrap_type_inventory: wrote {} calls, {} local types, {} generic sinks, {} skipped roots for {}",
                inventory.calls.len(),
                local_types,
                generic_sinks,
                skipped_roots,
                crate_name
            );
        }
    }
}

impl Bc2wrapTypeInventory {
    fn record<'tcx>(
        &mut self,
        cx: &LateContext<'tcx>,
        expr: &'tcx Expr<'_>,
        sink: &MatchedSink<'tcx>,
        root_info: RootInfo,
    ) {
        if matches!(
            root_info.category,
            RootCategory::Generic | RootCategory::Unknown
        ) {
            cx.span_lint(BC2WRAP_TYPE_INVENTORY, expr.span, |diag| {
                diag.primary_message(format!(
                    "generic or unresolved root type `{}` used by `{}`",
                    root_info.type_display, sink.sink_path,
                ));
                diag.note("The concrete type cannot be inventoried from this generic sink");
            });
        }

        self.calls.push(CallRecord {
            function: sink.spec.function.to_string(),
            sink_path: sink.sink_path.clone(),
            type_display: root_info.type_display,
            def_path: root_info.def_path,
            owner_crate: root_info.owner_crate,
            category: root_info.category,
            source: source_location(cx, expr),
        });
    }
}

/// Resolve a call or method-call expression to one of the configured serialization sinks.
fn sink_for_expr<'tcx>(
    cx: &LateContext<'tcx>,
    expr: &'tcx Expr<'tcx>,
) -> Option<(MatchedSink<'tcx>, &'tcx [Expr<'tcx>])> {
    match expr.kind {
        ExprKind::Call(callee, args) => {
            let (def_id, generic_args) = resolved_call_def(cx, callee)?;
            let spec = sink_spec_for_def(cx, def_id)?;
            Some((MatchedSink::new(cx, spec, def_id, Some(generic_args)), args))
        }
        ExprKind::MethodCall(_, _, args, _) => {
            let def_id = cx.typeck_results().type_dependent_def_id(expr.hir_id)?;
            let spec = sink_spec_for_def(cx, def_id)?;
            Some((MatchedSink::new(cx, spec, def_id, None), args))
        }
        _ => None,
    }
}

/// Resolve the `DefId` and inferred generic arguments of a function call.
fn resolved_call_def<'tcx>(
    cx: &LateContext<'tcx>,
    callee: &'tcx Expr<'_>,
) -> Option<(DefId, GenericArgsRef<'tcx>)> {
    let callee_ty = cx.typeck_results().expr_ty(callee);
    let TyKind::FnDef(def_id, generic_args) = callee_ty.kind() else {
        return None;
    };
    Some((*def_id, generic_args))
}

/// Find the sink spec for a resolved function or method definition.
fn sink_spec_for_def(cx: &LateContext<'_>, def_id: DefId) -> Option<&'static SinkSpec> {
    let item_name = cx.tcx.item_name(def_id);
    let item_name = item_name.as_str();

    SINK_SPECS
        .iter()
        .find(|spec| spec.matches(cx, def_id, item_name))
}

impl SinkSpec {
    fn matches(&self, cx: &LateContext<'_>, def_id: DefId, item_name: &str) -> bool {
        if item_name != self.function {
            return false;
        }

        if let Some(path_contains) = self.path_contains
            && !cx.tcx.def_path_str(def_id).contains(path_contains)
        {
            return false;
        }

        is_workspace_def(cx, def_id, workspace_crates())
    }
}

impl<'tcx> MatchedSink<'tcx> {
    fn new(
        cx: &LateContext<'tcx>,
        spec: &'static SinkSpec,
        def_id: DefId,
        generic_args: Option<GenericArgsRef<'tcx>>,
    ) -> Self {
        Self {
            spec,
            sink_path: cx.tcx.def_path_str(def_id),
            generic_args,
        }
    }
}

/// Extract the root type that a configured sink serializes or deserializes at a call site.
fn extract_root_type<'tcx>(
    extractor: RootExtractor,
    cx: &LateContext<'tcx>,
    expr: &'tcx Expr<'_>,
    args: &'tcx [Expr<'tcx>],
    generic_args: Option<GenericArgsRef<'tcx>>,
) -> ExtractedRoot<'tcx> {
    match extractor {
        RootExtractor::Arg(index) => extract_arg(cx, args, index),
        RootExtractor::OptionTupleRefFirst(index) => option_tuple_ref_first(cx, args, index),
        RootExtractor::ReturnResultOk => decode_ok_type(cx.typeck_results().expr_ty(expr))
            .map(ExtractedRoot::Root)
            .unwrap_or(ExtractedRoot::Unresolved),
        RootExtractor::FnGenericArg(index) => generic_args
            .and_then(|args| args.types().nth(index))
            .map(ExtractedRoot::Root)
            .unwrap_or(ExtractedRoot::Unresolved),
    }
}

fn extract_arg<'tcx>(
    cx: &LateContext<'tcx>,
    args: &'tcx [Expr<'tcx>],
    index: usize,
) -> ExtractedRoot<'tcx> {
    args.get(index)
        .map(|arg| ExtractedRoot::Root(peel_references(cx.typeck_results().expr_ty(arg))))
        .unwrap_or(ExtractedRoot::Unresolved)
}

fn option_tuple_ref_first<'tcx>(
    cx: &LateContext<'tcx>,
    args: &'tcx [Expr<'tcx>],
    index: usize,
) -> ExtractedRoot<'tcx> {
    let Some(arg) = args.get(index) else {
        return ExtractedRoot::Unresolved;
    };

    let ExprKind::Call(_, option_args) = arg.kind else {
        return ExtractedRoot::NoRoot;
    };
    let Some(tuple_expr) = option_args.first() else {
        return ExtractedRoot::NoRoot;
    };
    let ExprKind::Tup(tuple_fields) = tuple_expr.kind else {
        return ExtractedRoot::Unresolved;
    };
    let Some(first_field) = tuple_fields.first() else {
        return ExtractedRoot::Unresolved;
    };

    ExtractedRoot::Root(peel_references(cx.typeck_results().expr_ty(first_field)))
}

/// Return the first type argument of an enum return type, which is `T` for `Result<T, E>`.
///
/// This intentionally stays structural instead of checking for the exact `Result` definition:
/// bc2wrap decode helpers already identify the function, and the first enum type argument is the
/// value type we need from their return signature.
fn decode_ok_type<'tcx>(ty: Ty<'tcx>) -> Option<Ty<'tcx>> {
    let TyKind::Adt(adt_def, args) = ty.kind() else {
        return None;
    };

    if !adt_def.is_enum() {
        return None;
    }
    args.types().next()
}

/// Classify a root type into the inventory categories used by the JSON output.
///
/// Generic roots are kept separate because they identify call sites where the concrete serialized
/// type depends on monomorphization and cannot be represented by one stable root definition.
fn classify_root(cx: &LateContext<'_>, ty: Ty<'_>) -> RootInfo {
    let type_display = ty.to_string();

    if ty.has_param() || ty.has_infer() {
        return RootInfo {
            type_display,
            def_path: None,
            owner_crate: None,
            category: RootCategory::Generic,
        };
    }

    match ty.kind() {
        TyKind::Adt(_, _) | TyKind::Alias(..) => classify_named_root(cx, ty),
        TyKind::Tuple(..) | TyKind::Array(..) | TyKind::Slice(..) => RootInfo {
            type_display,
            def_path: None,
            owner_crate: None,
            category: RootCategory::Compound,
        },
        TyKind::Bool
        | TyKind::Char
        | TyKind::Int(_)
        | TyKind::Uint(_)
        | TyKind::Float(_)
        | TyKind::Str
        | TyKind::Never => RootInfo {
            type_display,
            def_path: None,
            owner_crate: None,
            category: RootCategory::Primitive,
        },
        _ => RootInfo {
            type_display,
            def_path: None,
            owner_crate: None,
            category: RootCategory::Unknown,
        },
    }
}

/// Classify a named root type as local or foreign by comparing its defining crate to the Cargo
/// workspace package set.
fn classify_named_root(cx: &LateContext<'_>, ty: Ty<'_>) -> RootInfo {
    let type_display = ty.to_string();
    let Some(def_id) = get_def_id_from_ty(ty) else {
        return RootInfo {
            type_display,
            def_path: None,
            owner_crate: None,
            category: RootCategory::Unknown,
        };
    };

    let owner_crate = def_crate_name(cx, def_id);
    let def_path = cx.tcx.def_path_str(def_id);
    let category = if is_workspace_def(cx, def_id, workspace_crates()) {
        RootCategory::Local
    } else {
        RootCategory::Foreign
    };

    RootInfo {
        type_display,
        def_path: Some(def_path),
        owner_crate: Some(owner_crate),
        category,
    }
}

/// Convert a rustc span into a stable, JSON-friendly source location.
fn source_location(cx: &LateContext<'_>, expr: &Expr<'_>) -> SourceLocation {
    let position = source_position(cx, expr.span);
    SourceLocation {
        file: position.file,
        line: position.line,
        column: position.column,
    }
}

/// Build the final per-target inventory from the complete set of call records.
fn build_inventory(crate_name: String, target_name: String, calls: Vec<CallRecord>) -> Inventory {
    let types = summarize_types(&calls);

    Inventory {
        crate_name,
        target_name,
        calls,
        types,
    }
}

/// Collapse raw call records into one categorized summary per distinct root type.
///
/// The full `calls` array remains the source of detailed locations. This summary exists for quick
/// auditing by root category, sink path, and call count.
fn summarize_types(calls: &[CallRecord]) -> Vec<TypeSummary> {
    let mut summaries: BTreeMap<SummaryKey, SummaryEntry> = BTreeMap::new();

    for call in calls {
        let key = (
            call.category,
            call.type_display.clone(),
            call.def_path.clone(),
        );
        let entry = summaries.entry(key).or_insert_with(|| SummaryEntry {
            summary: TypeSummary {
                type_display: call.type_display.clone(),
                def_path: call.def_path.clone(),
                owner_crate: call.owner_crate.clone(),
                category: call.category,
                sink_paths: Vec::new(),
                call_count: 0,
            },
            sink_paths: BTreeSet::new(),
        });
        entry.summary.call_count += 1;
        entry.sink_paths.insert(call.sink_path.clone());
    }

    summaries
        .into_values()
        .map(|mut entry| {
            entry.summary.sink_paths = entry.sink_paths.into_iter().collect();
            entry.summary
        })
        .collect()
}

/// Count summary roots matching a category predicate for the stderr status line.
fn count_types(summaries: &[TypeSummary], predicate: impl Fn(&RootCategory) -> bool) -> usize {
    summaries
        .iter()
        .filter(|summary| predicate(&summary.category))
        .count()
}

/// Run the Dylint UI fixture and assert that its JSON inventory keeps the intended categories.
#[test]
fn ui() {
    let output_dir = std::env::temp_dir().join(format!(
        "kms_lints_bc2wrap_type_inventory_ui_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&output_dir);

    // SAFETY: The UI test is single-threaded with respect to this lint invocation, and the
    // environment variables are set before the child cargo process is spawned.
    unsafe {
        std::env::set_var(kms_lints_common::INVENTORY_DIR_ENV, output_dir.as_os_str());
    }

    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "bc2wrap_type_inventory");

    let json_path = output_dir.join("main.json");
    let json = std::fs::read_to_string(&json_path)
        .unwrap_or_else(|error| panic!("expected inventory at {}: {error}", json_path.display()));
    let inventory: serde_json::Value =
        serde_json::from_str(&json).expect("inventory should be valid JSON");

    let types = inventory["types"]
        .as_array()
        .expect("types should be an array");
    assert!(
        types.iter().any(
            |entry| entry["type_display"].as_str() == Some("LocalPayload")
                && entry["category"].as_str() == Some("local")
        ),
        "LocalPayload should be inventoried as a local root"
    );

    assert!(
        types.iter().any(
            |entry| entry["type_display"].as_str() == Some("std::string::String")
                && entry["category"].as_str() == Some("foreign")
        ),
        "String should be recorded as a skipped foreign root"
    );

    assert!(
        types
            .iter()
            .any(|entry| entry["type_display"].as_str() == Some("T")
                && entry["category"].as_str() == Some("generic")
                && sink_paths_contains(entry, "bc2wrap")
                && sink_paths_contains(entry, "vault::storage")),
        "generic T should be recorded by both a bc2wrap and a versioned-storage sink"
    );

    assert!(
        types.iter().any(
            |entry| entry["type_display"].as_str() == Some("LocalStoragePayload")
                && entry["category"].as_str() == Some("local")
                && sink_paths_contains(entry, "vault::storage")
        ),
        "LocalStoragePayload should be inventoried as a local versioned storage root"
    );
}

#[cfg(test)]
fn sink_paths_contains(entry: &serde_json::Value, needle: &str) -> bool {
    entry["sink_paths"]
        .as_array()
        .expect("sink_paths should be an array")
        .iter()
        .any(|path| path.as_str().is_some_and(|p| p.contains(needle)))
}
