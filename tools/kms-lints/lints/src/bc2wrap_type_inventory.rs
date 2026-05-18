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
//! Why a compiler plugin? Because we need **post-monomorphization** information.
//! Plain text-search and HIR linting can't tell you that a generic helper is
//! monomorphized to `MyKey` at one call site and `Vec<u8>` at another. Hooking
//! into rustc as a `LateLintPass` lets us ask rustc for the concrete instances
//! it will codegen, then inspect those instances' MIR.
//!
//! ## Vocabulary
//!
//! - **Sink** — a function whose call sites we care about. Sinks are listed in
//!   `SINK_SPECS`. The current set covers the raw encode / decode helpers in
//!   the `bc2wrap` crate and the canonical vault storage reader / writer trait
//!   methods in this workspace.
//! - **Root type** — the top of the type tree handed to a sink. Fields are
//!   *not* recursed into: if a sink receives `&MyStruct { … }`, the root is
//!   `MyStruct`, full stop.
//! - **Extractor** — a `RootExtractor` tells the lint *where* in a
//!   monomorphized call to look for the root.
//!
//! ## Categories
//!
//! Each recorded root is bucketed into a `RootCategory`:
//!
//! - `Local` — defined in a workspace crate. **These are the rows that matter
//!   for backward compatibility.**
//! - `Foreign` — defined in an external dependency. Recorded for visibility.
//! - `Generic` / `Unknown` — the concrete type still isn't resolvable after
//!   monomorphization. Every such occurrence emits a compile-time warning so
//!   the author can refactor the call to expose the concrete type.
//! - `Compound` / `Primitive` — tuples, arrays, ints, etc. Recorded but
//!   normally filtered out downstream.
//!
//! ## Pipeline (per crate)
//!
//! 1. `check_crate_post` seeds a local worklist with codegen-reachable
//!    non-generic MIR roots, then follows local monomorphized calls and
//!    closure / coroutine bodies.
//! 2. The lint deduplicates local function instances and scans each instance's
//!    MIR call terminators. For every call, it substitutes the caller
//!    instance's concrete args into the callee and argument types.
//! 3. `sink_for_mono_call` canonicalizes impl-method calls back to their trait
//!    item when applicable, then matches the callee against `SINK_SPECS`.
//! 4. For each `RootExtractor` on the matched spec, `extract_mono_root_type`
//!    returns either:
//!    - `Root(ty)` — the concrete root. We classify it via `classify_root`
//!      and push a `CallRecord`.
//!    - `Unresolved` — we expected a root and couldn't determine one. We push
//!      a synthetic `<unknown>` record and emit a warning.
//! 5. `check_crate_post` writes the JSON file (one per crate target). The file
//!    contains the full `calls` array plus a deduped `types` summary built by
//!    `summarize_types`.
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
//! 1. rustc monomorphizes the caller containing the call.
//! 2. `collect_mono_calls` scans that caller's MIR and sees a call terminator
//!    whose callee resolves to `bc2wrap::serialize`.
//! 3. `extract_mono_root_type` runs `Arg(0)`: it reads arg 0's monomorphized
//!    type (`&LocalPayload`), peels the reference, and returns
//!    `Root(LocalPayload)`.
//! 4. `classify_root` sees an ADT defined in a workspace crate and returns
//!    `RootCategory::Local`.
//! 5. `record` pushes a `CallRecord` with `function = "serialize"`,
//!    `sink_path = "bc2wrap::serialize"`, `type_display = "LocalPayload"`,
//!    `category = Local`, and the source file / line / column of the matched
//!    lower-level sink call.
//! 6. After every mono item has been scanned, `check_crate_post` collapses
//!    duplicate calls into the `types` summary and writes the JSON file.
//!
//! Replace `&payload` with a generic `value: &T` inside `fn f<T>(value: &T)`
//! and call `f(&payload)`: the monomorphized MIR for `f::<LocalPayload>`
//! still records `LocalPayload`, not `T`. A `Generic` or `Unknown` warning is
//! emitted only if the root remains unresolved after monomorphization.
//!
//! ## How to add a new sink
//!
//! 1. Append an entry to `SINK_SPECS`: the function name, a `path_contains`
//!    substring that disambiguates same-named functions or traits, and one or
//!    more extractors. The sink only matches functions defined in a workspace
//!    crate (via `is_workspace_def`) — there is no separate "owner" knob.
//! 2. If none of the existing `RootExtractor` variants captures where the
//!    root lives in your signature, add a variant and handle it in
//!    `extract_mono_root_type`.
//! 3. Extend the UI fixture in `tests/bc2wrap_type_inventory/main.rs` and add
//!    an assertion in the `ui` test at the bottom of this file so the new
//!    sink is exercised by `cargo test`.
//!
//! ## Configuration
//!
//! Set `KMS_BC2WRAP_INVENTORY_DIR` to override the output directory. The
//! workspace crate set is always auto-detected via `cargo metadata`.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

use kms_lints_common::{
    def_crate_name, get_def_id_from_ty, inventory_dir, is_workspace_def, peel_references,
    source_position, workspace_crates,
};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_middle::mir::{
    AggregateKind, Body, Operand, Rvalue, StatementKind, Terminator, TerminatorKind,
};
use rustc_middle::ty::{
    self, EarlyBinder, GenericArgsRef, Instance, Ty, TyKind, TypeVisitableExt, Unnormalized,
};
use rustc_session::{declare_lint, impl_lint_pass};
use rustc_span::def_id::{DefId, LOCAL_CRATE};
use rustc_span::{Span, Spanned};
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
        extractors: &[RootExtractor::LastFnGenericArg],
    },
    SinkSpec {
        function: "deserialize_unsafe",
        path_contains: Some("bc2wrap"),
        extractors: &[RootExtractor::LastFnGenericArg],
    },
    SinkSpec {
        function: "store_data",
        path_contains: Some("vault::storage::Storage"),
        extractors: &[RootExtractor::Arg(1)],
    },
    SinkSpec {
        function: "store_data_at_epoch",
        path_contains: Some("vault::storage::StorageExt"),
        extractors: &[RootExtractor::Arg(1)],
    },
    SinkSpec {
        function: "read_data",
        path_contains: Some("vault::storage::StorageReader"),
        extractors: &[RootExtractor::LastFnGenericArg],
    },
    SinkSpec {
        function: "read_data_at_epoch",
        path_contains: Some("vault::storage::StorageReaderExt"),
        extractors: &[RootExtractor::LastFnGenericArg],
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

/// Where in a monomorphized sink call the root type lives.
///
/// The convention for `LastFnGenericArg` is that the inventoried type is always the *last* type
/// generic of the callee. For trait methods this works because the implicit `Self` precedes the
/// method's own type params, so `T` in `read_data<T>(&self, ...)` is the last entry in the
/// monomorphized `GenericArgsRef`. For free functions with a single type param (`deserialize_safe<T>`)
/// "last" is equivalently "only".
#[derive(Clone, Copy, Debug)]
enum RootExtractor {
    /// Read the type of the call's positional argument at `index` (after monomorphization and
    /// reference peeling). Arg 0 is the receiver for trait methods.
    Arg(usize),
    /// Read the last type generic of the callee. Used for sinks that take the root by `T` in the
    /// signature (e.g. `deserialize_safe<T>(bytes: &[u8]) -> Result<T, _>`,
    /// `StorageReader::read_data<T>`).
    LastFnGenericArg,
}

#[derive(Clone, Debug)]
struct MatchedSink<'tcx> {
    spec: &'static SinkSpec,
    sink_path: String,
    generic_args: GenericArgsRef<'tcx>,
}

#[derive(Clone, Copy, Debug)]
struct MonoCallee<'tcx> {
    canonical_def_id: DefId,
    generic_args: GenericArgsRef<'tcx>,
    instance: Option<Instance<'tcx>>,
}

#[derive(Clone, Copy, Debug)]
struct MonoCall<'a, 'tcx> {
    caller: Instance<'tcx>,
    body: &'a Body<'tcx>,
    func: &'a Operand<'tcx>,
    args: &'a [Spanned<Operand<'tcx>>],
    span: Span,
}

#[derive(Clone, Copy, Debug)]
enum ExtractedRoot<'tcx> {
    Root(Ty<'tcx>),
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
    // Write one inventory file per crate target. Dylint also checks build scripts, but those do
    // not represent production bc2wrap call sites for this inventory.
    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        let crate_name = cx.tcx.crate_name(LOCAL_CRATE).to_string();
        if crate_name == "build_script_build" {
            return;
        }

        let target_name = crate_name.clone();
        self.collect_mono_calls(cx);
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
    fn collect_mono_calls<'tcx>(&mut self, cx: &LateContext<'tcx>) {
        let tcx = cx.tcx;
        let mut pending = VecDeque::new();
        let mut seen_instances = HashSet::new();

        for &def_id in tcx.mir_keys(()).iter() {
            if tcx.generics_of(def_id).requires_monomorphization(tcx) {
                continue;
            }
            let def_id = def_id.to_def_id();
            let is_root = tcx.entry_fn(()).is_some_and(|(entry, _)| entry == def_id)
                || tcx.is_reachable_non_generic(def_id);
            if is_root {
                pending.push_back(Instance::mono(tcx, def_id));
            }
        }

        while let Some(instance) = pending.pop_front() {
            if !seen_instances.insert(instance) {
                continue;
            }

            let body = tcx.instance_mir(instance.def);
            for basic_block in body.basic_blocks.iter() {
                for statement in &basic_block.statements {
                    if let StatementKind::Assign(assign) = &statement.kind {
                        let (_, rvalue) = &**assign;
                        enqueue_local_aggregate_instance(cx, instance, rvalue, &mut pending);
                    }
                }

                if let Some((func, args, fn_span)) =
                    call_terminator_fields(basic_block.terminator())
                {
                    self.record_mono_call(
                        cx,
                        MonoCall {
                            caller: instance,
                            body,
                            func,
                            args,
                            span: fn_span,
                        },
                        &mut pending,
                    );
                }
            }
        }
    }

    fn record_mono_call<'tcx>(
        &mut self,
        cx: &LateContext<'tcx>,
        call: MonoCall<'_, 'tcx>,
        pending: &mut VecDeque<Instance<'tcx>>,
    ) {
        let Some(callee) = resolve_mono_callee(cx, call.caller, call.body, call.func) else {
            return;
        };
        if let Some(instance) = callee.instance {
            enqueue_local_instance(cx, instance, pending);
        }

        let Some(sink) = sink_for_mono_callee(cx, callee) else {
            return;
        };

        for extractor in sink.spec.extractors {
            let root_info = match extract_mono_root_type(
                *extractor,
                cx,
                call.caller,
                call.body,
                call.args,
                &sink,
            ) {
                ExtractedRoot::Root(root_ty) => classify_root(cx, root_ty),
                ExtractedRoot::Unresolved => RootInfo {
                    type_display: "<unknown>".to_string(),
                    def_path: None,
                    owner_crate: None,
                    category: RootCategory::Unknown,
                },
            };
            self.record(cx, call.span, &sink, root_info);
        }
    }

    fn record<'tcx>(
        &mut self,
        cx: &LateContext<'tcx>,
        span: Span,
        sink: &MatchedSink<'tcx>,
        root_info: RootInfo,
    ) {
        if matches!(
            root_info.category,
            RootCategory::Generic | RootCategory::Unknown
        ) {
            cx.emit_span_lint(
                BC2WRAP_TYPE_INVENTORY,
                span,
                rustc_errors::DiagDecorator(|diag| {
                    diag.primary_message(format!(
                        "generic or unresolved root type `{}` used by `{}`",
                        root_info.type_display, sink.sink_path,
                    ));
                    diag.note("The concrete type could not be inventoried after monomorphization");
                }),
            );
        }

        self.calls.push(CallRecord {
            function: sink.spec.function.to_string(),
            sink_path: sink.sink_path.clone(),
            type_display: root_info.type_display,
            def_path: root_info.def_path,
            owner_crate: root_info.owner_crate,
            category: root_info.category,
            source: source_location(cx, span),
        });
    }
}

/// Resolve a monomorphized MIR call to its concrete instance when rustc can do so.
fn resolve_mono_callee<'tcx>(
    cx: &LateContext<'tcx>,
    caller: Instance<'tcx>,
    body: &Body<'tcx>,
    func: &Operand<'tcx>,
) -> Option<MonoCallee<'tcx>> {
    let callee_ty = monomorphize_ty(cx, caller, func.ty(body, cx.tcx));
    let TyKind::FnDef(def_id, generic_args) = callee_ty.kind() else {
        return None;
    };

    let instance = Instance::try_resolve(
        cx.tcx,
        ty::TypingEnv::fully_monomorphized(),
        *def_id,
        generic_args,
    )
    .ok()
    .flatten();
    let resolved_def_id = instance
        .map(|instance| instance.def_id())
        .unwrap_or(*def_id);
    // Canonicalize impl-method calls back to the trait item so the sink lookup matches the trait
    // path (e.g. `<MemoryStorage as Storage>::store_data` → `Storage::store_data`). We try the
    // resolved (impl) DefId first, then fall back to the unresolved one — the latter fires when
    // `Instance::try_resolve` failed and the original call is already against a trait item.
    let canonical_def_id = cx
        .tcx
        .trait_item_of(resolved_def_id)
        .or_else(|| cx.tcx.trait_item_of(*def_id))
        .unwrap_or(*def_id);

    Some(MonoCallee {
        canonical_def_id,
        generic_args,
        instance,
    })
}

/// Match a resolved monomorphized MIR call against the configured serialization sinks.
fn sink_for_mono_callee<'tcx>(
    cx: &LateContext<'tcx>,
    callee: MonoCallee<'tcx>,
) -> Option<MatchedSink<'tcx>> {
    let spec = sink_spec_for_def(cx, callee.canonical_def_id)?;
    Some(MatchedSink::new(
        cx,
        spec,
        callee.canonical_def_id,
        callee.generic_args,
    ))
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
        generic_args: GenericArgsRef<'tcx>,
    ) -> Self {
        Self {
            spec,
            sink_path: cx.tcx.def_path_str(def_id),
            generic_args,
        }
    }
}

/// Extract the root type that a configured sink serializes or deserializes at a call site.
fn extract_mono_root_type<'tcx>(
    extractor: RootExtractor,
    cx: &LateContext<'tcx>,
    caller: Instance<'tcx>,
    body: &Body<'tcx>,
    args: &[Spanned<Operand<'tcx>>],
    sink: &MatchedSink<'tcx>,
) -> ExtractedRoot<'tcx> {
    match extractor {
        RootExtractor::Arg(index) => extract_mono_arg(cx, caller, body, args, index),
        RootExtractor::LastFnGenericArg => sink
            .generic_args
            .types()
            .last()
            .map(ExtractedRoot::Root)
            .unwrap_or(ExtractedRoot::Unresolved),
    }
}

fn extract_mono_arg<'tcx>(
    cx: &LateContext<'tcx>,
    caller: Instance<'tcx>,
    body: &Body<'tcx>,
    args: &[Spanned<Operand<'tcx>>],
    index: usize,
) -> ExtractedRoot<'tcx> {
    args.get(index)
        .map(|arg| {
            let ty = arg.node.ty(body, cx.tcx);
            let ty = monomorphize_ty(cx, caller, ty);
            ExtractedRoot::Root(peel_references(ty))
        })
        .unwrap_or(ExtractedRoot::Unresolved)
}

/// Extract `(func, args, fn_span)` from any call-shaped terminator. Returns `None` for any other
/// terminator kind.
fn call_terminator_fields<'a, 'tcx>(
    terminator: &'a Terminator<'tcx>,
) -> Option<(&'a Operand<'tcx>, &'a [Spanned<Operand<'tcx>>], Span)> {
    match &terminator.kind {
        TerminatorKind::Call {
            func,
            args,
            fn_span,
            ..
        }
        | TerminatorKind::TailCall {
            func,
            args,
            fn_span,
        } => Some((func, &**args, *fn_span)),
        _ => None,
    }
}

fn monomorphize_ty<'tcx>(cx: &LateContext<'tcx>, caller: Instance<'tcx>, ty: Ty<'tcx>) -> Ty<'tcx> {
    caller.instantiate_mir_and_normalize_erasing_regions(
        cx.tcx,
        ty::TypingEnv::fully_monomorphized(),
        EarlyBinder::bind(ty),
    )
}

fn enqueue_local_aggregate_instance<'tcx>(
    cx: &LateContext<'tcx>,
    caller: Instance<'tcx>,
    rvalue: &Rvalue<'tcx>,
    pending: &mut VecDeque<Instance<'tcx>>,
) {
    let Rvalue::Aggregate(kind, _) = rvalue else {
        return;
    };
    let (AggregateKind::Closure(def_id, args)
    | AggregateKind::Coroutine(def_id, args)
    | AggregateKind::CoroutineClosure(def_id, args)) = &**kind
    else {
        return;
    };

    let args = caller.instantiate_mir_and_normalize_erasing_regions(
        cx.tcx,
        ty::TypingEnv::fully_monomorphized(),
        EarlyBinder::bind(*args),
    );
    let instance = Instance::new_raw(*def_id, args);
    if let Ok(instance) = cx.tcx.try_normalize_erasing_regions(
        ty::TypingEnv::fully_monomorphized(),
        Unnormalized::new_wip(instance),
    ) {
        enqueue_local_instance(cx, instance, pending);
    }
}

fn enqueue_local_instance<'tcx>(
    cx: &LateContext<'tcx>,
    instance: Instance<'tcx>,
    pending: &mut VecDeque<Instance<'tcx>>,
) {
    if instance.def_id().is_local() && cx.tcx.is_mir_available(instance.def_id()) {
        pending.push_back(instance);
    }
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
fn source_location(cx: &LateContext<'_>, span: Span) -> SourceLocation {
    let position = source_position(cx, span);
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
            .all(|entry| entry["category"].as_str() != Some("generic")),
        "generic roots should be resolved by post-monomorphization analysis"
    );

    assert!(
        types.iter().any(
            |entry| entry["type_display"].as_str() == Some("LocalStoragePayload")
                && entry["category"].as_str() == Some("local")
                && sink_paths_contains(entry, "vault::storage::Storage::store_data")
                && sink_paths_contains(entry, "vault::storage::StorageExt::store_data_at_epoch")
                && sink_paths_contains(
                    entry,
                    "vault::storage::StorageReaderExt::read_data_at_epoch"
                )
        ),
        "LocalStoragePayload should be inventoried through canonical storage trait sinks"
    );

    assert!(
        types.iter().any(
            |entry| entry["type_display"].as_str() == Some("LocalPayload")
                && entry["category"].as_str() == Some("local")
                && sink_paths_contains(entry, "bc2wrap::serialize")
                && sink_paths_contains(entry, "vault::storage::StorageReader::read_data")
        ),
        "LocalPayload should include concrete generic bc2wrap and storage-reader roots"
    );

    let calls = inventory["calls"]
        .as_array()
        .expect("calls should be an array");
    assert!(
        calls.iter().all(|entry| {
            let sink_path = entry["sink_path"].as_str().unwrap_or_default();
            !sink_path.contains("store_versioned")
                && !sink_path.contains("read_versioned")
                && !sink_path.contains("write_all")
        }),
        "wrapper functions should not be matched as storage sinks"
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
