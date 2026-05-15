#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

mod bc2wrap_type_inventory;

dylint_linting::dylint_library!();

#[allow(clippy::no_mangle_with_rust_abi)]
#[unsafe(no_mangle)]
pub fn register_lints(_sess: &rustc_session::Session, lint_store: &mut rustc_lint::LintStore) {
    lint_store.register_lints(&[bc2wrap_type_inventory::BC2WRAP_TYPE_INVENTORY]);
    lint_store
        .register_late_pass(|_| Box::new(bc2wrap_type_inventory::Bc2wrapTypeInventory::default()));
}
