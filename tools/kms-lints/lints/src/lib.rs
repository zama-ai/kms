#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_errors;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

mod bc2wrap_type_inventory;

#[allow(unused_extern_crates)]
extern crate rustc_driver;

#[doc(hidden)]
#[unsafe(no_mangle)]
pub extern "C" fn dylint_version() -> *mut std::os::raw::c_char {
    std::ffi::CString::from(c"0.1.0").into_raw()
}

#[allow(clippy::no_mangle_with_rust_abi)]
#[unsafe(no_mangle)]
pub fn register_lints(_sess: &rustc_session::Session, lint_store: &mut rustc_lint::LintStore) {
    lint_store.register_lints(&[bc2wrap_type_inventory::BC2WRAP_TYPE_INVENTORY]);
    lint_store
        .register_late_pass(|_| Box::new(bc2wrap_type_inventory::Bc2wrapTypeInventory::default()));
}
