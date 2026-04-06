// Keep the attribute macro in a separate crate because Rust requires
// `#[proc_macro_attribute]` definitions to live in a proc-macro crate.
// The macro injects the per-test scope and runtime initialization, while the
// sibling `kms-test-tracing` crate owns the shared subscriber and captured-log
// state needed by `logs_contain(...)` assertions.
//
// Scope names are fully qualified via `concat!(module_path!(), "::", fn_name)`
// so tests with the same function name in different modules get distinct scopes.
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{ToTokens, quote};
use syn::{ItemFn, Stmt, parse};

#[proc_macro_attribute]
pub fn traced_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut function: ItemFn = parse(item).expect("Could not parse ItemFn");
    let fn_name = function.sig.ident.to_string();

    let init = parse::<Stmt>(
        quote! {
            kms_test_tracing::internal::INITIALIZED.call_once(|| {
                kms_test_tracing::internal::init_subscriber();
            });
        }
        .into(),
    )
    .expect("Could not parse quoted statement init");
    let span = parse::<Stmt>(
        quote! {
            // Keep the synthetic test scope visible even when CI forces an
            // `error`-level console filter; lower-level span metadata can be
            // filtered out before captured assertions inspect the emitted logs.
            let span = tracing::error_span!(concat!(module_path!(), "::", #fn_name));
        }
        .into(),
    )
    .expect("Could not parse quoted statement span");
    let enter = parse::<Stmt>(
        quote! {
            let _enter = span.enter();
        }
        .into(),
    )
    .expect("Could not parse quoted statement enter");
    let logs_contain_fn = parse::<Stmt>(
        quote! {
            #[allow(dead_code)]
            fn logs_contain(val: &str) -> bool {
                kms_test_tracing::internal::logs_with_scope_contain(
                    concat!(module_path!(), "::", #fn_name),
                    val,
                )
            }
        }
        .into(),
    )
    .expect("Could not parse quoted statement logs_contain_fn");
    let logs_assert_fn = parse::<Stmt>(
        quote! {
            #[allow(dead_code)]
            fn logs_assert(f: impl Fn(&[&str]) -> std::result::Result<(), String>) {
                match kms_test_tracing::internal::logs_assert(
                    concat!(module_path!(), "::", #fn_name),
                    f,
                ) {
                    Ok(()) => {}
                    Err(msg) => panic!("The logs_assert function returned an error: {}", msg),
                };
            }
        }
        .into(),
    )
    .expect("Could not parse quoted statement logs_assert_fn");

    function.block.stmts.insert(0, init);
    function.block.stmts.insert(1, span);
    function.block.stmts.insert(2, enter);
    function.block.stmts.insert(3, logs_contain_fn);
    function.block.stmts.insert(4, logs_assert_fn);

    TokenStream::from(function.to_token_stream())
}
