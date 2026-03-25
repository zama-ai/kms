// Keep the attribute macro in a separate crate because Rust requires
// `#[proc_macro_attribute]` definitions to live in a proc-macro crate.
// The macro injects the per-test scope and runtime initialization, while the
// sibling `tracing-test` crate owns the shared subscriber and captured-log
// state needed by `logs_contain(...)` assertions.
extern crate proc_macro;

use std::sync::{Mutex, OnceLock};

use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{parse, ItemFn, Stmt};

fn registered_scopes() -> &'static Mutex<Vec<String>> {
    static REGISTERED_SCOPES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    REGISTERED_SCOPES.get_or_init(|| Mutex::new(vec![]))
}

fn get_free_scope(mut test_fn_name: String) -> String {
    let mut vec = registered_scopes().lock().unwrap();
    let mut counter = 1;
    let len = test_fn_name.len();
    while vec.contains(&test_fn_name) {
        counter += 1;
        test_fn_name.replace_range(len.., &counter.to_string());
    }
    vec.push(test_fn_name.clone());
    test_fn_name
}

#[proc_macro_attribute]
pub fn traced_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut function: ItemFn = parse(item).expect("Could not parse ItemFn");
    let scope = get_free_scope(function.sig.ident.to_string());

    let init = parse::<Stmt>(
        quote! {
            tracing_test::internal::INITIALIZED.call_once(|| {
                tracing_test::internal::init_subscriber();
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
            let span = tracing::error_span!(#scope);
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
            fn logs_contain(val: &str) -> bool {
                tracing_test::internal::logs_with_scope_contain(#scope, val)
            }

        }
        .into(),
    )
    .expect("Could not parse quoted statement logs_contain_fn");
    let logs_assert_fn = parse::<Stmt>(
        quote! {
            fn logs_assert(f: impl Fn(&[&str]) -> std::result::Result<(), String>) {
                match tracing_test::internal::logs_assert(#scope, f) {
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
