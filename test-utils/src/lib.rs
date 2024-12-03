#![allow(clippy::test_attr_in_doctest)]
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

/// Attribute macro for integration tests that ensures proper setup
/// specifically it creates an env var `RUN_MODE=integration` that
/// disables launcing OpenTelemetry and initiating respective ports by it.
///
/// This macro will wrap the test function with necessary setup code
/// while maintaining the Once initialization pattern.
///
/// Example:
/// ```
/// #[test]
/// #[integration_test]
/// fn my_test() {
///     // test code
/// }
/// ```
#[proc_macro_attribute]
pub fn integration_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the input function
    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_name = &input_fn.sig.ident;
    let fn_block = &input_fn.block;
    let fn_vis = &input_fn.vis;
    let fn_attrs = &input_fn.attrs;

    // Generate the wrapped function
    let output = quote! {
        #(#fn_attrs)*
        #fn_vis fn #fn_name() {
            static INIT: std::sync::Once = std::sync::Once::new();
            INIT.call_once(|| {
                std::env::set_var("RUN_MODE", "integration");
            });
            #fn_block
        }
    };

    output.into()
}
