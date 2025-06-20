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

/// Attribute macro for enabling persistent trace logs in tests.
///
/// This macro configures file-based trace logging for tests, making them
/// available for CI artifact collection without changing test behavior.
/// It's designed for tests where detailed telemetry data is important for
/// debugging or performance analysis.
///
/// Unlike `integration_test`, this macro focuses solely on trace logging
/// and can be combined with other test attributes.
///
/// Example:
/// ```
/// #[test]
/// #[persistent_traces]
/// fn my_test() {
///     // test code with persistent trace logging
/// }
/// ```
#[proc_macro_attribute]
pub fn persistent_traces(_attr: TokenStream, item: TokenStream) -> TokenStream {
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
                // Configure trace export to file without changing other environment settings
                let sep = std::path::MAIN_SEPARATOR.to_string();
                // Set up the module path for trace logs
                let module_dir = module_path!().replace("::", &sep);
                std::env::set_var("TEST_MODULE_PATH", module_dir);

                // Set test function name for additional context
                let test_fn_name = stringify!(#fn_name);
                std::env::set_var("TEST_FUNCTION_NAME", test_fn_name);

                // Add unique process ID for CI artifacts differentiation
                let process_id = std::process::id().to_string();
                std::env::set_var("TEST_PROCESS_ID", &process_id);

                // Try to get CI job name from env if available
                if let Ok(job) = std::env::var("GITHUB_JOB") {
                    std::env::set_var("TEST_JOB_NAME", job);
                }

                // Enable trace persistence without changing execution environment
                std::env::set_var("TRACE_PERSISTENCE", "enabled");
            });
            #fn_block
        }
    };

    output.into()
}
