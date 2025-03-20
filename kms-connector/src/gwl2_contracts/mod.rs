// TODO: Remove this file when gateway-l2 is public
// by direct import httpz_gateway_rust_bindings

use alloy_sol_types::sol;

sol! {
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc)]
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    IDecryptionManager,
    "./gateway-l2/httpz_gateway_rust_bindings/abi/IDecryptionManager.abi"
}

sol! {
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc)]
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    HTTPZ,
    "./gateway-l2/httpz_gateway_rust_bindings/abi/HTTPZ.abi"
}

sol! {
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc)]
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    IKeyManager,
    "./gateway-l2/httpz_gateway_rust_bindings/abi/IKeyManager.abi"
}
