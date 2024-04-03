#[cfg(not(feature = "non-wasm"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_client(false)
        .build_server(false)
        .build_transport(false)
        .type_attribute("FheType", "#[wasm_bindgen::prelude::wasm_bindgen]")
        .type_attribute(
            "ReencryptionRequest",
            "#[wasm_bindgen::prelude::wasm_bindgen(getter_with_clone)]",
        )
        .type_attribute(
            "ReencryptionRequestPayload",
            "#[wasm_bindgen::prelude::wasm_bindgen(getter_with_clone)]",
        )
        .type_attribute(
            "ReencryptionResponse",
            "#[wasm_bindgen::prelude::wasm_bindgen(getter_with_clone)]",
        )
        .compile(&["proto/kms.proto"], &["proto"])?;
    Ok(())
}

#[cfg(feature = "non-wasm")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/kms.proto")?;
    Ok(())
}
