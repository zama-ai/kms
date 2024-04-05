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
            "ReencryptionRequest",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .type_attribute(
            "ReencryptionRequestPayload",
            "#[wasm_bindgen::prelude::wasm_bindgen(getter_with_clone)]",
        )
        .type_attribute(
            "ReencryptionRequestPayload",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .type_attribute(
            "ReencryptionResponse",
            "#[wasm_bindgen::prelude::wasm_bindgen(getter_with_clone)]",
        )
        .type_attribute(
            "ReencryptionResponse",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .type_attribute(
            "Eip712DomainMsg",
            "#[wasm_bindgen::prelude::wasm_bindgen(getter_with_clone)]",
        )
        .type_attribute(
            "Eip712DomainMsg",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .compile(&["proto/kms.proto"], &["proto"])?;
    Ok(())
}

#[cfg(feature = "non-wasm")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // tonic_build::compile_protos("proto/kms.proto")?;
    tonic_build::configure()
        .type_attribute(
            "ReencryptionRequest",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .type_attribute(
            "ReencryptionRequestPayload",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .type_attribute(
            "ReencryptionResponse",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .type_attribute(
            "Eip712DomainMsg",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .compile(&["proto/kms.proto"], &["proto"])?;
    Ok(())
}
