const DERIVES: &str = "#[derive(serde::Deserialize, serde::Serialize)]";
const EXTENDED_DERIVES: &str =
    "#[derive(serde::Deserialize, serde::Serialize, Hash, Eq, Ord, PartialOrd)]";

// Adding doc
#[cfg(all(not(feature = "non-wasm"), not(feature = "grpc-client")))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_client(false)
        .build_server(false)
        .build_transport(false)
        .type_attribute("DecryptionRequest", DERIVES)
        .type_attribute("DecryptionResponsePayload", DERIVES)
        .type_attribute("ReencryptionRequest", DERIVES)
        .type_attribute("ReencryptionRequestPayload", DERIVES)
        .type_attribute("ReencryptionResponse", DERIVES)
        .type_attribute("ReencryptionResponsePayload", DERIVES)
        .type_attribute("Eip712DomainMsg", DERIVES)
        .type_attribute("KeyGenRequest", DERIVES)
        .type_attribute("KeyGenResult", DERIVES)
        .type_attribute("RequestId", EXTENDED_DERIVES)
        .type_attribute("Config", EXTENDED_DERIVES)
        .type_attribute("SignedPubDataHandle", EXTENDED_DERIVES)
        .type_attribute("CrsGenRequest", DERIVES)
        .type_attribute("CrsGenResult", DERIVES)
        .type_attribute("FheType", "#[wasm_bindgen::prelude::wasm_bindgen]")
        .type_attribute(
            "RequestId",
            "#[wasm_bindgen::prelude::wasm_bindgen(getter_with_clone)]",
        )
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
        .type_attribute(
            "ReencryptionResponsePayload",
            "#[wasm_bindgen::prelude::wasm_bindgen(getter_with_clone)]",
        )
        .type_attribute(
            "Eip712DomainMsg",
            "#[wasm_bindgen::prelude::wasm_bindgen(getter_with_clone)]",
        )
        .compile(&["proto/kms.proto"], &["proto"])?;
    Ok(())
}

#[cfg(any(feature = "non-wasm", feature = "grpc-client"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .type_attribute("DecryptionRequest", DERIVES)
        .type_attribute("DecryptionResponsePayload", DERIVES)
        .type_attribute("ReencryptionRequest", DERIVES)
        .type_attribute("ReencryptionRequestPayload", DERIVES)
        .type_attribute("ReencryptionResponse", DERIVES)
        .type_attribute("ReencryptionResponsePayload", DERIVES)
        .type_attribute("Eip712DomainMsg", DERIVES)
        .type_attribute("KeyGenRequest", DERIVES)
        .type_attribute("KeyGenResult", DERIVES)
        .type_attribute("RequestId", EXTENDED_DERIVES)
        .type_attribute("Config", EXTENDED_DERIVES)
        .type_attribute("SignedPubDataHandle", EXTENDED_DERIVES)
        .type_attribute("CrsGenRequest", DERIVES)
        .type_attribute("CrsGenResult", DERIVES)
        .compile(&["proto/kms.proto"], &["proto"])?;
    Ok(())
}
