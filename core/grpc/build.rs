use tonic_build::Builder;

const DERIVES: &str = "#[derive(serde::Deserialize, serde::Serialize)]";
const EXTENDED_DERIVES: &str =
    "#[derive(serde::Deserialize, serde::Serialize, Hash, Eq, Ord, PartialOrd)]";

fn default_builder() -> Builder {
    tonic_build::configure()
        .type_attribute("DecryptionRequest", DERIVES)
        .type_attribute("DecryptionResponsePayload", DERIVES)
        .type_attribute("ExternalDecryptionResult", DERIVES)
        .type_attribute("ReencryptionRequest", DERIVES)
        .type_attribute("ReencryptionRequestPayload", DERIVES)
        .type_attribute("ReencryptionResponse", DERIVES)
        .type_attribute("ReencryptionResponsePayload", DERIVES)
        .type_attribute("Eip712DomainMsg", DERIVES)
        .type_attribute("KeyGenRequest", DERIVES)
        .type_attribute("TypedCiphertext", DERIVES)
        .type_attribute("KeyGenResult", DERIVES)
        .type_attribute("RequestId", EXTENDED_DERIVES)
        .type_attribute("Config", EXTENDED_DERIVES)
        .type_attribute("SignedPubDataHandle", EXTENDED_DERIVES)
        .type_attribute("CrsGenRequest", DERIVES)
        .type_attribute("CrsGenResult", DERIVES)
        .type_attribute("VerifyProvenCtResponse", DERIVES)
        .type_attribute("VerifyProvenCtResponsePayload", DERIVES)
        .type_attribute("TypedPlaintext", EXTENDED_DERIVES)
        .type_attribute("KeySetConfig", DERIVES)
        .type_attribute("KeySetType", DERIVES)
        .type_attribute("StandardKeySetConfig", DERIVES)
        .type_attribute("ComputeKeyType", DERIVES)
        .type_attribute("KeySetAddedInfo", DERIVES)
}

// This is the `main` for wasm builds, which does not include
// client, server or transport.
#[cfg(not(feature = "non-wasm"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    default_builder()
        .build_client(false)
        .build_server(false)
        .build_transport(false)
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
        .compile_protos(&["proto/kms.v1.proto"], &["proto"])?;
    Ok(())
}

#[cfg(all(feature = "non-wasm", not(feature = "insecure")))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    default_builder().compile_protos(&["proto/kms-service.v1.proto"], &["proto"])?;
    Ok(())
}

#[cfg(all(feature = "non-wasm", feature = "insecure"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    default_builder().compile_protos(&["proto/kms-service-insecure.v1.proto"], &["proto"])?;
    Ok(())
}
