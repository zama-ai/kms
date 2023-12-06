use kms::kms::{kms_endpoint_client::KmsEndpointClient, DecryptionRequest, FheType, Proof};

/// This client serves test purposes.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = KmsEndpointClient::connect("http://[::1]:50051").await?;

    let request = tonic::Request::new(DecryptionRequest {
        ciphertext: vec![],
        proof: Some(Proof {
            height: 666,
            merkle_patricia_proof: vec![],
        }),
        fhe_type: FheType::Euint8.into(),
    });

    let response = client.decrypt(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}
