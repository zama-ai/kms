use serde_asn1_der::to_vec;
use kms::core::der_types::{PrivateSigKey, PublicSigKey, Signature};
use kms::core::kms_core::get_address;
use kms::core::signcryption::{sign, verify_sig};
use kms::file_handling::read_element;
use kms::kms::{
    DecryptionRequest, DecryptionRequestPayload, FheType, kms_endpoint_client::KmsEndpointClient,
    Proof,
};

use crate::key_setup::{DEFAULT_CIPHER_PATH, DEFAULT_CLIENT_KEY_PATH, DEFAULT_SERVER_KEY_PATH};

mod key_setup;

/// This client serves test purposes.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = KmsEndpointClient::connect("http://0.0.0.0:50051").await?;

    let server_pk: PublicSigKey =
        read_element(DEFAULT_SERVER_KEY_PATH.to_string())?;
    let (client_pk, client_sk): (PublicSigKey, PrivateSigKey) =
        read_element(DEFAULT_CLIENT_KEY_PATH.to_string())?;
    let ct: Vec<u8> = read_element(DEFAULT_CIPHER_PATH.to_string())?;

    let payload = DecryptionRequestPayload {
        address: get_address(&client_pk).to_vec(),
        fhe_type: FheType::Euint8.into(),
        ciphertext: ct,
        proof: Some(Proof {
            height: 0,
            merkle_patricia_proof: vec![],
        }),
        randomness: Vec::new(),
    };
    let sig = sign(&to_vec(&payload).unwrap(), &client_sk).unwrap();
    let request = tonic::Request::new(DecryptionRequest {
        signature: to_vec(&sig).unwrap(),
        payload: Some(payload),
    });

    let response = client.decrypt(request).await?;

    println!("RESPONSE={:?}", response);
    let inner_resp = response.into_inner();
    let sig = Signature {
        sig: k256::ecdsa::Signature::from_slice(&inner_resp.signature)?,
        pk: server_pk.clone(),
    };
    match verify_sig(&to_vec(&inner_resp.payload.unwrap())?, &sig, &server_pk) {
        true => println!("Received response is valid!"),
        false => println!("Received response is NOT valid!"),
    }

    Ok(())
}

