use alloy_primitives::address;
use alloy_primitives::bytes;
use alloy_primitives::fixed_bytes;
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::eip712_domain;
use alloy_sol_types::sol;
use alloy_sol_types::SolStruct;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::rand_core::SeedableRng;
use serde::Serialize;
// use kms_lib::cryptography::signcryption::Reencrypt;

sol! {
    #[derive(Serialize)]
    struct Reencrypt {
        bytes publicKey;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example private key (32-byte array, in hexadecimal format)
    let _private_key_bytes =
        fixed_bytes!("7ec931411ad75a7c201469a385d6f18a325d4923f9f213bd882bbea87e160b67");

    let mut rng = aes_prng::AesRng::seed_from_u64(12);
    let sk = SigningKey::random(&mut rng);
    let pk = *SigningKey::verifying_key(&sk);

    let signer = PrivateKeySigner::from_signing_key(sk);
    //let signer = PrivateKeySigner::from_bytes(&private_key_bytes)?;
    println!("Signer address: {:?}", signer.address());

    let domain = eip712_domain! {
        name: "Authorization token",
        version: "1",
        chain_id: 9000,
        verifying_contract: address!("c8c9303Cd7F337fab769686B593B87DC3403E0ce"),
        //salt: keccak256("test"),
    };

    // Define the EIP-712 domain
    let message = Reencrypt {
        publicKey: bytes!("97f272ccfef4026a1f3f0e0e879d514627b84e69"),
    };

    // Derive the EIP-712 signing hash.
    let message_hash = message.eip712_signing_hash(&domain);

    println!("Message hash: {:?}", message_hash);

    // Sign the hash asynchronously with the wallet.
    let signature = signer.sign_hash(&message_hash).await?;

    // Validate that the signature is normalized.
    assert_eq!(signature.normalize_s().unwrap(), signature);

    println!("Signature: {:?}", signature);

    let binding = signature.as_bytes().to_vec();
    let signature = binding.as_slice();

    let signature = alloy_primitives::Signature::try_from(signature)?;

    let recovered_key = signature.recover_from_prehash(&message_hash)?; //signature.recover_from_msg(message_hash.clone())?;
    println!("Recovered key: {:?}", recovered_key);

    assert!(recovered_key == pk);

    println!("Signature: {:?}", signature);

    let recovered_address = signature.recover_address_from_prehash(&message_hash)?;
    println!("Recovered address: {:?}", recovered_address);

    // Verify the signature
    println!(
        "Recovered address matches wallet address: {}",
        signature.recover_address_from_prehash(&message_hash)? == signer.address()
    );

    Ok(())
}
