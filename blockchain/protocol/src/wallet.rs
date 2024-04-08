extern crate secp256k1;

use crate::transactions::transaction::Payload;
use crate::transactions::Transaction;
use hashes::{sha256, Hash};
use secp256k1::{ecdsa, Error, Message, Secp256k1, SecretKey, Signing, Verification};
use secp256k1::{PublicKey, SECP256K1};
use sha3::{Digest, Keccak256};

// address type that is a 20 byte array
pub type Address = [u8; 20];

#[derive(Debug, Clone)]
pub struct Wallet {
    secret_key: SecretKey,
    pub public_key: PublicKey,
    pub address: Address,
    pub balance: u64,
}

impl Default for Wallet {
    fn default() -> Self {
        Wallet::new()
    }
}

impl Wallet {
    pub fn new() -> Wallet {
        let (secret_key, public_key) = Wallet::generate_keypair();
        let address = Wallet::derive_address(&public_key);
        Wallet {
            secret_key,
            public_key,
            address,
            balance: 0,
        }
    }

    pub fn generate_keypair() -> (SecretKey, PublicKey) {
        SECP256K1.generate_keypair(&mut rand::thread_rng())
    }

    pub fn derive_address(public_key: &PublicKey) -> Address {
        let hash = Keccak256::digest(&public_key.serialize()[1..]);
        let address = &hash[12..];
        let address_bytes: [u8; 20] = match address.try_into() {
            Ok(arr) => arr,
            Err(_) => panic!("Expected an address of length 20, but it was a different length"),
        };
        address_bytes
    }

    fn verify<C: Verification>(
        secp: &Secp256k1<C>,
        msg: &[u8],
        sig: [u8; 64],
        pubkey: [u8; 33],
    ) -> Result<bool, Error> {
        let msg = sha256::Hash::hash(msg);
        let msg = Message::from_digest_slice(msg.as_ref())?;
        let sig = ecdsa::Signature::from_compact(&sig)?;
        let pubkey = PublicKey::from_slice(&pubkey)?;

        Ok(secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok())
    }

    fn sign<C: Signing>(
        secp: &Secp256k1<C>,
        msg: &[u8],
        seckey: [u8; 32],
    ) -> Result<ecdsa::Signature, Error> {
        let msg = sha256::Hash::hash(msg);
        let msg = Message::from_digest_slice(msg.as_ref())?;
        let seckey = SecretKey::from_slice(&seckey)?;
        Ok(secp.sign_ecdsa(&msg, &seckey))
    }

    pub fn sign_transaction(&self, payload: &Payload) -> Transaction {
        // sanity check
        //transaction.from = self.public_key.serialize().to_vec();
        let secp = Secp256k1::new();
        let serialized_payload = bincode::serialize(payload).unwrap();
        let signature =
            Wallet::sign(&secp, &serialized_payload, self.secret_key.secret_bytes()).unwrap();
        let serialize_sig = signature.serialize_compact();

        assert!(Wallet::verify(
            &secp,
            &serialized_payload,
            serialize_sig,
            self.public_key.serialize()
        )
        .unwrap());

        Transaction {
            from: self.public_key.serialize().to_vec(),
            signature: serialize_sig.to_vec(),
            payload: Some(payload.clone()),
        }
    }

    pub fn verify_transaction(transaction: &Transaction) -> bool {
        let secp = Secp256k1::new();
        let raw_transaction = bincode::serialize(&transaction.payload.clone().unwrap()).unwrap();
        let serialize_sig: [u8; 64] = match transaction.signature.clone().try_into() {
            Ok(arr) => arr,
            Err(_) => panic!("Expected a Vec of length 64, but it was a different length"),
        };

        let pk_slice: [u8; 33] = match transaction.from.clone().try_into() {
            Ok(arr) => arr,
            Err(_) => panic!("Expected a Vec of length 33, but it was a different length"),
        };

        Wallet::verify(&secp, &raw_transaction, serialize_sig, pk_slice).unwrap()
    }
}

pub trait Verify {
    fn verify(&self) -> bool;
}

impl Verify for Transaction {
    fn verify(&self) -> bool {
        Wallet::verify_transaction(self)
    }
}

// tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::transactions::transaction::Payload::Decryption as DecryptionPayload;
    use crate::transactions::Decryption;
    use crate::transactions::RawTransaction;

    #[test]
    fn test_wallet() {
        let alice = Wallet::new();
        let bob = Wallet::new();

        let decryption = DecryptionPayload(Decryption {
            raw: Some(RawTransaction {
                nonce: 0,
                to: Some(bob.public_key.serialize().to_vec()),
                value: 100,
                gas_price: 1,
                gas_limit: 100,
            }),
            ciphertext: vec![1, 2, 3, 4],
        });

        let transaction = alice.sign_transaction(&decryption);
        assert!(Wallet::verify_transaction(&transaction));

        // binary serialization
        let serialized = bincode::serialize(&transaction).unwrap();
        let deserialized = bincode::deserialize(serialized.as_slice()).unwrap();
        assert_eq!(transaction, deserialized);

        // json serialization
        assert!(Wallet::verify_transaction(&deserialized));
    }
}
