//! # Serialization Wrappers for Tendermint Merkle Proofs
//!
//! This module defines structures and functions to facilitate the serialization and deserialization
//! of Tendermint's cryptographic proof structures. It introduces wrapper structs to adapt these proofs
//! for serialization frameworks, specifically targeting the use case with Serde for JSON or other formats.
//! The wrappers employ base64 encoding for binary data to ensure the serialized format is text-based and
//! easily transmittable.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tendermint::merkle::proof::ProofOp;
use tendermint::merkle::proof::ProofOps;
use tendermint_proto::v0_38::crypto::ProofOps as RawProofOps;

/// A wrapper around Tendermint's `ProofOp` to adapt it for Serde serialization.
///
/// This struct serves as an intermediate representation, converting binary data
/// fields (`key`, `data`) into base64-encoded strings to ensure a text-based format
/// suitable for JSON serialization and other text-based formats.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct WrappedProofOp {
    /// The type of the proof operation, directly mapped from Tendermint's `ProofOp`.
    pub field_type: String,
    /// The key associated with the proof operation, base64-encoded.
    pub key: Vec<u8>,
    /// The data for the proof operation, base64-encoded.
    pub data: Vec<u8>,
}

/// A wrapper around Tendermint's `ProofOps` to adapt it for Serde serialization.
///
/// Contains a vector of `WrappedProofOp`, facilitating serialization of a sequence of proof
/// operations. This struct is particularly useful for serializing complex proofs consisting of
/// multiple operations.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct WrappedProofOps {
    /// A collection of wrapped proof operations.
    pub ops: Vec<WrappedProofOp>,
}

impl From<ProofOp> for WrappedProofOp {
    /// Converts a Tendermint `ProofOp` into a `WrappedProofOp`.
    ///
    /// This conversion involves base64-encoding the binary `key` and `data` fields of `ProofOp`
    /// to ensure the wrapper is fully text-based and compatible with JSON serialization.
    fn from(proof_op: ProofOp) -> Self {
        WrappedProofOp {
            field_type: proof_op.field_type,
            key: base64::encode(proof_op.key).into(),
            data: base64::encode(proof_op.data).into(),
        }
    }
}

impl From<WrappedProofOp> for ProofOp {
    /// Converts a `WrappedProofOp` back into a Tendermint `ProofOp`.
    ///
    /// This involves base64-decoding the `key` and `data` fields. It is assumed that the encoded
    /// data is correctly base64-encoded; otherwise, the `unwrap` could panic.
    fn from(inter_op: WrappedProofOp) -> Self {
        ProofOp {
            field_type: inter_op.field_type,
            key: base64::decode(inter_op.key).unwrap(),
            data: base64::decode(inter_op.data).unwrap(),
        }
    }
}

impl From<ProofOps> for WrappedProofOps {
    /// Converts Tendermint `ProofOps` into `WrappedProofOps` for serialization.
    ///
    /// Each `ProofOp` within the `ProofOps` is converted into a `WrappedProofOp`, facilitating
    /// the serialization of the entire proof operation sequence.
    fn from(proof_ops: ProofOps) -> Self {
        WrappedProofOps {
            ops: proof_ops
                .ops
                .into_iter()
                .map(WrappedProofOp::from)
                .collect(),
        }
    }
}

impl From<WrappedProofOps> for ProofOps {
    /// Converts `WrappedProofOps` back into Tendermint `ProofOps`.
    ///
    /// This conversion is used after deserialization, reconstructing the original `ProofOps`
    /// from the text-based wrapper.
    fn from(inter_ops: WrappedProofOps) -> Self {
        ProofOps {
            ops: inter_ops.ops.into_iter().map(ProofOp::from).collect(),
        }
    }
}

/// Custom serializer for `ProofOps` using Serde.
///
/// This function wraps the `ProofOps` into `WrappedProofOps` before serializing, converting binary
/// data to a base64-encoded string format suitable for text-based serialization formats like JSON.
pub fn ser_proof_ops<S>(proof_ops: &ProofOps, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let wrapped_proof_ops: WrappedProofOps = (*proof_ops).clone().into();
    wrapped_proof_ops.serialize(serializer)
}

/// Custom deserializer for `ProofOps` using Serde.
///
/// Deserializes data into `WrappedProofOps` and then converts it back into `ProofOps`,
/// performing base64 decoding of the binary fields in the process.
pub fn des_proof_ops<'de, D>(deserializer: D) -> Result<ProofOps, D::Error>
where
    D: Deserializer<'de>,
{
    let wrapped_proof_ops = WrappedProofOps::deserialize(deserializer)?;
    Ok(wrapped_proof_ops.into())
}

pub fn raw_to_proof_ops(raw_proof_ops: RawProofOps) -> ProofOps {
    let mut ops: Vec<ProofOp> = vec![];
    // loops throug the decoded_raw.ops and build a vector of ProofOp from it
    for op in raw_proof_ops.ops {
        ops.push(ProofOp {
            field_type: op.r#type,
            key: op.key,
            data: op.data,
        });
    }

    // build a ProofOps from the decoded_raw
    ProofOps { ops }
}

// test
#[cfg(test)]
mod tests {
    use super::*;
    use tendermint::merkle::proof::ProofOp;
    use tendermint::merkle::proof::ProofOps;

    #[test]
    fn test_ser_proof_ops() {
        let proof_ops = ProofOps {
            ops: vec![
                ProofOp {
                    field_type: "field_type".to_string(),
                    key: vec![1, 2, 3],
                    data: vec![4, 5, 6],
                },
                ProofOp {
                    field_type: "field_type2".to_string(),
                    key: vec![7, 8, 9],
                    data: vec![10, 11, 12],
                },
            ],
        };

        // Serialize using prost
        //let encoded: Vec<u8> = prost::Message::encode_to_vec(&raw_proof_ops);

        let encoded = hex::decode("0aba030a0a69637332333a6961766c1235020a9368e9c545238c82a2faed62e631450d6432c100000000000000000000000000000000000000000000000000000000000000001af4020af1020a35020a9368e9c545238c82a2faed62e631450d6432c10000000000000000000000000000000000000000000000000000000000000000122000fe45721cca632a7bfd41731597b9c429d1eb3e7c0bdee9f93b8457b8e8ea2b1a0c0801180120012a040002c601222c080112050204c601201a212017d89f809694c84d9804c31753ed3b2b5a0fb1c1fcd0e12ac23e90bb5cb1631e222a080112260408c60120ba177f3df5846e5b37f803039694540d3058b905680b998ab5ec278a984e255b20222a080112260610c601205d8ba0070abec0ef6fcecb128ecb04cd74201c212e69ea41e3afc0a09821767920222a080112260820c601204d9768b67c3c1dcced0c551955affe6543d84fd5db82212a0ef96ad06acc702c20222a080112260a30c60120c5c11bfdfa26f1993937eacf0681a70995cea9b77d43c0e6f819af990f3ec1c620222a080112260c50c601204776998adaf284b2e37fe88b33c52f59847dfa61fa4f4f7efd66d9a4e433b515200a94020a0c69637332333a73696d706c65120365766d1afe010afb010a0365766d1220df1f9cda2162dbd0084eb01a6ab6391cc3ce8208c597d86e9a6ae85f5e6502e61a090801180120012a0100222708011201011a20382fe7d260d7d08ad6075c1b815e1943c2c700202292b4a106f6c4dc554891562225080112210176de43ccf7110b83a71401ec10cec62b16e29f9d0a8431c276f8f0efb66d0509222508011221015ef24443bc00b440548d7a10950d8ae35b8afcf73830a6e49aeb699958a0ea5e222708011201011a20d6fccfbe60c68f52ac9dae9c23f6de07a9c1969d8d2855bcbb1cbd671b354b03222708011201011a20fcce8d7181acc9a611be74f97dc062d12a530171658f7582af9ee817dcede532")
                                 .unwrap();

        // Deserialize using prost
        //let pops = ProofOps{ ops: vec![] };
        //pops.merge(encoded.as_slice()).unwrap();

        let decoded_raw: RawProofOps = prost::Message::decode(&*encoded).unwrap();

        //let decoded_raw: ProofOps = ProofOps::decode(encoded).unwrap()?;

        println!("Original: {:?}", proof_ops);
        println!("Decoded: {:?}", decoded_raw);

        let serialized = serde_json::to_string(&proof_ops).unwrap();
        let deserialized: ProofOps = serde_json::from_str(&serialized).unwrap();

        assert_eq!(proof_ops, deserialized);
    }

    #[test]
    fn test_ser_proof_op() {
        let proof_op = ProofOp {
            field_type: "field_type".to_string(),
            key: vec![1, 2, 3],
            data: vec![4, 5, 6],
        };

        let serialized = serde_json::to_string(&proof_op).unwrap();
        let deserialized: ProofOp = serde_json::from_str(&serialized).unwrap();

        assert_eq!(proof_op, deserialized);
    }
}
