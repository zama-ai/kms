//! # Cryptographic Commitment and Serialization Operations
//!
//! This library provides a suite of modules for handling cryptographic commitments,
//! proof operators, and serialization/deserialization operations. These components are
//! designed to facilitate the creation, manipulation, and verification of cryptographic proofs,
//! especially in the context of blockchain applications and merkle trees.

/// The `commitment` module provides functionality related to cryptographic commitments.
///
/// This includes structures and functions for representing, creating, and verifying commitments.
/// Commitments are cryptographic primitives that allow one to commit to a chosen value while
/// keeping it hidden, with the ability to reveal the committed value later.
pub mod commitment;

/// The `operator` module defines traits and implementations for proof operators.
///
/// Proof operators are abstractions used in the verification of cryptographic proofs. They define
/// the operations that can be performed on proofs, such as verification against a commitment or
/// the computation of proof paths. This module provides the necessary interfaces and implementations
/// for handling different types of proof operations.
pub mod operator;

/// The `serde_ops` module focuses on serialization and deserialization operations.
///
/// Serialization is crucial in the context of cryptographic proofs for storage or network
/// transmission. This module provides utilities to serialize and deserialize data structures
/// used in the proof verification process, ensuring compatibility and efficiency. It leverages
/// Rust's `serde` framework for serialization, offering both generic and customized
/// serialization/deserialization solutions for complex cryptographic data types.
pub mod serde_ops;


pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
