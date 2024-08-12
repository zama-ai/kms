//! # Proof Operators and Runtime Verification
//!
//! This module provides the structures and functions to work with cryptographic proofs,
//! specifically targeting the verification of merkle proofs within the context of blockchain
//! applications. It supports various proof formats through a pluggable decoder mechanism.
//!

#![allow(dead_code)]
use super::commitment::commitment_op_decoder;
use super::commitment::{PROOF_OP_IAVL_COMMITMENT, PROOF_OP_SIMPLE_MERKLE_COMMITMENT};
use anyhow::anyhow;
use percent_encoding::percent_decode_str;
use percent_encoding::utf8_percent_encode;
use percent_encoding::NON_ALPHANUMERIC;
use std::error::Error;
use std::{collections::HashMap, path::MAIN_SEPARATOR};
use tendermint::merkle::proof::ProofOp;
use tendermint::merkle::proof::ProofOps;

/// A trait defining operations for a proof operator.
/// Proof operators are responsible for executing cryptographic proofs.
pub trait ProofOperator {
    /// Runs the proof operation with the provided arguments.
    ///
    /// # Arguments
    ///
    /// * `args` - A vector of byte vectors representing the arguments to the proof operation.
    ///
    /// # Returns
    ///
    /// A result containing either the output of the proof operation as a vector of byte vectors,
    /// or an error if the operation fails.
    fn run(&self, args: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, Box<dyn Error>>;

    /// Retrieves the key associated with this proof operation.
    ///
    /// # Returns
    ///
    /// A result containing either the key as a byte vector, or an error if no key is available.
    fn get_key(&self) -> Result<Vec<u8>, Box<dyn Error>>;
}

/// A container for multiple proof operators.
struct ProofOperators(Vec<Box<dyn ProofOperator>>);

impl ProofOperators {
    /// Verifies a value given a root hash, a key path, and the expected value.
    ///
    /// This is a convenience method for verifying a single value.
    ///
    /// # Arguments
    ///
    /// * `root` - The root hash of the proof.
    /// * `key_path` - The path to the key within the proof, as a string.
    /// * `value` - The expected value to verify, as a byte vector.
    ///
    /// # Returns
    ///
    /// A result indicating success if the value is verified, or an error if verification fails.
    #[allow(dead_code)]
    fn verify_value(
        &self,
        root: Vec<u8>,
        key_path: &str,
        value: Vec<u8>,
    ) -> Result<(), Box<dyn Error>> {
        self.verify(root, key_path, vec![value])
    }

    /// Verifies a proof given a root hash, a key path, and arguments.
    ///
    /// # Arguments
    ///
    /// * `root` - The root hash of the proof.
    /// * `keypath` - The path to the key within the proof, as a string.
    /// * `args` - A vector of arguments to the proof operation, as byte vectors.
    ///
    /// # Returns
    ///
    /// A result indicating success if the proof is verified, or an error if verification fails.
    fn verify(
        &self,
        root: Vec<u8>,
        keypath: &str,
        mut args: Vec<Vec<u8>>,
    ) -> Result<(), Box<dyn Error>> {
        let mut keys = key_path_to_keys(keypath)?;
        if keys.is_empty() {
            return Err("Key path is empty".into());
        }

        for (i, op) in self.0.iter().enumerate() {
            let key = op.get_key()?;
            if !key.is_empty() {
                if keys.is_empty() {
                    return Err(format!("Key path has insufficient number of parts: expected no more keys but got {:?}", key).into());
                }
                let last_key = keys.pop().unwrap(); // Safe to unwrap due to the check above
                if last_key != key {
                    return Err(format!(
                        "Key mismatch on operation #{}: expected {:?} but got {:?}",
                        i,
                        hex::encode(last_key),
                        hex::encode(key)
                    )
                    .into());
                }
            }

            args = op.run(args)?;
        }

        if args.len() != 1 || args[0] != root {
            return Err(format!(
                "Calculated root hash is invalid: expected {} but got {}",
                hex::encode(root),
                hex::encode(args.first().unwrap_or(&vec![]))
            )
            .into());
        }
        if !keys.is_empty() {
            return Err("Keypath not fully consumed".into());
        }

        Ok(())
    }
}

/// Represents the runtime environment for proof verification.
///
/// It holds a registry of proof operators, allowing for the decoding and verification of proofs
/// using registered operators.
#[allow(clippy::type_complexity)]
pub struct ProofRuntime {
    decoders:
        HashMap<String, Box<dyn Fn(ProofOp) -> Result<Box<dyn ProofOperator>, Box<dyn Error>>>>,
}

impl Default for ProofRuntime {
    fn default() -> Self {
        default_proof_runtime()
    }
}

impl ProofRuntime {
    /// Constructs a new `ProofRuntime`.
    ///
    /// Initializes an empty `ProofRuntime` with no decoders registered. Decoders must be registered
    /// using the `register_op_decoder` method before the runtime can be used to decode and verify proofs.
    ///
    pub fn new() -> Self {
        ProofRuntime {
            decoders: HashMap::new(),
        }
    }

    /// Registers a proof operator decoder for a specific proof type.
    ///
    /// This method allows the runtime to be extended with custom proof verification logic by associating
    /// a proof type identifier with a decoder function. If a decoder for the given type is already registered,
    /// this method will return an error.
    ///
    /// # Arguments
    ///
    /// * `typ` - A string slice representing the proof type identifier.
    /// * `dec` - A function that takes a `ProofOp` and returns a `Result` containing a boxed `ProofOperator`.
    ///
    /// # Returns
    ///
    /// Ok(()) if the decoder was successfully registered, or an error if a decoder for the type is already present.
    ///
    pub fn register_op_decoder<F>(&mut self, typ: &str, dec: F) -> Result<(), Box<dyn Error>>
    where
        F: 'static + Fn(ProofOp) -> Result<Box<dyn ProofOperator>, Box<dyn Error>>,
    {
        if self.decoders.contains_key(typ) {
            return Err(anyhow!("already registered for type {}", typ).into());
            //anyhow!("already registered for type {}", typ);
        }
        self.decoders.insert(typ.to_string(), Box::new(dec));
        Ok(())
    }

    /// Attempts to decode a `ProofOp` using the registered decoders.
    ///
    /// Looks up the decoder associated with the `ProofOp`'s type and applies it to decode the `ProofOp` into
    /// a `ProofOperator`. If no decoder is found for the type, this method returns an error.
    ///
    /// # Arguments
    ///
    /// * `pop` - The `ProofOp` to decode.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decoded `ProofOperator` if successful, or an error if no decoder is registered
    /// for the `ProofOp`'s type.
    ///
    pub fn decode(&self, pop: &ProofOp) -> Result<Box<dyn ProofOperator>, Box<dyn Error>> {
        match self.decoders.get(&pop.field_type) {
            Some(decoder) => decoder(pop.clone()),
            None => Err(anyhow!("Unregistered proof operator type").into()),
        }
    }

    fn decode_proof(&self, proof: &ProofOps) -> Result<Box<ProofOperators>, Box<dyn Error>> {
        let mut ops = Vec::with_capacity(proof.ops.len());
        for pop in &proof.ops {
            let op = self.decode(pop)?;
            ops.push(op);
        }
        Ok(Box::new(ProofOperators(ops)))
    }

    /// Decodes each `ProofOp` in a `ProofOps` and verifies them against a given root and optional arguments.
    ///
    /// This method is the primary entry point for verifying proofs. It decodes each `ProofOp` in the given `ProofOps`,
    /// then sequentially verifies each operation against the provided root hash, key path, and arguments.
    ///
    /// # Arguments
    ///
    /// * `proof` - The `ProofOps` containing the sequence of proof operations to verify.
    /// * `root` - The root hash against which to verify the proof operations, as a byte slice.
    /// * `keypath` - The path to the key within the proof, as a string.
    /// * `args` - An optional vector of arguments to pass to the proof operations, as a vector of byte vectors.
    ///
    /// # Returns
    ///
    /// Ok(()) if all proof operations are successfully verified against the root, or an error if any verification step fails.
    ///
    pub fn verify(
        &self,
        proof: &ProofOps,
        root: &[u8],
        keypath: &str,
        args: &Option<Vec<Vec<u8>>>,
    ) -> Result<(), Box<dyn Error>> {
        let operators = self.decode_proof(proof)?;
        operators.verify(root.to_vec(), keypath, args.clone().unwrap().to_vec())
    }

    // Verifies a value given a proof, root, keypath, and the value
    pub fn verify_value(
        &self,
        proof: &ProofOps,
        root: &[u8],
        keypath: &str,
        value: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.verify(proof, root, keypath, &Some(vec![value.to_vec()]))
    }
}

/// Constructs the default `ProofRuntime` with pre-registered decoders.
///
/// Returns:
/// The default `ProofRuntime` instance.
///
/// This function pre-registers a set of known decoder functions for common proof types, allowing
/// for immediate use of the runtime for verifying these proof types without manual registration.
pub fn default_proof_runtime() -> ProofRuntime {
    let mut prt = ProofRuntime::new();

    // Assuming `commitment_op_decoder` is defined elsewhere and matches the expected signature.
    if let Err(err) = prt.register_op_decoder(PROOF_OP_IAVL_COMMITMENT, commitment_op_decoder) {
        eprintln!("Failed to register op decoder: {}", err);
    }
    if let Err(err) =
        prt.register_op_decoder(PROOF_OP_SIMPLE_MERKLE_COMMITMENT, commitment_op_decoder)
    {
        eprintln!("Failed to register op decoder: {}", err);
    }
    prt
}

/// # Key Encoding and Path Handling
///
/// This module provides functionality for handling key encodings and paths. It is particularly useful
/// in contexts where keys need to be encoded in different formats (e.g., URL, Hex) and combined into paths
/// for cryptographic proofs or similar applications.
/// Represents the encoding format of a key.
///
/// This enum is used to specify how a key should be encoded when converting it to a string representation.
#[derive(Debug, Clone, Copy)]
pub enum KeyEncoding {
    /// URL encoding format, where characters are percent-encoded to make them safe for use in URLs.
    Url = 0,
    /// Hexadecimal encoding format, where binary data is represented as a string of hexadecimal digits.
    #[allow(dead_code)]
    Hex = 1,
}

impl KeyEncoding {
    /// Returns `true` if the key encoding is [`Hex`].
    ///
    /// [`Hex`]: KeyEncoding::Hex
    pub fn is_hex(&self) -> bool {
        matches!(self, Self::Hex)
    }
}

impl Default for KeyEncoding {
    fn default() -> Self {
        Self::Url
    }
}

/// A struct representing a key with a specified encoding.
///
/// This struct encapsulates a key and its encoding format, providing a basis for converting the key
/// into a properly encoded string.
#[derive(Debug, Clone)]
pub struct Key {
    /// The raw bytes of the key.
    name: Vec<u8>,
    /// The encoding format of the key.
    enc: KeyEncoding,
}

impl Key {
    /// Constructs a new `Key` with the specified name and encoding.
    ///
    /// Arguments:
    /// * `name`: The raw bytes of the key.
    /// * `enc`: The encoding format to be used for the key.
    ///
    /// Returns:
    /// * A new `Key` instance.
    pub fn new(name: Vec<u8>, enc: KeyEncoding) -> Self {
        Self { name, enc }
    }
}

/// Represents a path composed of multiple keys, each with its own encoding.
///
/// This struct provides functionality for appending keys to the path and converting the entire path
/// into a string representation, taking into account the encoding of each key.
#[derive(Debug, Clone, Default)]
pub struct KeyPath(Vec<Key>);

impl KeyPath {
    /// Appends a key with the specified encoding to the path.
    ///
    /// Arguments:
    /// * `key`: The raw bytes of the key to append.
    /// * `enc`: The encoding format of the key.
    pub fn append_key(&mut self, key: Vec<u8>, enc: KeyEncoding) {
        self.0.push(Key::new(key, enc))
    }

    /// Converts the key path into a string representation.
    ///
    /// Each key in the path is converted to its string representation according to its encoding,
    /// and the keys are concatenated into a single string with slashes (`/`) as separators.
    ///
    /// Returns:
    /// * A result containing the string representation of the key path, or an error if any key
    ///   cannot be properly encoded.
    pub fn to_string(&self) -> Result<String, Box<dyn Error>> {
        let mut res = String::new();
        for key in &self.0 {
            match key.enc {
                KeyEncoding::Url => {
                    let name = String::from_utf8(key.name.clone())?;
                    let encoded = utf8_percent_encode(&name, NON_ALPHANUMERIC);
                    res.push_str(&format!("/{}", encoded));
                }
                KeyEncoding::Hex => {
                    res.push_str(&format!("/x:{}", hex::encode(key.name.clone())));
                }
            }
        }
        Ok(res)
    }
}

/// Converts a key path string into a vector of keys, each represented as a vector of bytes.
///
/// This function parses a key path string, interpreting each segment according to its prefix
/// (`x:` for hex-encoded segments, no prefix for URL-encoded segments), and returns the raw bytes
/// of each key.
///
/// Arguments:
/// * `path`: The key path string to parse.
///
/// Returns:
/// * A result containing a vector of keys (each as a vector of bytes), or an error if the path is invalid
///   or any segment cannot be properly decoded.
fn key_path_to_keys(path: &str) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    if !path.starts_with(MAIN_SEPARATOR) || path.is_empty() {
        return Err(
            format!("key path string must start with a forward slash '{MAIN_SEPARATOR}'").into(),
        );
    }

    let parts = path[1..].split(MAIN_SEPARATOR).collect::<Vec<_>>();
    let mut keys = Vec::with_capacity(parts.len());

    for (i, part) in parts.iter().enumerate() {
        if let Some(stripped) = part.strip_prefix("x:") {
            let hex_part = stripped;
            match hex::decode(hex_part) {
                Ok(key) => keys.push(key),
                Err(e) => {
                    return Err(
                        format!("decoding hex-encoded part #{}: /{}: {}", i, part, e).into(),
                    )
                }
            }
        } else {
            let k = path_unescape(part)?;
            keys.push(k.into_bytes());
        }
    }
    Ok(keys)
}

/// Decodes a percent-encoded string path segment into its original form.
///
/// Arguments:
/// * `path`: The percent-encoded path segment to decode.
///
/// Returns:
/// * A result containing the decoded string, or an error if the segment cannot be decoded as UTF-8.
fn path_unescape(path: &str) -> Result<String, std::str::Utf8Error> {
    let decoded = percent_decode_str(path).decode_utf8()?;
    Ok(decoded.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distributions::{Distribution, Uniform};
    use rand::rngs::OsRng;
    use rand::Rng;
    use serde::Deserialize;
    use serde::Serialize;

    // ignore clippy warning for test functions
    #[allow(clippy::needless_range_loop)]
    #[test]
    fn test_key_path() {
        let alphanum: Vec<u8> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            .bytes()
            .collect();
        let alphanum_range = Uniform::from(0..alphanum.len());
        let mut rng = rand::thread_rng();

        for _ in 0..1_000 {
            let mut path = KeyPath(Vec::new());
            let mut keys = Vec::with_capacity(10);

            for _ in 0..10 {
                let enc = if rng.gen() {
                    KeyEncoding::Url
                } else {
                    KeyEncoding::Hex
                };
                let key_len: usize = rng.gen_range(1..=20);
                let mut key = vec![0u8; key_len];

                match enc {
                    KeyEncoding::Url => {
                        for j in 0..key_len {
                            key[j] = alphanum[alphanum_range.sample(&mut rng)];
                        }
                    }
                    KeyEncoding::Hex => {
                        key = OsRng.gen::<[u8; 16]>().to_vec();
                        key.truncate(key_len);
                    }
                }

                path.append_key(key.clone(), enc);
                keys.push(key);
            }

            let path_string = path
                .to_string()
                .expect("Failed to convert KeyPath to string");
            let res = key_path_to_keys(&path_string).expect("Failed to decode KeyPath");

            assert_eq!(keys.len(), res.len(), "Mismatch in number of keys");

            for (i, key) in keys.iter().enumerate() {
                assert_eq!(key, &res[i], "Key mismatch at index {}", i);
            }
        }
    }

    // Define the DominoOp struct
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct DominoOp {
        key: String,
        input: String,
        output: String,
    }

    impl DominoOp {
        // Constructor function for DominoOp
        pub fn new(key: &str, input: &str, output: &str) -> Self {
            Self {
                key: key.to_string(),
                input: input.to_string(),
                output: output.to_string(),
            }
        }
    }

    // Implement the DominoOp functionality
    impl ProofOperator for DominoOp {
        // Runs the DominoOp, producing output from the given input
        fn run(&self, input: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
            if input.len() != 1 {
                // return Err(Box::<dyn Error>::from("expected input of length 1".to_string()));
                return Err("expected input of length 1".into());
            }
            let input_str = String::from_utf8(input[0].clone()).map_err(|e| e.to_string())?;
            if input_str != self.input {
                return Err(format!("expected input {}, got {}", self.input, input_str).into());
            }
            Ok(vec![self.output.clone().into_bytes()])
        }

        // Gets the key as bytes
        fn get_key(&self) -> Result<Vec<u8>, Box<dyn Error>> {
            Ok(self.key.clone().into_bytes())
        }
    }

    #[test]
    fn test_proof_operators() {
        // Assuming `ProofOperators` and related logic are defined somewhere
        let op1 = Box::new(DominoOp::new("KEY1", "INPUT1", "INPUT2"));
        let op2 = Box::new(DominoOp::new("KEY2", "INPUT2", "INPUT3"));
        let op3 = Box::new(DominoOp::new("", "INPUT3", "INPUT4"));
        let op4 = Box::new(DominoOp::new("KEY4", "INPUT4", "OUTPUT4"));

        // Example test case - adjust according to your ProofOperators implementation
        // This is a placeholder to show how a single test might look

        // Good
        let popz = ProofOperators(vec![op1, op2, op3, op4]);
        let result = popz.verify(bz("OUTPUT4"), "/KEY4/KEY2/KEY1", vec![bz("INPUT1")]);
        assert!(result.is_ok());
        let result = popz.verify_value(bz("OUTPUT4"), "/KEY4/KEY2/KEY1", bz("INPUT1"));
        assert!(result.is_ok());

        // Bad Input
        let result = popz.verify(bz("OUTPUT4"), "/KEY4/KEY2/KEY1", vec![bz("INPUT1_WRONG")]);
        assert!(result.is_err());
        let result = popz.verify_value(bz("OUTPUT4"), "/KEY4/KEY2/KEY1", bz("INPUT1_WRONG"));
        assert!(result.is_err());

        // BAD KEY 1
        let result = popz.verify(bz("OUTPUT4"), "/KEY3/KEY2/KEY1", vec![bz("INPUT1")]);
        assert!(result.is_err());

        // BAD KEY 2
        let result = popz.verify(bz("OUTPUT4"), "KEY4/KEY2/KEY1", vec![bz("INPUT1")]);
        assert!(result.is_err());

        // BAD KEY 3
        let result = popz.verify(bz("OUTPUT4"), "/KEY4/KEY2/KEY1/", vec![bz("INPUT1")]);
        assert!(result.is_err());

        // BAD KEY 4
        let result = popz.verify(bz("OUTPUT4"), "//KEY4/KEY2/KEY1", vec![bz("INPUT1")]);
        assert!(result.is_err());

        // BAD KEY 5
        let result = popz.verify(bz("OUTPUT4"), "/KEY2/KEY1", vec![bz("INPUT1")]);
        assert!(result.is_err());

        // BAD OUTPUT 1
        let result = popz.verify(bz("OUTPUT4_WRONG"), "/KEY4/KEY2/KEY1", vec![bz("INPUT1")]);
        assert!(result.is_err());

        // BAD OUTPUT 2
        let result = popz.verify(bz(""), "/KEY4/KEY2/KEY1", vec![bz("INPUT1")]);
        assert!(result.is_err());

        let op1 = Box::new(DominoOp::new("KEY1", "INPUT1", "INPUT2"));
        let op2 = Box::new(DominoOp::new("KEY2", "INPUT2", "INPUT3"));
        let op3 = Box::new(DominoOp::new("", "INPUT3", "INPUT4"));
        let op4 = Box::new(DominoOp::new("KEY4", "INPUT4", "OUTPUT4"));
        // BAD POPZ 1
        let popz = ProofOperators(vec![op1.clone(), op2.clone(), op4.clone()]);
        let result = popz.verify(bz("OUTPUT4"), "/KEY4/KEY2/KEY1", vec![bz("INPUT1")]);
        assert!(result.is_err());

        // BAD POPZ 2
        let popz = ProofOperators(vec![op4, op3, op2, op1]);
        let result = popz.verify(bz("OUTPUT4"), "/KEY4/KEY2/KEY1", vec![bz("INPUT1")]);
        assert!(result.is_err());

        // BAD POPZ 3
        let popz = ProofOperators(vec![]);
        let result = popz.verify(bz("OUTPUT4"), "/KEY4/KEY2/KEY1", vec![bz("INPUT1")]);
        assert!(result.is_err());
    }

    fn bz(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }
}
