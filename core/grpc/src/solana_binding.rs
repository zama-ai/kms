//! The canonical Solana user-decryption binding.
//!
//! One checked type owns both halves of the request-side contract: its constructor validates the
//! request's Solana-owned fields, and `compute_link` produces the per-request commitment that
//! signcryption embeds verbatim. The same type is used by KMS request validation and by the
//! client/WASM response path, so a link can only be computed from inputs that passed validation —
//! there is no unchecked helper to reach for.
//!
//! The link is the EVM construction over a Solana-shaped struct: the EIP-712 signing hash of
//! [`SolanaUserDecryptionLinker`] under the Gateway `Decryption` domain,
//! `keccak256(0x1901 ‖ domainSeparator(domain) ‖ hashStruct(linker))`, computed by the same alloy
//! helper the EVM path uses for its `UserDecryptionLinker`. Every variable-width input is hashed
//! to one 32-byte word before the struct hash, so no field boundary depends on validation, and the
//! type string is the version boundary: a layout change is a new type name, never a
//! reinterpretation of the same bytes.
//!
//! The link is opaque to signcryption: the engine neither parses nor re-hashes it, it embeds the
//! bytes in the signed, encrypted payload, and the receiver compares them byte-for-byte against an
//! independently recomputed link. The only hard requirement is therefore that every implementation
//! (KMS core, KMS client/WASM, SDK) produces byte-identical bytes.

use alloy_primitives::B256;
use alloy_sol_types::{Eip712Domain, SolStruct};

use crate::solidity_types::SolanaUserDecryptionLinker;

/// Width of every identity the binding accepts: handles, the recipient, and the program id.
pub const SOLANA_IDENTITY_LEN: usize = 32;

/// Bit 63 of the embedded chain id marks a Solana-kind host chain. It is the KMS-side backstop
/// that keeps Solana handles off the EVM linker and vice versa.
pub(crate) const SOLANA_CHAIN_TYPE_BIT: u64 = 1 << 63;

/// Byte range of the chain id embedded in a ciphertext handle.
const HANDLE_CHAIN_ID_START: usize = 22;
const HANDLE_CHAIN_ID_END: usize = 30;

/// A host chain id that is valid for the Solana request path: bit 63 is set.
///
/// The binding keeps it for the declared-value check only. The link binds the host chain through
/// the handle bytes this value was read from, not through the value itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SolanaHostChainId(u64);

impl SolanaHostChainId {
    fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for SolanaHostChainId {
    type Error = SolanaUserDecryptBindingError;

    fn try_from(chain_id: u64) -> Result<Self, Self::Error> {
        if chain_id & SOLANA_CHAIN_TYPE_BIT == 0 {
            return Err(SolanaUserDecryptBindingError::InvalidDeclaredChainId { chain_id });
        }
        Ok(Self(chain_id))
    }
}

/// A validated Solana user-decryption request, and the only place a link can come from.
///
/// Construction goes through [`SolanaUserDecryptBinding::new`], which is the request-side half of
/// the linker contract; the response-side half (recompute, compare, discard mismatching shares)
/// belongs to the client.
///
/// Fields are private, so a caller cannot assemble an unvalidated binding:
///
/// ```compile_fail,E0451
/// let binding = kms_grpc::solana_binding::SolanaUserDecryptBinding {
///     verifying_program_id: [0u8; 32],
///     // The chain id's type is itself private, so its name cannot even be written here.
///     chain_id: todo!(),
///     receiver_id: [0u8; 32],
///     handles: vec![[0u8; 32]],
///     transport_key: vec![],
/// };
/// ```
///
/// The supported way in, which also pins the argument order:
///
/// ```
/// use alloy_primitives::{Address, U256};
/// use alloy_sol_types::Eip712Domain;
/// use kms_grpc::solana_binding::SolanaUserDecryptBinding;
///
/// let mut handle = [0x11u8; 32];
/// handle[22..30].copy_from_slice(&((1u64 << 63) | 12_345).to_be_bytes());
///
/// let binding = SolanaUserDecryptBinding::new(
///     &[0x22u8; 32],                       // verifying_program_id
///     &[0x33u8; 32],                       // receiver_id (the raw ed25519 wallet key)
///     std::iter::once(handle.as_slice()),   // ordered ciphertext handles
///     &[0x66u8; 869],                      // transport key, as the request carries it
/// )
/// .expect("a canonical Solana request");
///
/// // The Gateway `Decryption` contract's EIP-712 domain, as the request carries it.
/// let domain = Eip712Domain::new(
///     Some("Decryption".into()),
///     Some("1".into()),
///     Some(U256::from(54_321u64)),
///     Some(Address::ZERO),
///     None,
/// );
///
/// assert_eq!(binding.compute_link(&domain).len(), 32);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolanaUserDecryptBinding {
    verifying_program_id: [u8; SOLANA_IDENTITY_LEN],
    chain_id: SolanaHostChainId,
    receiver_id: [u8; SOLANA_IDENTITY_LEN],
    handles: Vec<[u8; SOLANA_IDENTITY_LEN]>,
    transport_key: Vec<u8>,
}

impl SolanaUserDecryptBinding {
    /// Validates the Solana-owned fields of a user-decryption request.
    ///
    /// Checked here: the width of every identity, the chain-kind bit of each handle's embedded
    /// chain id, that all handles embed one common chain id, and that the handle list is not
    /// empty. Duplicate handles are legal — each occurrence is authorized independently upstream
    /// and the linker binds every occurrence at its position. These checks are the part of the
    /// host-chain binding the hash cannot provide — `keccak256` over the handle words accepts any
    /// bytes — which is why this constructor is the only way to a link.
    ///
    /// Deliberately not checked: the request bit budget, which is enforced on chain before the
    /// request reaches any KMS party, and the 869-byte transport-key rule, which belongs to the
    /// wallet permit and the connector. 869 is the width of the safe-serialized
    /// `UnifiedPublicEncKey::MlKem512` container — the 800-byte encapsulation key plus its framing
    /// — which is the one representation the key has anywhere in the system; the linker binds
    /// those bytes verbatim rather than reframing them. `transport_key` is taken as the request
    /// carries it, the same way the EVM linker takes its `publicKey`.
    ///
    /// Not an input: the request's `extra_data`. It is authenticated by the external response
    /// signature alone, as on EVM, so a change to it fails that signature and leaves the link
    /// unchanged; an internal node signature by itself does not authenticate it.
    pub fn new<'a>(
        verifying_program_id: &[u8],
        receiver_id: &[u8],
        handles: impl IntoIterator<Item = &'a [u8]>,
        transport_key: &[u8],
    ) -> Result<Self, SolanaUserDecryptBindingError> {
        let verifying_program_id = identity(verifying_program_id).ok_or(
            SolanaUserDecryptBindingError::InvalidProgramIdLength {
                actual: verifying_program_id.len(),
            },
        )?;
        let receiver_id =
            identity(receiver_id).ok_or(SolanaUserDecryptBindingError::InvalidReceiverLength {
                actual: receiver_id.len(),
            })?;

        let mut canonical_handles = Vec::new();
        let mut common_chain_id = None;

        for (index, handle) in handles.into_iter().enumerate() {
            let canonical =
                identity(handle).ok_or(SolanaUserDecryptBindingError::InvalidHandleLength {
                    index,
                    actual: handle.len(),
                })?;
            // Per handle rather than once for the batch: a foreign handle mixed into an otherwise
            // valid batch must be caught at its own index, not hidden behind the first one.
            let chain_id = handle_chain_id(&canonical);
            if chain_id & SOLANA_CHAIN_TYPE_BIT == 0 {
                return Err(SolanaUserDecryptBindingError::InvalidHandleChainId {
                    index,
                    chain_id,
                });
            }
            match common_chain_id {
                Some(expected) if chain_id != expected => {
                    return Err(SolanaUserDecryptBindingError::MixedChainIds {
                        index,
                        expected,
                        actual: chain_id,
                    });
                }
                Some(_) => {}
                None => common_chain_id = Some(chain_id),
            }
            canonical_handles.push(canonical);
        }

        // The chain-kind bit was checked for every handle above, which is why this wraps the value
        // directly: the fallible conversion exists for a chain id a caller declares separately.
        let chain_id = common_chain_id
            .map(SolanaHostChainId)
            .ok_or(SolanaUserDecryptBindingError::EmptyHandles)?;

        Ok(Self {
            verifying_program_id,
            chain_id,
            receiver_id,
            handles: canonical_handles,
            transport_key: transport_key.to_vec(),
        })
    }

    /// The per-request commitment: the EIP-712 signing hash of [`SolanaUserDecryptionLinker`]
    /// under `domain`, delivered to signcryption as 32 opaque bytes.
    ///
    /// `domain` is the Gateway `Decryption` contract's EIP-712 domain — the one the request
    /// carries and the client configures — not a domain built from the Solana host chain id. It is
    /// a required input: the type has no default, so a caller without a domain has no link.
    ///
    /// What the struct binds, field by field: the transport key verbatim (`publicKey`), the handles
    /// in request order (`handles`), the 32-byte recipient (`userPubkey`) and the host program
    /// (`verifyingProgramId`). The host chain enters through bytes `[22..30]` of every handle; the
    /// chain id this binding extracted from them is not hashed a second time, it only serves
    /// [`Self::validate_declared_chain_id`].
    pub fn compute_link(&self, domain: &Eip712Domain) -> Vec<u8> {
        let linker = SolanaUserDecryptionLinker {
            publicKey: self.transport_key.clone().into(),
            handles: self.handles.iter().copied().map(B256::from).collect(),
            userPubkey: B256::from(self.receiver_id),
            verifyingProgramId: B256::from(self.verifying_program_id),
        };
        linker.eip712_signing_hash(domain).to_vec()
    }

    /// Checks a separately declared chain id against the one embedded in the handles.
    ///
    /// Used by callers that hold a declared value of their own — the client recomputing a link
    /// from its signed permit fields. A KMS party has no declared value in the request and relies
    /// on the constructor's chain-kind and common-id checks instead.
    pub fn validate_declared_chain_id(
        &self,
        declared: u64,
    ) -> Result<(), SolanaUserDecryptBindingError> {
        let declared = SolanaHostChainId::try_from(declared)?;
        if declared != self.chain_id {
            return Err(SolanaUserDecryptBindingError::DeclaredChainIdMismatch {
                declared: declared.get(),
                embedded: self.chain_id.get(),
            });
        }
        Ok(())
    }

    /// The recipient the result is signcrypted to: the raw 32-byte ed25519 wallet key.
    pub fn receiver_id(&self) -> &[u8; SOLANA_IDENTITY_LEN] {
        &self.receiver_id
    }
}

/// Why a Solana user-decryption request is not a valid binding.
///
/// One variant per rejected property, each carrying what was seen, so a failure identifies itself
/// from the log line alone.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SolanaUserDecryptBindingError {
    #[error("Solana user-decrypt request contains no ciphertext handles")]
    EmptyHandles,
    #[error("Solana ciphertext handle at index {index} must be 32 bytes, got {actual}")]
    InvalidHandleLength { index: usize, actual: usize },
    #[error(
        "Solana ciphertext handle at index {index} embeds chain ID {chain_id}, which does not set bit 63"
    )]
    InvalidHandleChainId { index: usize, chain_id: u64 },
    #[error(
        "Solana ciphertext handle at index {index} embeds chain ID {actual}, expected {expected}"
    )]
    MixedChainIds {
        index: usize,
        expected: u64,
        actual: u64,
    },
    #[error("declared Solana host chain ID {chain_id} does not set bit 63")]
    InvalidDeclaredChainId { chain_id: u64 },
    #[error("declared Solana host chain ID {declared} does not match handle chain ID {embedded}")]
    DeclaredChainIdMismatch { declared: u64, embedded: u64 },
    #[error("Solana verifying program ID must be 32 bytes, got {actual}")]
    InvalidProgramIdLength { actual: usize },
    #[error("Solana recipient must be a 32-byte ed25519 public key, got {actual}")]
    InvalidReceiverLength { actual: usize },
}

/// An identity of the one width this binding accepts, or `None` for anything else.
fn identity(bytes: &[u8]) -> Option<[u8; SOLANA_IDENTITY_LEN]> {
    bytes.try_into().ok()
}

/// Reads the chain id a ciphertext handle embeds in bytes `[22..30]`, big-endian.
pub(crate) fn handle_chain_id(handle: &[u8; SOLANA_IDENTITY_LEN]) -> u64 {
    let mut chain_id = [0u8; size_of::<u64>()];
    chain_id.copy_from_slice(&handle[HANDLE_CHAIN_ID_START..HANDLE_CHAIN_ID_END]);
    u64::from_be_bytes(chain_id)
}
