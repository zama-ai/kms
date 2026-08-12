//! The canonical Solana user-decryption binding (linker v1).
//!
//! One checked type owns both halves of the request-side contract: its constructor validates the
//! request's Solana-owned fields, and `compute_link` produces the per-request commitment that
//! signcryption embeds verbatim. The same type is used by KMS request validation and by the
//! client/WASM response path, so a link can only be computed from inputs that passed validation —
//! there is no unchecked helper to reach for.
//!
//! The link is opaque to signcryption: the engine neither parses nor re-hashes it, it embeds the
//! bytes in the signed, encrypted payload, and the receiver compares them byte-for-byte against an
//! independently recomputed link. The only hard requirement is therefore that every implementation
//! (KMS core, KMS client/WASM, SDK) produces byte-identical bytes.

use hashing::{DSEP_LIST, DomainSep, unsafe_hash_list_w_size};

/// Scheme and version tag, first element of the hashed list. Exactly 29 bytes.
///
/// A change to any normative rule of the construction bumps the version in this tag rather than
/// silently reinterpreting the same bytes. Frozen: see [`DSEP_SOLANA_LINKER`].
pub const SOLANA_LINKER_SCHEME_TAG: &[u8; 29] = b"SolanaUserDecryptionLinker:v1";

/// Call separator for the linker's list hash.
///
/// The linker is a KMS-domain object that is never validated on chain, so the hash is SHAKE-256
/// with an 8-byte call separator, per the KMS hashing policy. It MUST stay unique among the
/// codebase's [`DomainSep`] constants; `core/grpc/tests/domain_separator_inventory.rs` enforces
/// that.
///
/// **Frozen**, together with [`SOLANA_LINKER_SCHEME_TAG`], the element layout, and the normative
/// vectors in `core/grpc/test-vectors/solana_linker_v1.json`. Other implementations now reproduce
/// these bytes, so changing this value — or anything else the vectors pin — is a deliberate version
/// bump in the scheme tag, not an edit. `core/grpc/tests/solana_frozen_constants.rs` is the gate.
pub const DSEP_SOLANA_LINKER: DomainSep = *b"SOLLNK01";

/// Width of every identity the binding accepts: handles, the recipient, the program id, and the
/// KMS context and epoch ids.
pub const SOLANA_IDENTITY_LEN: usize = 32;

/// Width of the link, in bytes.
///
/// Stated here rather than taken from the hashing crate's digest width: the link's width is a rule
/// of this construction, and it must not follow an unrelated constant if that one ever moves.
const SOLANA_LINK_LEN: usize = 32;

/// Width of the big-endian chain id element.
const CHAIN_ID_LEN: usize = size_of::<u64>();

/// Hashed elements that are not a ciphertext handle: the scheme tag, the deployment pair, the
/// recipient, the KMS context and epoch, and the transport key. The element count is this plus the
/// handle count, which is what lets a reader recover the handle count from the count alone.
const FIXED_ELEMENTS: usize = 7;

/// Bit 63 of the embedded chain id marks a Solana-kind host chain. It is the KMS-side backstop
/// that keeps Solana handles off the EVM linker and vice versa.
pub(crate) const SOLANA_CHAIN_TYPE_BIT: u64 = 1 << 63;

/// Byte range of the chain id embedded in a ciphertext handle.
const HANDLE_CHAIN_ID_START: usize = 22;
const HANDLE_CHAIN_ID_END: usize = 30;

/// A host chain id that is valid for the Solana request path.
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

/// A validated Solana user-decryption request, and the only place a linker v1 can come from.
///
/// Construction goes through [`SolanaUserDecryptBinding::new`], which is the request-side half of
/// the linker contract; the response-side half (recompute, compare, discard mismatching shares)
/// belongs to the client.
///
/// Fields are private, so a caller cannot assemble an unvalidated binding:
///
/// ```compile_fail,E0451
/// // Paired with the positive example below: if this snippet ever compiles, the validating
/// // constructor stopped being the only way in. Every field is initialized, so the one thing
/// // that can stop it from compiling is field privacy — the error code on the fence.
/// let binding = kms_grpc::solana_binding::SolanaUserDecryptBinding {
///     verifying_program_id: [0u8; 32],
///     // The chain id's type is itself private, so its name cannot even be written here.
///     chain_id: todo!(),
///     receiver_id: [0u8; 32],
///     kms_context_id: [0u8; 32],
///     kms_epoch_id: [0u8; 32],
///     handles: vec![[0u8; 32]],
///     transport_key: vec![],
/// };
/// ```
///
/// The supported way in, which also pins the argument order:
///
/// ```
/// use kms_grpc::solana_binding::SolanaUserDecryptBinding;
///
/// let mut handle = [0x11u8; 32];
/// handle[22..30].copy_from_slice(&((1u64 << 63) | 12_345).to_be_bytes());
///
/// let binding = SolanaUserDecryptBinding::new(
///     &[0x22u8; 32],                       // verifying_program_id
///     &[0x33u8; 32],                       // receiver_id (the raw ed25519 wallet key)
///     &[0x44u8; 32],                       // kms_context_id
///     &[0x55u8; 32],                       // kms_epoch_id
///     std::iter::once(handle.as_slice()),   // ordered ciphertext handles
///     &[0x66u8; 869],                      // transport key, as the request carries it
/// )
/// .expect("a canonical Solana request");
///
/// assert_eq!(binding.compute_link().len(), 32);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolanaUserDecryptBinding {
    verifying_program_id: [u8; SOLANA_IDENTITY_LEN],
    chain_id: SolanaHostChainId,
    receiver_id: [u8; SOLANA_IDENTITY_LEN],
    kms_context_id: [u8; SOLANA_IDENTITY_LEN],
    kms_epoch_id: [u8; SOLANA_IDENTITY_LEN],
    handles: Vec<[u8; SOLANA_IDENTITY_LEN]>,
    transport_key: Vec<u8>,
}

impl SolanaUserDecryptBinding {
    /// Validates the Solana-owned fields of a user-decryption request.
    ///
    /// Checked here: the width of every identity, the chain-kind bit of each handle's embedded
    /// chain id, that all handles embed one common chain id, and that the handle list is not
    /// empty. Duplicate handles are legal — each occurrence is authorized independently upstream
    /// and the linker binds every occurrence at its position.
    ///
    /// Deliberately not checked: the request bit budget, which is enforced on chain before the
    /// request reaches any KMS party, and the 869-byte transport-key rule, which belongs to the
    /// wallet permit and the connector. 869 is the width of the serialized
    /// `UnifiedPublicEncKey::MlKem512` container — the 800-byte encapsulation key plus its framing
    /// — which is the one representation the key has anywhere in the system; the linker binds
    /// those bytes verbatim rather than reframing them. `transport_key` is taken as the request
    /// carries it, the same way the EVM linker takes its `publicKey`.
    pub fn new<'a>(
        verifying_program_id: &[u8],
        receiver_id: &[u8],
        kms_context_id: &[u8],
        kms_epoch_id: &[u8],
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
        let kms_context_id = identity(kms_context_id).ok_or(
            SolanaUserDecryptBindingError::InvalidContextIdLength {
                actual: kms_context_id.len(),
            },
        )?;
        let kms_epoch_id =
            identity(kms_epoch_id).ok_or(SolanaUserDecryptBindingError::InvalidEpochIdLength {
                actual: kms_epoch_id.len(),
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
            kms_context_id,
            kms_epoch_id,
            handles: canonical_handles,
            transport_key: transport_key.to_vec(),
        })
    }

    /// The per-request commitment: 32 bytes, delivered to signcryption as opaque bytes.
    pub fn compute_link(&self) -> Vec<u8> {
        let chain_id = self.chain_id.get().to_be_bytes();

        unsafe_hash_list_w_size(
            &DSEP_SOLANA_LINKER,
            &self.hashed_elements(&chain_id),
            SOLANA_LINK_LEN,
        )
    }

    /// The exact byte sequence fed to the hasher, in order.
    ///
    /// Public because it is a specified artifact, not a debugging aid: it is the vector field that
    /// lets five implementations compare their construction before comparing digests, which is
    /// where a single-byte disagreement is actually diagnosable.
    pub fn linker_hasher_input(&self) -> Vec<u8> {
        let chain_id = self.chain_id.get().to_be_bytes();
        let elements = self.hashed_elements(&chain_id);

        let mut input = Vec::with_capacity(
            DSEP_LIST.len()
                + DSEP_SOLANA_LINKER.len()
                + size_of::<u64>() // the element count
                + elements.iter().map(|element| element.len()).sum::<usize>(),
        );
        input.extend_from_slice(&DSEP_LIST);
        input.extend_from_slice(&DSEP_SOLANA_LINKER);
        input.extend_from_slice(&(elements.len() as u64).to_le_bytes());
        for element in elements {
            input.extend_from_slice(element);
        }
        input
    }

    /// The hashed elements, in order.
    ///
    /// The transport key is last and is the only element of variable length, which is the
    /// precondition the shared list hash needs to stay injective: every element before it has a
    /// position-determined width, so the element count recovers the handle count exactly.
    ///
    /// `chain_id` is passed in rather than produced here because the elements borrow from `self`
    /// and the big-endian chain id has to outlive the returned slice list.
    fn hashed_elements<'a>(&'a self, chain_id: &'a [u8; CHAIN_ID_LEN]) -> Vec<&'a [u8]> {
        let mut elements: Vec<&[u8]> = Vec::with_capacity(FIXED_ELEMENTS + self.handles.len());
        elements.push(SOLANA_LINKER_SCHEME_TAG.as_slice());
        elements.push(self.verifying_program_id.as_slice());
        elements.push(chain_id.as_slice());
        elements.push(self.receiver_id.as_slice());
        elements.push(self.kms_context_id.as_slice());
        elements.push(self.kms_epoch_id.as_slice());
        elements.extend(self.handles.iter().map(|handle| handle.as_slice()));
        elements.push(self.transport_key.as_slice());
        elements
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

    /// The common chain id embedded in every handle of the request.
    pub fn chain_id(&self) -> u64 {
        self.chain_id.get()
    }

    /// The recipient the result is signcrypted to: the raw 32-byte ed25519 wallet key.
    pub fn receiver_id(&self) -> &[u8; SOLANA_IDENTITY_LEN] {
        &self.receiver_id
    }

    /// The ciphertext handles, in request order, duplicates preserved.
    pub fn handles(&self) -> &[[u8; SOLANA_IDENTITY_LEN]] {
        &self.handles
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
    #[error("KMS context ID must be 32 bytes, got {actual}")]
    InvalidContextIdLength { actual: usize },
    #[error("KMS epoch ID must be 32 bytes, got {actual}")]
    InvalidEpochIdLength { actual: usize },
}

/// An identity of the one width this binding accepts, or `None` for anything else.
fn identity(bytes: &[u8]) -> Option<[u8; SOLANA_IDENTITY_LEN]> {
    bytes.try_into().ok()
}

/// Reads the chain id a ciphertext handle embeds in bytes `[22..30]`.
pub(crate) fn handle_chain_id(handle: &[u8; SOLANA_IDENTITY_LEN]) -> u64 {
    u64::from_be_bytes(
        handle[HANDLE_CHAIN_ID_START..HANDLE_CHAIN_ID_END]
            .try_into()
            .expect("the chain ID range is eight bytes"),
    )
}
