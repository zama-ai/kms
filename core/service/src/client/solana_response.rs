//! Solana user-decryption **response** verification, and the release that may follow it.
//!
//! The request-side half of the linker contract lives in [`SolanaUserDecryptBinding`]: a request
//! that validates produces one 32-byte link. This module owns the response-side half, as four
//! rules in fixed order:
//!
//! * **Recompute, don't parse.** The expected link is recomputed from the client's own typed
//!   request fields through the canonical binding. The `digest` embedded in a response payload is
//!   never a source of the expectation, only the thing compared against it.
//! * **Authenticate before comparing.** Each share's KMS node signature is verified against the
//!   caller-supplied trusted key set before its link is looked at, exactly as on the EVM path: a
//!   non-empty internal `signature` is ECDSA over the serialized payload, an empty one falls back
//!   to the EIP-712 `external_signature`, verified in full under the request's response domain,
//!   transport key and `extra_data`. A key found inside a response acts only under its binding to
//!   a registered signer address, never on its own authority.
//! * **Byte equality.** The embedded digest must equal the recomputed link byte for byte, length
//!   included. A share that fails is discarded and contributes nothing.
//! * **Uniformity and threshold.** Every accepted share must carry the same link, a party
//!   contributes at most one accepted share, and there must be at least as many of them as the
//!   release needs — fewer fails the response as a whole. A multi-share set must additionally be
//!   one consistent threshold response, checked by the EVM path's own validation, unchanged.
//!
//! The centralized case is the degenerate single-share case of the same rules.
//!
//! Verification and release are separate on purpose: [`verify_solana_user_decryption_response`]
//! returns a [`VerifiedSolanaShares`] and [`release_solana_user_decryption`] consumes it, so
//! there is no path to a plaintext that skips verification, and no public entry point in this
//! module accepts a link as an argument. `VerifiedSolanaShares` has private fields and no
//! constructor:
//!
//! ```compile_fail
//! let shares = kms_lib::client::solana_response::VerifiedSolanaShares {
//!     link: vec![0u8; 32],
//! };
//! ```
//!
//! The supported way in — the client's own fields, and the link recomputed from them:
//!
//! ```
//! use kms_lib::client::solana_response::SolanaUserDecryptionRequest;
//!
//! let mut handle = [0xabu8; 32];
//! handle[22..30].copy_from_slice(&((1u64 << 63) | 12_345).to_be_bytes());
//!
//! let request = SolanaUserDecryptionRequest {
//!     user_pubkey: [0x11; 32],
//!     host_chain_id: (1 << 63) | 12_345,
//!     verifying_program_id: [0x22; 32],
//!     handles: vec![handle.to_vec()],
//!     enc_key: vec![0x66; 869],
//!     // A link input like the fields above it, and also part of what an external node
//!     // signature is verified against.
//!     extra_data: Vec::new(),
//!     // Not an input to the link: only what an external node signature is verified against. A
//!     // caller that only wants the link can leave it empty.
//!     response_domain: Default::default(),
//! };
//!
//! assert_eq!(request.expected_link().expect("a canonical request").len(), 32);
//! ```

use std::collections::{BTreeSet, HashMap};

use alloy_dyn_abi::Eip712Domain;
use kms_grpc::kms::v1::{TypedPlaintext, UserDecryptionResponse, UserDecryptionResponsePayload};
use kms_grpc::rpc_types::SigncryptionReceiver;
use kms_grpc::solana_binding::{
    SOLANA_IDENTITY_LEN, SolanaUserDecryptBinding, SolanaUserDecryptBindingError,
};

use crate::client::client_wasm::Client;
use crate::client::user_decryption_wasm::{CiphertextHandle, ParsedUserDecryptionRequest};
use crate::cryptography::encryption::{UnifiedPrivateEncKey, UnifiedPublicEncKey};
use crate::cryptography::signatures::PublicSigKey;
use crate::cryptography::signcryption::{UnifiedUnsigncryptionKey, UnsigncryptFHEPlaintext};
use crate::engine::validation::{
    DSEP_USER_DECRYPTION, ShareAuthenticationError, UserDecTrustedValidationContext,
    authenticate_user_decrypt_share, validate_user_decrypt_responses,
};

/// A Solana user-decryption request, in the client's own typed terms.
///
/// This is the trusted side of the response check: every field here is state the client already
/// holds — what it asked for, who it asked as, and which deployment it asked of. Nothing in this
/// struct is ever taken from a response.
///
/// Two groups of fields, and the split matters. Everything except [`Self::response_domain`] is an
/// input the link commits to, and [`Self::expected_link`] is built from exactly those.
/// [`Self::response_domain`] commits to nothing: it is the request-side input to the EIP-712
/// message a KMS node's `external_signature` is made over, and it exists here so a node's
/// external signature can be verified instead of merely noticed. [`Self::extra_data`] does double
/// duty — a link input, and an input to that same EIP-712 message.
///
/// The fields are public because they carry no invariant of their own: validation happens where it
/// is defined, in the canonical binding's constructor, which [`Self::binding`] calls. A request
/// with, say, a handle of the wrong width is representable here and is rejected there.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolanaUserDecryptionRequest {
    /// The recipient: the raw 32-byte ed25519 wallet key, never hashed and never truncated.
    pub user_pubkey: [u8; SOLANA_IDENTITY_LEN],
    /// The host chain id the client's permit was signed for. Checked against the id embedded in
    /// every handle — a client, unlike a KMS party, has a declared value of its own.
    pub host_chain_id: u64,
    /// The on-chain verifying program; half of the deployment pair the response is bound to.
    pub verifying_program_id: [u8; SOLANA_IDENTITY_LEN],
    /// The ciphertext handles, in request order, duplicates preserved.
    pub handles: Vec<Vec<u8>>,
    /// The serialized transport (ephemeral ML-KEM) public key, exactly as the request carried it.
    /// The linker binds these bytes verbatim rather than reframing them.
    pub enc_key: Vec<u8>,
    /// The request's `extra_data`, verbatim.
    ///
    /// Opaque bytes, bound verbatim by the linker and never parsed — the host-side metadata
    /// travels inside it, so the contract can evolve what it carries without a KMS release. It is
    /// also one of the fields the EIP-712 message behind an `external_signature` is built from,
    /// so a response carrying different `extra_data` is not a response to this request.
    pub extra_data: Vec<u8>,
    /// The EIP-712 domain a KMS node produces the response's `external_signature` under.
    ///
    /// The gateway's own domain, as the client's configuration holds it. The Solana path invents no
    /// domain of its own — the server-side adapter carries the request's domain through unchanged —
    /// so the client must be told the same one to verify an external signature against.
    /// Not an input to the link.
    pub response_domain: Eip712Domain,
}

impl SolanaUserDecryptionRequest {
    /// The canonical binding for this request, or why the request is not one.
    ///
    /// Two checks, in this order: the binding's own constructor validates the Solana-owned fields
    /// (identity widths, the chain-kind bit of every handle, one common embedded chain id, a
    /// non-empty handle list), and then the declared [`Self::host_chain_id`] is checked against the
    /// id the handles embed.
    pub fn binding(&self) -> Result<SolanaUserDecryptBinding, SolanaUserDecryptBindingError> {
        let binding = SolanaUserDecryptBinding::new(
            &self.verifying_program_id,
            &self.user_pubkey,
            self.handles.iter().map(|handle| handle.as_slice()),
            &self.enc_key,
            &self.extra_data,
        )?;
        binding.validate_declared_chain_id(self.host_chain_id)?;
        Ok(binding)
    }

    /// The link this request expects a response to carry.
    ///
    /// Recomputed from the fields above through the one canonical construction. This is the only
    /// value the response's `digest` is ever compared against.
    pub fn expected_link(&self) -> Result<Vec<u8>, SolanaUserDecryptBindingError> {
        Ok(self.binding()?.compute_link())
    }
}

/// Why each rejected share was rejected, as counters — the census a failed response reports in
/// [`SolanaUserDecryptionResponseError::BelowThreshold`].
///
/// Each share is counted under the *first* rule it failed, in rule order; shares dropped later by
/// the whole-set consistency gate are not counted here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ShareRejections {
    /// The response carried no payload at all.
    pub missing_payload: usize,
    /// No trusted verification key is configured for the party id the payload claims.
    pub unknown_party: usize,
    /// The payload's verification key could not be parsed, or its address is not the registered
    /// signer address for the claimed party id.
    pub malformed_verification_key: usize,
    /// The share carries no KMS node signature at all, or the one it carries — internal
    /// ECDSA, or the EIP-712 external signature an empty internal one falls back to — does not
    /// verify under the trusted key.
    pub node_signature: usize,
    /// The payload's digest is not, byte for byte, the recomputed link.
    pub link_mismatch: usize,
    /// The share verified, but a share from the same party was already accepted. Only the
    /// first accepted share of a party counts; every later one lands here.
    pub duplicate_party: usize,
}

/// One share that passed the per-share rules: authenticated by a trusted KMS node, carrying the recomputed
/// link.
///
/// Fields are private and there is no constructor: an accepted share can only come out of
/// [`verify_solana_user_decryption_response`].
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedSolanaShare {
    party_id: u32,
    verification_key: PublicSigKey,
    payload: UserDecryptionResponsePayload,
}

/// The outcome of verification: the accepted shares and the single link every one of them carries.
///
/// Fields are private. In particular `link` has no setter and no constructor argument anywhere in
/// this module's public surface — it is always the value recomputed from the request, which is
/// what makes "the expectation came from the response" unrepresentable rather than merely
/// discouraged.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedSolanaShares {
    link: Vec<u8>,
    receiver_id: [u8; SOLANA_IDENTITY_LEN],
    shares: Vec<VerifiedSolanaShare>,
}

/// Why a Solana user-decryption response did not yield a plaintext.
///
/// One variant per failure the rules distinguish, each naming the party it can be attributed to.
/// The taxonomy is deliberately enumerated rather than catch-all: a caller matching on it should
/// stop compiling when a new failure mode is added, instead of silently folding it into a default
/// arm.
///
/// A response carrying exactly one share — the centralized shape — reports the rule that share
/// failed directly ([`Self::NodeSignature`], [`Self::LinkMismatch`], …). With more than one share
/// the individual reasons are counted in [`ShareRejections`] and the aggregate outcome is
/// [`Self::BelowThreshold`]: with many shares, no single share's failure is the reason the response
/// failed.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SolanaUserDecryptionResponseError {
    /// No responses at all. Spelled the way the WASM boundary has always spelled it, because JS
    /// callers pin this message.
    #[error("Response does not exist")]
    EmptyResponse,

    /// The request itself is not a valid binding, so there is no expectation to compare
    /// against. Checked before any response is examined.
    #[error(transparent)]
    Binding(#[from] SolanaUserDecryptBindingError),

    /// The response carried no payload.
    #[error("the user decryption response from party {party_id} carries no payload")]
    MissingPayload { party_id: u32 },

    /// No trusted verification key is configured for the claimed party id.
    #[error("no trusted KMS verification key is configured for party {party_id}")]
    UnknownParty { party_id: u32 },

    /// The payload's verification key is unparseable, or its address is not the registered signer
    /// address for the party id it claims to be.
    #[error("the response from party {party_id} does not carry that party's trusted key")]
    MalformedVerificationKey { party_id: u32 },

    /// The KMS node signature on the payload — internal ECDSA, or the external EIP-712 one
    /// an empty internal signature falls back to — is absent or does not verify. A response whose
    /// `extra_data` is not the request's lands here too: the message an external signature commits
    /// to is then not this request's, which is the same failure said differently.
    #[error("the KMS node signature on the response from party {party_id} is not valid")]
    NodeSignature { party_id: u32 },

    /// The payload's digest is not the recomputed link.
    #[error(
        "the response from party {party_id} carries a digest that is not the link recomputed from the request"
    )]
    LinkMismatch { party_id: u32 },

    /// A share verified, but a share from the same party had already been accepted. The
    /// threshold counts distinct parties, so a party's later shares are discarded, not re-counted.
    #[error("the response carries more than one share from party {party_id}")]
    DuplicateParty { party_id: u32 },

    /// Too few shares carry one common link for the release to be attempted. All or
    /// nothing — a partially valid response releases no plaintext.
    #[error(
        "only {valid} of the {needed} required user decryption shares carry the recomputed link ({rejections:?})"
    )]
    BelowThreshold {
        valid: usize,
        needed: usize,
        rejections: ShareRejections,
    },

    /// The accepted shares do not form one consistent threshold response. Each share individually
    /// authenticated and carried the recomputed link, but as a set they disagree on the metadata
    /// reconstruction relies on — degree against the configured threshold, ciphertext count, FHE
    /// types, packing, handles — or reuse one signer identity under two party ids. The check is the
    /// EVM path's own validation, run here unchanged, so what a threshold response must look like
    /// is defined exactly once.
    #[error("the accepted shares are not one consistent threshold response: {reason}")]
    InconsistentShares { reason: String },

    /// A verified share could not be unsigncrypted under the recomputed link and the client's
    /// ephemeral key pair.
    #[error("could not unsigncrypt the response from party {party_id}: {reason}")]
    Unsigncryption { party_id: u32, reason: String },

    /// The threshold release failed: the verified shares could not be reconstructed into a
    /// plaintext — unsigncryption failures beyond the tolerated count, shares that do not
    /// interpolate, or inconsistent share metadata.
    #[error("could not reconstruct a plaintext from the verified shares: {reason}")]
    Reconstruction { reason: String },
}

/// How many same-link shares a release needs, for a deployment of `server_count` KMS nodes: one
/// for the centralized deployment, and `t + 1` for a threshold deployment of `n = 3t + 1` nodes —
/// the same derivation the EVM path uses when no threshold is supplied.
fn solana_required_shares(server_count: usize) -> usize {
    if server_count <= 1 {
        1
    } else {
        (server_count - 1) / 3 + 1
    }
}

/// The first rule a share failed, in the order the rules run.
///
/// Private on purpose: a rejected share is folded into the [`ShareRejections`] counters, and only
/// a single-share response surfaces it as the public error naming the rule. Both conversions live
/// here, next to the enum, so the counter a rejection bumps and the error it becomes cannot drift
/// apart.
enum ShareRejection {
    MissingPayload { party_id: u32 },
    UnknownParty { party_id: u32 },
    MalformedVerificationKey { party_id: u32 },
    NodeSignature { party_id: u32 },
    LinkMismatch { party_id: u32 },
    DuplicateParty { party_id: u32 },
}

impl ShareRejection {
    /// Bumps the counter of the one rule this rejection stands for.
    fn count(&self, rejections: &mut ShareRejections) {
        match self {
            Self::MissingPayload { .. } => rejections.missing_payload += 1,
            Self::UnknownParty { .. } => rejections.unknown_party += 1,
            Self::MalformedVerificationKey { .. } => rejections.malformed_verification_key += 1,
            Self::NodeSignature { .. } => rejections.node_signature += 1,
            Self::LinkMismatch { .. } => rejections.link_mismatch += 1,
            Self::DuplicateParty { .. } => rejections.duplicate_party += 1,
        }
    }
}

impl From<ShareRejection> for SolanaUserDecryptionResponseError {
    fn from(rejection: ShareRejection) -> Self {
        match rejection {
            ShareRejection::MissingPayload { party_id } => Self::MissingPayload { party_id },
            ShareRejection::UnknownParty { party_id } => Self::UnknownParty { party_id },
            ShareRejection::MalformedVerificationKey { party_id } => {
                Self::MalformedVerificationKey { party_id }
            }
            ShareRejection::NodeSignature { party_id } => Self::NodeSignature { party_id },
            ShareRejection::LinkMismatch { party_id } => Self::LinkMismatch { party_id },
            ShareRejection::DuplicateParty { party_id } => Self::DuplicateParty { party_id },
        }
    }
}

/// Runs one share through the per-share rules, in order, and stops at the first failure.
///
/// The order is the contract: payload present, party known, advertised key's address is the
/// registered one, node signature verifies, digest equals the recomputed link. A share
/// failing an earlier rule never reaches a later one, which is what makes the rejection counters
/// a record of the order and not just of the outcome.
fn verify_share(
    request: &SolanaUserDecryptionRequest,
    expected_link: &[u8],
    trusted_signers: &HashMap<u32, alloy_primitives::Address>,
    response: &UserDecryptionResponse,
) -> Result<VerifiedSolanaShare, ShareRejection> {
    let Some(payload) = response.payload.as_ref() else {
        // With no payload there is no claimed party id; zero is "no party", since real ids
        // start at one.
        return Err(ShareRejection::MissingPayload { party_id: 0 });
    };
    let party_id = payload.party_id;

    let Some(trusted_addr) = trusted_signers.get(&party_id) else {
        return Err(ShareRejection::UnknownParty { party_id });
    };

    // One copy of the authentication rule for every user-decryption flavor: the key is admitted
    // by its address binding to the caller's signer set, then whichever signature the share
    // carries is the one verified — see `authenticate_user_decrypt_share`. Both address failures
    // fold into the malformed-key rejection, everything after the key into the node-signature
    // rejection: the counters record which of this module's rules failed, not the shared rule's
    // internals.
    let advertised = authenticate_user_decrypt_share(
        payload,
        trusted_addr,
        &response.signatures,
        &response.signature,
        &response.external_signature,
        &response.extra_data,
        &request.enc_key,
        &request.extra_data,
        &request.response_domain,
    )
    .map_err(|reason| match reason {
        ShareAuthenticationError::MalformedVerificationKey
        | ShareAuthenticationError::WrongAddress => {
            ShareRejection::MalformedVerificationKey { party_id }
        }
        ShareAuthenticationError::MissingSignature
        | ShareAuthenticationError::InvalidInternalSignature
        | ShareAuthenticationError::InvalidExternalSignature
        | ShareAuthenticationError::UnsupportedTypedSignatureScheme
        | ShareAuthenticationError::InvalidTypedSignature => {
            ShareRejection::NodeSignature { party_id }
        }
    })?;

    // Byte equality, length included. An unauthenticated share never gets here.
    if payload.digest != expected_link {
        return Err(ShareRejection::LinkMismatch { party_id });
    }

    Ok(VerifiedSolanaShare {
        party_id,
        verification_key: advertised,
        payload: payload.clone(),
    })
}

/// Verifies an aggregated Solana user-decryption response against the request that produced it —
/// recompute, authenticate, compare, count.
///
/// # Arguments
///
/// * `request` — trusted client state. The expected link is recomputed from it; the response
///   never contributes to the expectation. It also carries the two values an external node
///   signature is verified against: the response EIP-712 domain and the request's
///   `extra_data`.
/// * `trusted_signers` — the registered KMS signer addresses, keyed by party id, as the client's
///   own configuration holds them — on Solana, the host program's KMS-context signer set. A key
///   appearing inside a response is admitted only under its binding to one of these addresses
///   ; it is never trusted on its own. The signer count also fixes how many same-link shares
///   the release needs: one for a single-node deployment, `t + 1` for `n = 3t + 1` nodes —
///   the demand is derived here and is not a caller-supplied parameter, so it cannot be weakened.
/// * `agg_resp` — the untrusted responses.
///
/// # Returns
///
/// The accepted shares and the single link they carry, or the first rule that made the response as
/// a whole unusable. A multi-share set is additionally required to be one consistent threshold
/// response — degree matching the configured threshold, uniform ciphertext metadata, one signer
/// identity per party — checked by the EVM path's own validation run over the accepted originals,
/// so the release's reconstruction never sees a share set the EVM path would have refused.
pub fn verify_solana_user_decryption_response(
    request: &SolanaUserDecryptionRequest,
    trusted_signers: &HashMap<u32, alloy_primitives::Address>,
    agg_resp: &[UserDecryptionResponse],
) -> Result<VerifiedSolanaShares, SolanaUserDecryptionResponseError> {
    let required_shares = solana_required_shares(trusted_signers.len());
    // Recompute first: the expectation comes from the request's own fields and nowhere else, and a
    // request that is not a valid binding fails before any response — even an absent one — is
    // examined. JS callers pin this order: an invalid request with no responses reports the
    // request's problem, not the response's.
    let expected_link = request.expected_link()?;

    // No shares is not a below-threshold response but the absence of
    // one, and JS callers pin this message.
    if agg_resp.is_empty() {
        return Err(SolanaUserDecryptionResponseError::EmptyResponse);
    }

    let mut shares = Vec::with_capacity(agg_resp.len());
    let mut accepted_responses = Vec::with_capacity(agg_resp.len());
    let mut accepted_parties = BTreeSet::new();
    let mut rejections = ShareRejections::default();
    let mut first_rejection = None;
    for response in agg_resp {
        match verify_share(request, &expected_link, trusted_signers, response) {
            // One share per party: acceptance is keyed on the party, so a replayed
            // or equivocating share is discarded rather than counted towards the threshold twice.
            // Only *accepted* shares claim their party — a party whose earlier share failed a rule
            // is still represented by a later valid one.
            Ok(share) if accepted_parties.insert(share.party_id) => {
                shares.push(share);
                // The original response, kept for the consistency gate below, which re-reads the
                // signatures itself.
                accepted_responses.push(response.clone());
            }
            Ok(share) => {
                let rejection = ShareRejection::DuplicateParty {
                    party_id: share.party_id,
                };
                rejection.count(&mut rejections);
                first_rejection.get_or_insert(rejection);
            }
            Err(rejection) => {
                rejection.count(&mut rejections);
                first_rejection.get_or_insert(rejection);
            }
        }
    }

    // The consistency gate, for the multi-share sets that will reach the shared reconstruction:
    // per-share rules say nothing about the payload metadata reconstruction relies on — degree,
    // ciphertext count and types, packing, handles, one signer identity per party. Rather than
    // restate what a consistent threshold response is, the accepted originals are run through the
    // EVM path's own validation, unchanged, so that definition exists exactly once and the two
    // paths cannot drift. Its threshold is derived from the same trusted signer set as
    // `required_shares`, its pivot needs t + 1 agreeing payloads, and a share it drops as
    // inconsistent stops counting here too. The single-share case is the centralized shape, which
    // never reconstructs and carries nothing to cross-check — the same split the EVM entry point
    // makes.
    if shares.len() > 1 && shares.len() >= required_shares {
        let parsed = ParsedUserDecryptionRequest::new(
            None,
            // Unread by the validation, which authenticates KMS nodes, not the caller — and the
            // Solana path has no wallet address to put here anyway.
            alloy_primitives::Address::ZERO,
            request.enc_key.clone(),
            request
                .handles
                .iter()
                .cloned()
                .map(CiphertextHandle::new)
                .collect(),
            request
                .response_domain
                .verifying_contract
                .unwrap_or_default(),
            request.extra_data.clone(),
        );
        let trusted_ctx = UserDecTrustedValidationContext {
            server_addresses: trusted_signers,
            client_request: &parsed,
            eip712_domain: &request.response_domain,
            threshold: None,
        };
        let consistent = validate_user_decrypt_responses(&trusted_ctx, &accepted_responses)
            .map_err(
                |error| SolanaUserDecryptionResponseError::InconsistentShares {
                    reason: error.to_string(),
                },
            )?;
        let surviving: BTreeSet<u32> = consistent
            .as_slice()
            .iter()
            .map(|payload| payload.party_id)
            .collect();
        shares.retain(|share| surviving.contains(&share.party_id));
    }

    // The threshold: enough distinct parties carry the recomputed link, or the response fails as a whole.
    // Uniformity needs no extra pass — acceptance in `verify_share` is equality with the one
    // recomputed link, so every accepted share carries it by construction — and distinctness was
    // enforced at acceptance above.
    if shares.len() >= required_shares {
        return Ok(VerifiedSolanaShares {
            link: expected_link,
            receiver_id: request.user_pubkey,
            shares,
        });
    }
    match first_rejection {
        // A response of exactly one share reports the rule that share failed: there is no
        // aggregate story to tell about a single share.
        Some(rejection) if agg_resp.len() == 1 => Err(rejection.into()),
        // With more shares (or a lone share that verified against a higher demand) no single
        // failure is the reason the response failed — the census is.
        _ => Err(SolanaUserDecryptionResponseError::BelowThreshold {
            valid: shares.len(),
            needed: required_shares,
            rejections,
        }),
    }
}

/// Releases the plaintexts from a verified share set.
///
/// Consumes the verification result, which is the only way to obtain one: there is no path from an
/// unverified response to a plaintext.
///
/// One accepted share is the centralized case: it is unsigncrypted with the recomputed link as
/// associated data and the raw 32-byte wallet key as the receiver id — the same mapping the server
/// used, not a second copy of it. Two or more accepted shares are the threshold case: the shares
/// are handed to [`Client::reconstruct_validated_user_decryption`], the very code the EVM path
/// runs after its own validation, so recovery and Shamir reconstruction exist once and the two
/// paths differ only in what they validated and which receiver they open under.
///
/// `client` carries the FHE parameters and decryption mode the reconstruction runs under; its
/// server identities and wallet address play no part here — trust was settled during verification.
pub fn release_solana_user_decryption(
    client: &Client,
    shares: VerifiedSolanaShares,
    enc_key: &UnifiedPublicEncKey,
    dec_key: &UnifiedPrivateEncKey,
) -> Result<Vec<TypedPlaintext>, SolanaUserDecryptionResponseError> {
    let VerifiedSolanaShares {
        link,
        receiver_id,
        shares,
    } = shares;
    // The same receiver mapping the server signcrypted under: the raw 32-byte wallet key.
    let receiver = SigncryptionReceiver::Solana(receiver_id);

    if shares.len() > 1 {
        // Every accepted payload carries the recomputed link as its digest — that is what it was
        // accepted for — so the shared reconstruction unsigncrypts under exactly the link the
        // request expects, same as the centralized arm below.
        let payloads: Vec<UserDecryptionResponsePayload> =
            shares.into_iter().map(|share| share.payload).collect();
        return client
            .reconstruct_validated_user_decryption(receiver, &payloads, enc_key, dec_key)
            .map_err(|error| SolanaUserDecryptionResponseError::Reconstruction {
                reason: error.to_string(),
            });
    }

    // Unreachable through verification, which fails an empty response before this point; a
    // caller demanding zero shares could still construct one, and it holds no plaintext.
    let Some(share) = shares.into_iter().next() else {
        return Err(SolanaUserDecryptionResponseError::EmptyResponse);
    };

    let unsign_key = UnifiedUnsigncryptionKey::new(
        dec_key,
        enc_key,
        &share.verification_key,
        receiver.as_bytes(),
    );

    share
        .payload
        .signcrypted_ciphertexts
        .iter()
        .map(|ct| {
            unsign_key
                .unsigncrypt_plaintext(&DSEP_USER_DECRYPTION, &ct.signcrypted_ciphertext, &link)
                .map(|opened| opened.plaintext)
                .map_err(|error| SolanaUserDecryptionResponseError::Unsigncryption {
                    party_id: share.party_id,
                    reason: error.to_string(),
                })
        })
        .collect()
}

impl Client {
    /// Recovers the plaintexts of a Solana user-decryption response.
    ///
    /// A thin composition and nothing else: [`verify_solana_user_decryption_response`], then
    /// [`release_solana_user_decryption`]. Every verification rule lives in those functions, so
    /// there is exactly one implementation of each for every caller — Rust, WASM, or test.
    ///
    /// The trusted signer set is this client's own
    /// [`crate::client::client_wasm::ServerIdentities`], reduced to addresses — a configuration
    /// holding full keys contributes the addresses those keys determine. `client_address` plays no
    /// part on this path, since the recipient is the 32-byte wallet key carried by `request`.
    pub fn process_user_decryption_resp_solana(
        &self,
        request: &SolanaUserDecryptionRequest,
        enc_key: &UnifiedPublicEncKey,
        dec_key: &UnifiedPrivateEncKey,
        agg_resp: &[UserDecryptionResponse],
    ) -> Result<Vec<TypedPlaintext>, SolanaUserDecryptionResponseError> {
        let trusted_signers = self.get_server_addrs();
        let verified = verify_solana_user_decryption_response(request, &trusted_signers, agg_resp)?;
        release_solana_user_decryption(self, verified, enc_key, dec_key)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::num::Wrapping;

    use aes_prng::AesRng;
    use algebra::base_ring::Z64;
    use algebra::galois_rings::degree_4::ResiduePolyF4;
    use algebra::sharing::shamir::{InputOp, ShamirSharings};
    use kms_grpc::kms::v1::{
        TypedPlaintext, TypedSigncryptedCiphertext, UserDecryptionResponse,
        UserDecryptionResponsePayload,
    };
    use kms_grpc::rpc_types::{SigncryptionReceiver, fhe_types_to_num_blocks};
    use kms_grpc::solana_binding::{SolanaUserDecryptBinding, SolanaUserDecryptBindingError};
    use rand::SeedableRng;
    use tfhe::FheTypes;
    use threshold_execution::endpoints::decryption::DecryptionMode;
    use threshold_execution::tfhe_internals::parameters::AugmentedCiphertextParameters;

    use super::{
        ShareRejections, SolanaUserDecryptionRequest, SolanaUserDecryptionResponseError,
        VerifiedSolanaShares, release_solana_user_decryption, solana_required_shares,
        verify_solana_user_decryption_response,
    };
    use crate::client::client_wasm::Client;
    use crate::consts::{SAFE_SER_SIZE_LIMIT, TEST_PARAM};
    use crate::cryptography::compute_user_decrypt_message;
    use crate::cryptography::encryption::{
        Encryption, PkeScheme, PkeSchemeType, UnifiedPrivateEncKey, UnifiedPublicEncKey,
    };
    use crate::cryptography::signatures::{
        PrivateSigKey, PublicSigKey, compute_eip712_signature, gen_sig_keys, internal_sign,
    };
    use crate::cryptography::signcryption::{SigncryptFHEPlaintext, UnifiedSigncryptionKey};
    use crate::dummy_domain;
    use crate::engine::validation::DSEP_USER_DECRYPTION;

    const CHAIN_ID: u64 = (1 << 63) | 12_345;
    const PUBKEY: [u8; 32] = [0x11; 32];
    const PROGRAM_ID: [u8; 32] = [0x22; 32];
    const CONTEXT_ID: [u8; 32] = [0x44; 32];
    const EPOCH_ID: [u8; 32] = [0x55; 32];
    /// The request's opaque `extra_data`. Non-empty on purpose: it is an input to the message an
    /// external node signature commits to, so an all-empty fixture would let an implementation that
    /// ignores the field pass by coincidence.
    const EXTRA_DATA: [u8; 3] = [0x9a, 0x9b, 0x9c];

    /// A ciphertext handle on the canonical chain, `discriminator` filling every other byte so that
    /// two handles of one request stay distinguishable.
    fn handle(discriminator: u8) -> Vec<u8> {
        handle_for_chain(CHAIN_ID, discriminator)
    }

    fn handle_for_chain(chain_id: u64, discriminator: u8) -> Vec<u8> {
        let mut handle = [discriminator; 32];
        handle[22..30].copy_from_slice(&chain_id.to_be_bytes());
        handle.to_vec()
    }

    /// An ephemeral ML-KEM-512 pair plus the serialized public key, in the form a request carries
    /// it and the linker binds it.
    fn transport_key(seed: u64) -> (UnifiedPrivateEncKey, UnifiedPublicEncKey, Vec<u8>) {
        let mut rng = AesRng::seed_from_u64(seed);
        let (sk, pk) = Encryption::new(PkeSchemeType::MlKem512, &mut rng)
            .keygen()
            .expect("ML-KEM-512 keygen");
        let mut serialized = Vec::new();
        tfhe::safe_serialization::safe_serialize(&pk, &mut serialized, SAFE_SER_SIZE_LIMIT)
            .expect("serialize the transport key");
        (sk, pk, serialized)
    }

    /// The canonical request every test below deviates from in exactly one field.
    fn request_over(handles: Vec<Vec<u8>>) -> SolanaUserDecryptionRequest {
        SolanaUserDecryptionRequest {
            user_pubkey: PUBKEY,
            host_chain_id: CHAIN_ID,
            verifying_program_id: PROGRAM_ID,
            kms_context_id: CONTEXT_ID,
            kms_epoch_id: EPOCH_ID,
            handles,
            enc_key: transport_key(0).2,
            response_domain: dummy_domain(),
            extra_data: EXTRA_DATA.to_vec(),
        }
    }

    fn canonical_request() -> SolanaUserDecryptionRequest {
        request_over(vec![handle(0xa1)])
    }

    /// `count` KMS node key pairs, and the trusted key set keyed by party id (ids start at 1).
    fn node_keys(count: u32) -> (HashMap<u32, PublicSigKey>, Vec<PrivateSigKey>) {
        let mut rng = AesRng::seed_from_u64(42);
        let mut pks = HashMap::new();
        let mut sks = Vec::new();
        for party_id in 1..=count {
            let (vk, sk) = gen_sig_keys(&mut rng);
            pks.insert(party_id, vk);
            sks.push(sk);
        }
        (pks, sks)
    }

    /// The trusted signer set as `verify` consumes it: the registered address of each node key.
    fn trusted(pks: &HashMap<u32, PublicSigKey>) -> HashMap<u32, alloy_primitives::Address> {
        pks.iter().map(|(id, pk)| (*id, pk.address())).collect()
    }

    /// The accepted parties, in response order — the tests' shorthand for "which shares survived".
    fn party_ids(verified: &VerifiedSolanaShares) -> Vec<u32> {
        verified.shares.iter().map(|share| share.party_id).collect()
    }

    /// Signcrypted bytes that are never opened — enough for a test whose subject is the
    /// verification layer, which treats them as opaque.
    fn dummy_signcrypted() -> Vec<u8> {
        vec![1, 2, 3, 4]
    }

    /// A response payload for `party_id`, claiming `digest` and carrying opaque ciphertext bytes.
    fn payload(
        party_id: u32,
        vk: &PublicSigKey,
        digest: Vec<u8>,
        degree: u32,
        signcrypted: Vec<u8>,
    ) -> UserDecryptionResponsePayload {
        UserDecryptionResponsePayload {
            verification_key: bc2wrap::serialize(vk).expect("serialize a verification key"),
            digest,
            signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                fhe_type: FheTypes::Uint64 as i32,
                signcrypted_ciphertext: signcrypted,
                external_handle: handle(0xa1),
                packing_factor: 1,
            }],
            party_id,
            degree,
        }
    }

    /// The KMS node signature the client authenticates: ECDSA over `bc2wrap::serialize(&payload)`
    /// under the user-decryption domain separator.
    fn sign(payload: &UserDecryptionResponsePayload, sk: &PrivateSigKey) -> Vec<u8> {
        let serialized = bc2wrap::serialize(payload).expect("serialize a payload");
        internal_sign(&DSEP_USER_DECRYPTION, &serialized, sk)
            .expect("sign a payload")
            .sig
            .to_vec()
    }

    /// A response carrying `payload` and a valid *internal* node signature over it — the ECDSA
    /// authentication branch, with no external signature to fall back to.
    fn signed_response(
        payload: UserDecryptionResponsePayload,
        sk: &PrivateSigKey,
    ) -> UserDecryptionResponse {
        let signature = sign(&payload, sk);
        UserDecryptionResponse {
            signature,
            external_signature: vec![],
            payload: Some(payload),
            extra_data: EXTRA_DATA.to_vec(),
            signatures: vec![],
        }
    }

    /// A response authenticated the way the wire authenticates one: no internal ECDSA signature at
    /// all, and an EIP-712 `external_signature` over the payload, the request's transport key and
    /// `extra_data`, under the request's response domain — the very message the server builds.
    ///
    /// `extra_data` is passed explicitly so a test can sign over bytes other than the request's; the
    /// response carries the same bytes the signature commits to, which is what makes the mismatch a
    /// disagreement with the *request* rather than a self-inconsistent share.
    fn external_signed_response_over(
        request: &SolanaUserDecryptionRequest,
        payload: UserDecryptionResponsePayload,
        sk: &PrivateSigKey,
        extra_data: &[u8],
    ) -> UserDecryptionResponse {
        // The two steps the server takes, composed here rather than borrowed from a shared shim:
        // build the EIP-712 message from the payload, the request's transport key and `extra_data`,
        // then sign it under the request's response domain.
        let message = compute_user_decrypt_message(&payload, &request.enc_key, extra_data)
            .expect("build the external user-decryption message");
        let external_signature = compute_eip712_signature(sk, &message, &request.response_domain)
            .expect("compute an external user decryption signature");
        UserDecryptionResponse {
            signature: vec![],
            external_signature,
            payload: Some(payload),
            extra_data: extra_data.to_vec(),
            // Main's multi-scheme `signatures` list, left empty so these fixtures exercise the
            // deprecated-field fallback; the typed-list branch has its own tests.
            signatures: vec![],
        }
    }

    /// [`external_signed_response_over`] with the request's own `extra_data`: a share whose
    /// external signature is exactly the one this request expects.
    fn external_signed_response(
        request: &SolanaUserDecryptionRequest,
        payload: UserDecryptionResponsePayload,
        sk: &PrivateSigKey,
    ) -> UserDecryptionResponse {
        external_signed_response_over(request, payload, sk, &request.extra_data)
    }

    /// A one-share response for the canonical request, correctly signed and correctly linked.
    fn canonical_centralized_response(
        request: &SolanaUserDecryptionRequest,
        sk: &PrivateSigKey,
        vk: &PublicSigKey,
    ) -> UserDecryptionResponse {
        let link = request.expected_link().expect("a canonical request");
        signed_response(payload(1, vk, link, 0, dummy_signcrypted()), sk)
    }

    /// A `count`-share response for the canonical request, every share correctly signed by its own
    /// node and carrying the recomputed link.
    fn canonical_threshold_response(
        request: &SolanaUserDecryptionRequest,
        pks: &HashMap<u32, PublicSigKey>,
        sks: &[PrivateSigKey],
        degree: u32,
    ) -> Vec<UserDecryptionResponse> {
        let link = request.expected_link().expect("a canonical request");
        sks.iter()
            .enumerate()
            .map(|(index, sk)| {
                let party_id = index as u32 + 1;
                signed_response(
                    payload(
                        party_id,
                        &pks[&party_id],
                        link.clone(),
                        degree,
                        dummy_signcrypted(),
                    ),
                    sk,
                )
            })
            .collect()
    }

    /// An `n = 4`, `t = 1` threshold response whose shares actually reconstruct — the server-side
    /// arithmetic in miniature, with no MPC underneath. The plaintext is split into message blocks
    /// exactly as servers publish them under `BitDecSmall`, every block is Shamir-shared, and each
    /// party's share vector is signcrypted for the canonical receiver under the recomputed link.
    /// Returns the responses and the plaintext they share.
    fn reconstructable_threshold_response(
        request: &SolanaUserDecryptionRequest,
        pks: &HashMap<u32, PublicSigKey>,
        sks: &[PrivateSigKey],
        enc_key: &UnifiedPublicEncKey,
        rng: &mut AesRng,
    ) -> (Vec<UserDecryptionResponse>, TypedPlaintext) {
        const DEGREE: usize = 1;
        let num_parties = sks.len();
        assert_eq!(num_parties, 3 * DEGREE + 1, "the fixture is n = 3t + 1");

        let link = request.expected_link().expect("a canonical request");
        let receiver_id = SigncryptionReceiver::Solana(PUBKEY).as_bytes().to_vec();
        let expected = TypedPlaintext::new(0xAB, FheTypes::Uint8);

        // Least significant block first, one Shamir sharing per block: party i's payload is its
        // share of every block, in block order — the byte layout `recover_sharings` expects.
        let pbs = TEST_PARAM.classic_pbs();
        let bits_in_block = pbs.message_modulus_log();
        let num_blocks =
            fhe_types_to_num_blocks(FheTypes::Uint8, &pbs, 1).expect("block count for Uint8");
        let mut per_party_blocks = vec![Vec::new(); num_parties];
        let mut value = 0xABu64;
        for _ in 0..num_blocks {
            let block = value & ((1u64 << bits_in_block) - 1);
            value >>= bits_in_block;
            let sharing = ShamirSharings::share(
                rng,
                ResiduePolyF4::<Z64>::from_scalar(Wrapping(block)),
                num_parties,
                DEGREE,
            )
            .expect("share a block");
            for (party_blocks, share) in per_party_blocks.iter_mut().zip(&sharing.shares) {
                party_blocks.push(share.value());
            }
        }

        let responses = per_party_blocks
            .iter()
            .enumerate()
            .map(|(index, blocks)| {
                let party_id = index as u32 + 1;
                let serialized = bc2wrap::serialize(blocks).expect("serialize the share vector");
                let signcrypted = UnifiedSigncryptionKey::new(&sks[index], enc_key, &receiver_id)
                    .signcrypt_plaintext(
                        rng,
                        &DSEP_USER_DECRYPTION,
                        &serialized,
                        FheTypes::Uint8,
                        &link,
                    )
                    .expect("signcrypt the share")
                    .payload;
                signed_response(
                    UserDecryptionResponsePayload {
                        verification_key: bc2wrap::serialize(&pks[&party_id])
                            .expect("serialize a verification key"),
                        digest: link.clone(),
                        signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                            fhe_type: FheTypes::Uint8 as i32,
                            signcrypted_ciphertext: signcrypted,
                            external_handle: handle(0xa1),
                            packing_factor: 1,
                        }],
                        party_id,
                        degree: DEGREE as u32,
                    },
                    &sks[index],
                )
            })
            .collect();
        (responses, expected)
    }

    // ---------------------------------------------------------------------------------------
    // The shape of the API itself.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn response_error_taxonomy_matched_without_catch_all() {
        // A build-time canary, not a behaviour test: this match has no `_` arm, so adding a
        // variant to the taxonomy breaks this suite and forces a decision about which rule the new
        // failure belongs to. Every arm names the rule it stands for.
        let describe = |error: &SolanaUserDecryptionResponseError| -> &'static str {
            match error {
                SolanaUserDecryptionResponseError::EmptyResponse => "no shares at all",
                SolanaUserDecryptionResponseError::Binding(_) => "the request is not a binding",
                SolanaUserDecryptionResponseError::MissingPayload { .. } => "share without payload",
                SolanaUserDecryptionResponseError::UnknownParty { .. } => "no trusted key",
                SolanaUserDecryptionResponseError::MalformedVerificationKey { .. } => {
                    "not the trusted key"
                }
                SolanaUserDecryptionResponseError::NodeSignature { .. } => "bad node signature",
                SolanaUserDecryptionResponseError::LinkMismatch { .. } => "digest is not link",
                SolanaUserDecryptionResponseError::DuplicateParty { .. } => "a party counted twice",
                SolanaUserDecryptionResponseError::BelowThreshold { .. } => "too few shares",
                SolanaUserDecryptionResponseError::InconsistentShares { .. } => {
                    "not one consistent threshold response"
                }
                SolanaUserDecryptionResponseError::Unsigncryption { .. } => "release failed",
                SolanaUserDecryptionResponseError::Reconstruction { .. } => {
                    "threshold reconstruction failed"
                }
            }
        };

        assert_eq!(
            describe(&SolanaUserDecryptionResponseError::EmptyResponse),
            "no shares at all"
        );
        assert_eq!(
            describe(&SolanaUserDecryptionResponseError::LinkMismatch { party_id: 1 }),
            "digest is not link"
        );
    }

    #[test]
    fn js_pinned_error_messages_still_surface() {
        // tests/js/test.js asserts on these two strings across the WASM boundary. They are part of
        // the published behaviour of the JS export, so they are pinned on the Rust side too rather
        // than only in a suite that needs a wasm build to run.
        assert_eq!(
            SolanaUserDecryptionResponseError::EmptyResponse.to_string(),
            "Response does not exist"
        );

        let declared_mismatch = SolanaUserDecryptionResponseError::Binding(
            SolanaUserDecryptBindingError::DeclaredChainIdMismatch {
                declared: CHAIN_ID + 1,
                embedded: CHAIN_ID,
            },
        );
        assert!(
            declared_mismatch
                .to_string()
                .contains("does not match handle chain ID"),
            "the JS-visible chain-id message changed: {declared_mismatch}",
        );
    }

    #[test]
    fn solana_path_ignores_client_address() {
        // The Solana client has no wallet address, and the recipient is the
        // 32-byte key carried by the request. Two clients differing only in `client_address` must
        // therefore be indistinguishable on this path.
        let (pks, sks) = node_keys(1);
        let request = canonical_request();
        let (dec_key, enc_key, _) = transport_key(0);
        let agg_resp = vec![canonical_centralized_response(&request, &sks[0], &pks[&1])];

        let zero_address = Client::new_solana(trusted(&pks), TEST_PARAM, None);
        let other_address = Client::new(
            pks,
            alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
            None,
            TEST_PARAM,
            None,
        );

        assert_eq!(
            zero_address
                .process_user_decryption_resp_solana(&request, &enc_key, &dec_key, &agg_resp),
            other_address
                .process_user_decryption_resp_solana(&request, &enc_key, &dec_key, &agg_resp),
        );
    }

    #[test]
    fn required_share_count_follows_server_count() {
        // The release's "needed": one share centralized, t+1 for n = 3t + 1.
        assert_eq!(solana_required_shares(1), 1);
        assert_eq!(solana_required_shares(4), 2);
        assert_eq!(solana_required_shares(7), 3);
        assert_eq!(solana_required_shares(13), 5);
    }

    // ---------------------------------------------------------------------------------------
    // The expectation is recomputed, never parsed out of the response.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn expected_link_recomputed_from_request_fields() {
        // Built independently here through the canonical binding: if the request struct grew a
        // second construction of its own that merely agrees today, this comparison is what fails.
        let request = canonical_request();

        let binding = SolanaUserDecryptBinding::new(
            &PROGRAM_ID,
            &PUBKEY,
            &CONTEXT_ID,
            &EPOCH_ID,
            request.handles.iter().map(|handle| handle.as_slice()),
            &request.enc_key,
        )
        .expect("a canonical request");

        assert_eq!(
            request.expected_link().expect("a canonical request"),
            binding.compute_link()
        );
    }

    #[test]
    fn declared_chain_id_validated_before_response_processing() {
        // The client holds a chain id of its own — the one its permit was signed for — so
        // unlike a KMS party it can check the value the handles embed against a declared one.
        let request = canonical_request();
        assert_eq!(request.expected_link().unwrap().len(), 32);

        let mut wrong_chain = canonical_request();
        wrong_chain.host_chain_id = CHAIN_ID + 1;
        assert_eq!(
            wrong_chain.expected_link(),
            Err(SolanaUserDecryptBindingError::DeclaredChainIdMismatch {
                declared: CHAIN_ID + 1,
                embedded: CHAIN_ID,
            })
        );
    }

    #[test]
    fn rejects_invalid_handle_chain_ids_and_widths() {
        // A handle without the chain-kind bit belongs to the EVM linker, and a handle of the
        // wrong width is not a handle at all; neither can reach a link.
        let mut evm_handle = canonical_request();
        evm_handle.host_chain_id = 12_345;
        evm_handle.handles = vec![handle_for_chain(12_345, 0xa1)];
        assert_eq!(
            evm_handle.expected_link(),
            Err(SolanaUserDecryptBindingError::InvalidHandleChainId {
                index: 0,
                chain_id: 12_345,
            })
        );

        let mut short_handle = canonical_request();
        short_handle.handles = vec![vec![0; 31]];
        assert_eq!(
            short_handle.expected_link(),
            Err(SolanaUserDecryptBindingError::InvalidHandleLength {
                index: 0,
                actual: 31,
            })
        );
    }

    #[test]
    fn signed_share_with_foreign_digest_is_link_mismatch() {
        // The share is authentic — it is the *expectation* that does not come from it.
        // The digest below is the link of a different request, so a client that took the response's
        // digest as its expectation would accept this share.
        let (pks, sks) = node_keys(1);
        let request = canonical_request();
        let foreign_link = request_over(vec![handle(0xbb)])
            .expected_link()
            .expect("a canonical request");

        let agg_resp = vec![signed_response(
            payload(1, &pks[&1], foreign_link, 0, dummy_signcrypted()),
            &sks[0],
        )];

        assert_eq!(
            verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp),
            Err(SolanaUserDecryptionResponseError::LinkMismatch { party_id: 1 })
        );
    }

    // ---------------------------------------------------------------------------------------
    // Whichever node signature the share carries is verified, before its link is read.
    //
    // The rule is the EVM one, shared through `engine::validation_wasm`'s
    // `authenticate_user_decrypt_share`: a non-empty typed `signatures` list is the
    // authentication; otherwise a non-empty internal `signature` is checked as ECDSA over the
    // serialized payload, an empty one falls back to the EIP-712 `external_signature`, and
    // neither means unauthenticated.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn internal_signature_alone_authenticates_share() {
        // Sunshine, internal authentication branch. The share carries an ECDSA signature over the serialized
        // payload and nothing else, and that is enough to be authenticated.
        let (pks, sks) = node_keys(1);
        let request = canonical_request();
        let link = request.expected_link().expect("a canonical request");
        let agg_resp = vec![signed_response(
            payload(1, &pks[&1], link, 0, dummy_signcrypted()),
            &sks[0],
        )];
        assert!(
            agg_resp[0].external_signature.is_empty(),
            "this fixture must exercise the internal branch alone",
        );

        let verified = verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp)
            .expect("an internally signed share is authenticated");

        assert_eq!(party_ids(&verified), vec![1]);
    }

    #[test]
    fn external_signature_alone_authenticates_share() {
        // Sunshine, external authentication branch — and this is the shape the wire actually has: the relayer
        // forwards `signature: vec![]`, so the EIP-712 `external_signature` is the only
        // authentication a real Solana response carries. It must be *verified* against the response
        // domain, the request's transport key and its extra_data, which is precisely what the
        // earlier Solana code did not do.
        let (pks, sks) = node_keys(1);
        let request = canonical_request();
        let link = request.expected_link().expect("a canonical request");
        let agg_resp = vec![external_signed_response(
            &request,
            payload(1, &pks[&1], link, 0, dummy_signcrypted()),
            &sks[0],
        )];
        assert!(
            agg_resp[0].signature.is_empty() && !agg_resp[0].external_signature.is_empty(),
            "this fixture must exercise the external branch alone",
        );

        let verified = verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp)
            .expect("an externally signed share is authenticated");

        assert_eq!(party_ids(&verified), vec![1]);
    }

    #[test]
    fn typed_signatures_list_authenticates_share() {
        // Main's multi-scheme wire shape: the authentication travels in the typed `signatures`
        // list and both deprecated scalar fields are empty. The ECDSA entry carries the same
        // EIP-712 signature the external field would, so moving the bytes across is exactly the
        // migration a node performs when the deprecated fields go away.
        let (pks, sks) = node_keys(1);
        let request = canonical_request();
        let link = request.expected_link().expect("a canonical request");
        let mut response = external_signed_response(
            &request,
            payload(1, &pks[&1], link, 0, dummy_signcrypted()),
            &sks[0],
        );
        response.signatures =
            kms_grpc::rpc_types::ecdsa_signatures(std::mem::take(&mut response.external_signature));
        let agg_resp = vec![response];

        let verified = verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp)
            .expect("a share authenticated by its typed ECDSA signature is accepted");

        assert_eq!(party_ids(&verified), vec![1]);
    }

    #[test]
    fn typed_list_without_a_verifiable_scheme_rejects_share() {
        // An ed25519-only list is addressed to verifiers that hold per-scheme keys; this client's
        // registered identities are secp256k1 addresses, so the share fails the signature rule —
        // and the valid external signature sitting beside the list must not rescue it.
        let (pks, sks) = node_keys(1);
        let request = canonical_request();
        let link = request.expected_link().expect("a canonical request");
        let mut response = external_signed_response(
            &request,
            payload(1, &pks[&1], link, 0, dummy_signcrypted()),
            &sks[0],
        );
        response.signatures = vec![kms_grpc::kms::v1::TypedSignature {
            scheme: kms_grpc::kms::v1::SigningSchemeType::Ed25519 as i32,
            signature: vec![1; 64],
        }];
        assert!(
            !response.external_signature.is_empty(),
            "this fixture must offer a valid legacy signature the list must not fall back to",
        );
        let agg_resp = vec![response];

        let err = verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp)
            .expect_err("a list without a verifiable scheme authenticates nothing");

        assert!(matches!(
            err,
            SolanaUserDecryptionResponseError::NodeSignature { party_id: 1 }
        ));
    }

    #[test]
    fn single_share_response_names_failed_signature_rule() {
        // Internal branch. Three ways for an internal signature to be wrong plus the share that
        // carries no signature at all; all four are the same rule, and none of them may be reported
        // as a link problem.
        let (pks, sks) = node_keys(2);
        let request = canonical_request();
        let link = request.expected_link().expect("a canonical request");
        let good = payload(1, &pks[&1], link, 0, dummy_signcrypted());

        // Signed by a key that is not party 1's.
        let wrong_key = signed_response(good.clone(), &sks[1]);

        // The right signature, with a corrupted byte.
        let mut corrupted = signed_response(good.clone(), &sks[0]);
        corrupted.signature[0] ^= 0xff;

        // A signature over a payload that was mutated after signing.
        let mut mutated = signed_response(good.clone(), &sks[0]);
        let mut after = good.clone();
        after.degree += 1;
        mutated.payload = Some(after);

        // Neither signature: unauthenticated is unauthenticated, and an empty internal signature is
        // not a licence to skip the check when there is nothing to fall back to.
        let unsigned = UserDecryptionResponse {
            signature: vec![],
            external_signature: vec![],
            payload: Some(good),
            extra_data: EXTRA_DATA.to_vec(),
            signatures: vec![],
        };

        for (name, response) in [
            ("a foreign signing key", wrong_key),
            ("a corrupted signature", corrupted),
            ("a payload mutated after signing", mutated),
            ("no signature at all", unsigned),
        ] {
            assert_eq!(
                verify_solana_user_decryption_response(&request, &trusted(&pks), &[response]),
                Err(SolanaUserDecryptionResponseError::NodeSignature { party_id: 1 }),
                "{name} must be reported as the signature rule",
            );
        }
    }

    #[test]
    fn failed_external_signature_is_signature_error() {
        // External branch. The mirror of the case above: every way the EIP-712 signature can
        // fail to be party 1's signature over this request's message is the same rule. A share is
        // rejected here for reasons that have nothing to do with its digest, which is correct
        // throughout.
        let (pks, sks) = node_keys(2);
        let request = canonical_request();
        let link = request.expected_link().expect("a canonical request");
        let good = payload(1, &pks[&1], link, 0, dummy_signcrypted());

        // Signed by a key that is not party 1's.
        let wrong_key = external_signed_response(&request, good.clone(), &sks[1]);

        // Party 1's own signature, with a corrupted byte.
        let mut corrupted = external_signed_response(&request, good.clone(), &sks[0]);
        corrupted.external_signature[0] ^= 0xff;

        // A signature over a payload that was mutated after signing.
        let mut mutated = external_signed_response(&request, good.clone(), &sks[0]);
        let mut after = good.clone();
        after.degree += 1;
        mutated.payload = Some(after);

        // Party 1's own signature over this very payload, made under a different EIP-712 domain: a
        // signature from another deployment is not a signature for this one.
        let mut other_domain = canonical_request();
        other_domain.response_domain = alloy_sol_types::eip712_domain!(
            name: "Authorization token",
            version: "2",
            chain_id: 8006,
            verifying_contract: alloy_primitives::address!(
                "66f9664f97F2b50F62D13eA064982f936dE76657"
            ),
        );
        assert_ne!(other_domain.response_domain, request.response_domain);
        let foreign_domain = external_signed_response(&other_domain, good, &sks[0]);

        for (name, response) in [
            ("a foreign signing key", wrong_key),
            ("a corrupted external signature", corrupted),
            ("a payload mutated after signing", mutated),
            ("a signature made under another domain", foreign_domain),
        ] {
            assert_eq!(
                verify_solana_user_decryption_response(&request, &trusted(&pks), &[response]),
                Err(SolanaUserDecryptionResponseError::NodeSignature { party_id: 1 }),
                "{name} must be reported as the signature rule",
            );
        }
    }

    #[test]
    fn external_signature_over_other_extra_data_is_rejected() {
        // The EVM path requires the response's extra_data to be the request's before it
        // verifies anything, and this path mirrors it. The bytes stay opaque — nothing here parses
        // them — but they are an input to the signed message, so a share committing to other bytes
        // is authentic for a request that was never made. Everything else about this share is
        // right: party 1's own key, the recomputed link, a signature that verifies against the
        // bytes it was made over.
        let (pks, sks) = node_keys(1);
        let request = canonical_request();
        let link = request.expected_link().expect("a canonical request");
        let other_extra_data = [0xde, 0xad];
        assert_ne!(other_extra_data.as_slice(), request.extra_data.as_slice());

        let agg_resp = vec![external_signed_response_over(
            &request,
            payload(1, &pks[&1], link, 0, dummy_signcrypted()),
            &sks[0],
            &other_extra_data,
        )];

        assert_eq!(
            verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp),
            Err(SolanaUserDecryptionResponseError::NodeSignature { party_id: 1 })
        );
    }

    #[test]
    fn share_advertising_foreign_address_key_rejected() {
        // The advertised key is admitted by its address binding to the registered signer set. A
        // share advertising a different party's key — with a signature that even verifies under
        // that key — fails the key gate, before authentication: a valid signature by the wrong signer is not
        // a signature failure but a key that is not this party's.
        let (pks, sks) = node_keys(2);
        let request = canonical_request();
        let link = request.expected_link().expect("a canonical request");

        // Party 2's key and party 2's valid signature, claiming to be party 1.
        let foreign_key = payload(1, &pks[&2], link, 0, dummy_signcrypted());
        let response = signed_response(foreign_key, &sks[1]);

        assert_eq!(
            verify_solana_user_decryption_response(&request, &trusted(&pks), &[response]),
            Err(SolanaUserDecryptionResponseError::MalformedVerificationKey { party_id: 1 })
        );
    }

    #[test]
    fn empty_trusted_signer_set_authenticates_nothing() {
        // Fail-closed: with no registered signers every share is an unknown party, however well
        // signed. This is the semantics the wasm wrapper leans on when its caller omits the
        // signer set — omission weakens nothing into acceptance.
        let (pks, sks) = node_keys(1);
        let request = canonical_request();
        let agg_resp = vec![canonical_centralized_response(&request, &sks[0], &pks[&1])];

        assert_eq!(
            verify_solana_user_decryption_response(&request, &HashMap::new(), &agg_resp),
            Err(SolanaUserDecryptionResponseError::UnknownParty { party_id: 1 })
        );
    }

    #[test]
    fn present_internal_signature_takes_precedence() {
        // Authentication branches on which signature is present, exactly as the EVM path does — it does not try
        // both and accept either. A share with a forged internal signature must not be waved
        // through on a valid external one sitting next to it.
        let (pks, sks) = node_keys(2);
        let request = canonical_request();
        let link = request.expected_link().expect("a canonical request");
        let good = payload(1, &pks[&1], link, 0, dummy_signcrypted());

        let mut response = external_signed_response(&request, good.clone(), &sks[0]);
        // Party 2's ECDSA over party 1's payload: the internal signature is present and wrong.
        response.signature = sign(&good, &sks[1]);

        assert_eq!(
            verify_solana_user_decryption_response(&request, &trusted(&pks), &[response]),
            Err(SolanaUserDecryptionResponseError::NodeSignature { party_id: 1 })
        );
    }

    #[test]
    fn bad_signature_rejected_before_link_compared() {
        // Authentication before comparison. The share carries the byte-correct link, so the only reason to reject it is
        // the signature — and `link_mismatch` staying at zero is what shows the comparison was
        // never reached for an unauthenticated payload.
        let (pks, sks) = node_keys(4);
        let request = canonical_request();
        let mut agg_resp = canonical_threshold_response(&request, &pks, &sks, 1);
        // Party 1's payload is re-signed by party 2's key: correct link, wrong signer.
        let party_one = agg_resp[0].payload.clone().expect("a payload");
        agg_resp[0].signature = sign(&party_one, &sks[1]);

        let verified = verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp)
            .expect("three good shares are more than the two needed");

        assert_eq!(party_ids(&verified), vec![2, 3, 4]);
    }

    #[test]
    fn share_failing_both_rules_reported_as_signature_error() {
        // Authentication before comparison. The rejection is the *first* rule failed, so a share that is both
        // unauthenticated and wrongly linked never reaches the link comparison.
        let (pks, sks) = node_keys(1);
        let request = canonical_request();
        let mut agg_resp = vec![canonical_centralized_response(&request, &sks[0], &pks[&1])];
        let mut broken = agg_resp[0].payload.clone().expect("a payload");
        broken.digest[0] ^= 0xff;
        agg_resp[0].payload = Some(broken.clone());
        agg_resp[0].signature = sign(&broken, &sks[0]);
        agg_resp[0].signature[0] ^= 0xff;

        assert_eq!(
            verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp),
            Err(SolanaUserDecryptionResponseError::NodeSignature { party_id: 1 }),
        );
    }

    // ---------------------------------------------------------------------------------------
    // The digest comparison is byte equality, and a mismatching share contributes nothing.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn single_share_with_recomputed_link_verifies() {
        // Sunshine. The centralized case is the one-share case of the same rules.
        let (pks, sks) = node_keys(1);
        let request = canonical_request();
        let agg_resp = vec![canonical_centralized_response(&request, &sks[0], &pks[&1])];

        let verified = verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp)
            .expect("a canonical centralized response verifies");

        assert_eq!(party_ids(&verified), vec![1]);
        assert_eq!(
            verified.link,
            request.expected_link().expect("a canonical request"),
        );
        assert_eq!(verified.receiver_id, PUBKEY);

        // The accepted share carries the trusted key it verified under — the client's own, not the
        // one the payload advertises — and the payload it was taken from.
        let share = &verified.shares[0];
        assert_eq!(share.party_id, 1);
        assert_eq!(share.verification_key, pks[&1]);
        assert_eq!(share.payload.party_id, 1);
    }

    #[test]
    fn wrong_length_digest_rejected() {
        // Byte equality includes the length: a 31-byte digest is not a prefix match, and an
        // empty one is not a wildcard.
        let (pks, sks) = node_keys(1);
        let request = canonical_request();
        let link = request.expected_link().expect("a canonical request");

        for length in [0usize, 31, 33] {
            let mut digest = link.clone();
            digest.resize(length, 0);
            let agg_resp = vec![signed_response(
                payload(1, &pks[&1], digest, 0, dummy_signcrypted()),
                &sks[0],
            )];

            assert_eq!(
                verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp),
                Err(SolanaUserDecryptionResponseError::LinkMismatch { party_id: 1 }),
                "a {length}-byte digest must not pass the link comparison",
            );
        }
    }

    #[test]
    fn single_byte_digest_flip_rejected() {
        // The comparison is over all 32 bytes; there is no tolerance anywhere in it.
        let (pks, sks) = node_keys(1);
        let request = canonical_request();
        let link = request.expected_link().expect("a canonical request");

        for index in [0usize, 15, 31] {
            let mut digest = link.clone();
            digest[index] ^= 1;
            let agg_resp = vec![signed_response(
                payload(1, &pks[&1], digest, 0, dummy_signcrypted()),
                &sks[0],
            )];

            assert_eq!(
                verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp),
                Err(SolanaUserDecryptionResponseError::LinkMismatch { party_id: 1 }),
                "a flipped bit at byte {index} must not pass the link comparison",
            );
        }
    }

    #[test]
    fn wrongly_linked_share_excluded_others_survive() {
        // The discarded share contributes nothing: it is neither in the accepted set nor
        // counted towards the threshold, and the rest of the response is unaffected by it.
        let (pks, sks) = node_keys(4);
        let request = canonical_request();
        let mut agg_resp = canonical_threshold_response(&request, &pks, &sks, 1);
        let mut wrong_link = agg_resp[2].payload.clone().expect("a payload");
        wrong_link.digest[7] ^= 0xff;
        agg_resp[2] = signed_response(wrong_link, &sks[2]);

        let verified = verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp)
            .expect("three good shares are more than the two needed");

        assert_eq!(party_ids(&verified), vec![1, 2, 4]);
    }

    // ---------------------------------------------------------------------------------------
    // One common link, and all or nothing.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn only_shares_carrying_recomputed_link_accepted() {
        // Two groups of shares, each internally consistent, both correctly signed. The group
        // that matters is the one carrying the *recomputed* link — "the majority agrees" is not a
        // rule here, and a majority carrying a foreign link would still be rejected.
        let (pks, sks) = node_keys(4);
        let request = canonical_request();
        let foreign_link = request_over(vec![handle(0xbb)])
            .expected_link()
            .expect("a canonical request");

        let mut agg_resp = canonical_threshold_response(&request, &pks, &sks, 1);
        for index in [2usize, 3] {
            let mut divergent = agg_resp[index].payload.clone().expect("a payload");
            divergent.digest = foreign_link.clone();
            agg_resp[index] = signed_response(divergent, &sks[index]);
        }

        let verified = verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp)
            .expect("two shares carry the recomputed link, which is what is needed");

        assert_eq!(party_ids(&verified), vec![1, 2]);
        assert_ne!(verified.link, foreign_link);
    }

    #[test]
    fn too_few_same_link_shares_release_no_plaintext_at_all() {
        // All or nothing: a response that is partially valid is not partially released. This is
        // the EVM behaviour preserved as an explicit rule rather than as an accident of
        // reconstruction failing later.
        let (pks, sks) = node_keys(4);
        let request = canonical_request();
        let mut agg_resp = canonical_threshold_response(&request, &pks, &sks, 1);
        for index in [1usize, 2, 3] {
            let mut broken = agg_resp[index].payload.clone().expect("a payload");
            broken.digest[0] ^= 0xff;
            agg_resp[index] = signed_response(broken, &sks[index]);
        }

        assert_eq!(
            verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp),
            Err(SolanaUserDecryptionResponseError::BelowThreshold {
                valid: 1,
                needed: 2,
                rejections: ShareRejections {
                    link_mismatch: 3,
                    ..ShareRejections::default()
                },
            })
        );
    }

    #[test]
    fn shares_at_exact_threshold_still_verify() {
        // The threshold boundary. Dropping shares one at a time must keep verifying until the count
        // falls below what is needed, and fail on the very next one.
        let (pks, sks) = node_keys(4);
        let request = canonical_request();
        let full = canonical_threshold_response(&request, &pks, &sks, 1);
        let needed = solana_required_shares(4);

        for count in (needed..=full.len()).rev() {
            let verified =
                verify_solana_user_decryption_response(&request, &trusted(&pks), &full[..count])
                    .unwrap_or_else(|error| panic!("{count} shares must verify, got {error}"));
            assert_eq!(verified.shares.len(), count);
        }

        let below =
            verify_solana_user_decryption_response(&request, &trusted(&pks), &full[..needed - 1]);
        assert_eq!(
            below,
            Err(SolanaUserDecryptionResponseError::BelowThreshold {
                valid: needed - 1,
                needed,
                rejections: ShareRejections::default(),
            })
        );
    }

    #[test]
    fn replayed_share_does_not_fill_threshold() {
        // One share per party. A single node's share, replayed, is one distinct
        // party — never two — so the threshold cannot be met by echoing one share.
        let (pks, sks) = node_keys(4);
        let request = canonical_request();
        let agg_resp = canonical_threshold_response(&request, &pks, &sks, 1);
        let replayed = vec![agg_resp[0].clone(), agg_resp[0].clone()];

        assert_eq!(
            verify_solana_user_decryption_response(&request, &trusted(&pks), &replayed),
            Err(SolanaUserDecryptionResponseError::BelowThreshold {
                valid: 1,
                needed: 2,
                rejections: ShareRejections {
                    duplicate_party: 1,
                    ..ShareRejections::default()
                },
            })
        );
    }

    #[test]
    fn only_first_accepted_share_per_party_counted() {
        // A replay next to an otherwise complete response is discarded into the census; the
        // accepted set still carries each party exactly once.
        let (pks, sks) = node_keys(4);
        let request = canonical_request();
        let mut agg_resp = canonical_threshold_response(&request, &pks, &sks, 1);
        agg_resp.push(agg_resp[0].clone());

        let verified = verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp)
            .expect("four distinct parties are more than the two needed");

        assert_eq!(party_ids(&verified), vec![1, 2, 3, 4]);
    }

    #[test]
    fn party_with_failed_first_share_still_counted_via_valid_share() {
        // Distinctness is keyed on *accepted* shares. A garbage share planted in front of a
        // party's real one must not consume that party's slot — otherwise anyone able to inject
        // bytes into the aggregate could vote a trusted node out of the count.
        let (pks, sks) = node_keys(4);
        let request = canonical_request();
        let mut agg_resp = canonical_threshold_response(&request, &pks, &sks, 1);
        let mut planted = agg_resp[0].clone();
        planted.signature = sign(&planted.payload.clone().expect("a payload"), &sks[1]);
        agg_resp.insert(0, planted);

        let verified = verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp)
            .expect("all four real shares verify");

        assert_eq!(party_ids(&verified), vec![1, 2, 3, 4]);
    }

    #[test]
    fn empty_response_rejected_before_examining_shares() {
        // The degenerate case: no shares at all, and the message the JS tests pin.
        let (pks, _sks) = node_keys(1);
        let request = canonical_request();

        assert_eq!(
            verify_solana_user_decryption_response(&request, &trusted(&pks), &[]),
            Err(SolanaUserDecryptionResponseError::EmptyResponse)
        );
    }

    #[test]
    fn verified_threshold_response_reconstructs_shared_plaintext() {
        // The threshold release end to end: four real shares of one plaintext, Shamir-shared and
        // signcrypted exactly as servers publish them, reconstruct through the same code the EVM
        // path runs after its own validation — no Solana-only reconstruction exists to diverge.
        let mut rng = AesRng::seed_from_u64(9);
        let (pks, sks) = node_keys(4);
        let request = canonical_request();
        let (dec_key, enc_key, _) = transport_key(0);
        let (agg_resp, expected) =
            reconstructable_threshold_response(&request, &pks, &sks, &enc_key, &mut rng);

        let client =
            Client::new_solana(trusted(&pks), TEST_PARAM, Some(DecryptionMode::BitDecSmall));
        let verified = verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp)
            .expect("four good shares verify");
        let released = release_solana_user_decryption(&client, verified, &enc_key, &dec_key)
            .expect("the threshold release reconstructs");

        assert_eq!(released, vec![expected]);
    }

    #[test]
    fn threshold_response_missing_one_share_still_reconstructs() {
        // t-of-n, not n-of-n: with degree 1 and four parties any t + 1 = 2 shares interpolate, so
        // dropping a whole response must not change the released plaintext — the same one-share
        // drop the EVM threshold tests perform.
        let mut rng = AesRng::seed_from_u64(9);
        let (pks, sks) = node_keys(4);
        let request = canonical_request();
        let (dec_key, enc_key, _) = transport_key(0);
        let (agg_resp, expected) =
            reconstructable_threshold_response(&request, &pks, &sks, &enc_key, &mut rng);

        let client =
            Client::new_solana(trusted(&pks), TEST_PARAM, Some(DecryptionMode::BitDecSmall));
        let verified =
            verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp[1..])
                .expect("three good shares are more than the two needed");
        let released = release_solana_user_decryption(&client, verified, &enc_key, &dec_key)
            .expect("the threshold release tolerates a missing share");

        assert_eq!(released, vec![expected]);
    }

    #[test]
    fn centralized_response_releases_its_signcrypted_plaintext() {
        // The whole path, with real signcryption: the link is the associated data and the raw
        // 32-byte wallet key is the receiver id, so a plaintext only comes out if the client
        // recomputed both exactly as the server used them.
        let mut rng = AesRng::seed_from_u64(7);
        let (pks, sks) = node_keys(1);
        let request = canonical_request();
        let link = request.expected_link().expect("a canonical request");
        let (dec_key, enc_key, enc_key_bytes) = transport_key(0);
        assert_eq!(request.enc_key, enc_key_bytes, "the request binds this key");

        let expected = TypedPlaintext::new(42, FheTypes::Uint64);
        let receiver_id = SigncryptionReceiver::Solana(PUBKEY).as_bytes().to_vec();
        let signcrypted = UnifiedSigncryptionKey::new(&sks[0], &enc_key, &receiver_id)
            .signcrypt_plaintext(
                &mut rng,
                &DSEP_USER_DECRYPTION,
                &expected.bytes,
                FheTypes::Uint64,
                &link,
            )
            .expect("signcrypt the share")
            .payload;

        let agg_resp = vec![signed_response(
            payload(1, &pks[&1], link, 0, signcrypted),
            &sks[0],
        )];

        let client = Client::new_solana(trusted(&pks), TEST_PARAM, None);
        let verified = verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp)
            .expect("a canonical centralized response verifies");
        let released = release_solana_user_decryption(&client, verified, &enc_key, &dec_key)
            .expect("the centralized release opens the share");

        assert_eq!(released, vec![expected]);
    }

    // ---------------------------------------------------------------------------------------
    // Duplicate handles are bound by position.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn repeated_handle_binds_both_occurrences() {
        // Duplicates are legal upstream — each occurrence is authorized independently — so the
        // linker binds every occurrence at its position, and [h, h] is not [h].
        let once = request_over(vec![handle(0xa1)]);
        let twice = request_over(vec![handle(0xa1), handle(0xa1)]);

        assert_eq!(twice.handles.len(), 2);
        assert_ne!(
            once.expected_link().expect("a canonical request"),
            twice.expected_link().expect("a canonical request"),
        );
    }

    #[test]
    fn digest_over_deduplicated_handles_is_link_mismatch() {
        // A server (or relayer) that collapsed the repeated handle answered a request the client
        // did not make. The client asked for two decryptions and must not accept a response bound
        // to one.
        let (pks, sks) = node_keys(1);
        let request = request_over(vec![handle(0xa1), handle(0xa1)]);
        let deduplicated = request_over(vec![handle(0xa1)])
            .expected_link()
            .expect("a canonical request");

        let agg_resp = vec![signed_response(
            payload(1, &pks[&1], deduplicated, 0, dummy_signcrypted()),
            &sks[0],
        )];

        assert_eq!(
            verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp),
            Err(SolanaUserDecryptionResponseError::LinkMismatch { party_id: 1 })
        );
    }

    // ---------------------------------------------------------------------------------------
    // The consistency gate: a multi-share set must be one threshold response.
    // ---------------------------------------------------------------------------------------

    /// `response`, its payload changed by `mutate` and re-signed by the same node: a share that is
    /// perfectly authenticated and correctly linked, wrong only in the mutated metadata. The
    /// consistency gate exists exactly for these — every per-share rule accepts them.
    fn mutated_and_resigned(
        mut response: UserDecryptionResponse,
        sk: &PrivateSigKey,
        mutate: impl FnOnce(&mut UserDecryptionResponsePayload),
    ) -> UserDecryptionResponse {
        let payload = response.payload.as_mut().expect("a fixture payload");
        mutate(payload);
        response.signature = sign(payload, sk);
        response
    }

    #[test]
    fn signed_zero_ciphertext_share_cannot_shape_reconstruction() {
        // n = 4, t = 1: two distinct parties satisfy the count, so a correctly signed share with
        // zero ciphertexts plus one honest share used to reach reconstruction, which takes the
        // batch shape from the first payload and would release an empty plaintext list as
        // success. The two shares do not agree on what is being released, and the gate refuses
        // the set.
        let mut rng = AesRng::seed_from_u64(21);
        let (pks, sks) = node_keys(4);
        let request = canonical_request();
        let (dec_key, enc_key, _) = transport_key(0);
        let (agg_resp, _) =
            reconstructable_threshold_response(&request, &pks, &sks, &enc_key, &mut rng);

        let hollow = mutated_and_resigned(agg_resp[0].clone(), &sks[0], |payload| {
            payload.signcrypted_ciphertexts.clear();
        });
        let two = vec![hollow, agg_resp[1].clone()];

        let client =
            Client::new_solana(trusted(&pks), TEST_PARAM, Some(DecryptionMode::BitDecSmall));
        let result = client.process_user_decryption_resp_solana(&request, &enc_key, &dec_key, &two);
        assert!(
            matches!(
                result,
                Err(SolanaUserDecryptionResponseError::InconsistentShares { .. })
            ),
            "a hollow share must fail the consistency gate, got {result:?}",
        );
    }

    #[test]
    fn shorter_late_share_dropped_not_indexed() {
        // The same mutation surrounded by an honest majority: the pivot is the three consistent
        // shares, the hollow one is dropped as disagreeing with it, and the release still
        // reconstructs — reconstruction never indexes past the short ciphertext list, because the
        // short list never reaches it.
        let mut rng = AesRng::seed_from_u64(22);
        let (pks, sks) = node_keys(4);
        let request = canonical_request();
        let (dec_key, enc_key, _) = transport_key(0);
        let (mut agg_resp, expected) =
            reconstructable_threshold_response(&request, &pks, &sks, &enc_key, &mut rng);

        agg_resp[3] = mutated_and_resigned(agg_resp[3].clone(), &sks[3], |payload| {
            payload.signcrypted_ciphertexts.clear();
        });

        let client =
            Client::new_solana(trusted(&pks), TEST_PARAM, Some(DecryptionMode::BitDecSmall));
        let released = client
            .process_user_decryption_resp_solana(&request, &enc_key, &dec_key, &agg_resp)
            .expect("three consistent shares reconstruct around the dropped one");
        assert_eq!(released, vec![expected]);
    }

    #[test]
    fn degree_other_than_configured_threshold_refused() {
        // Four shares agreeing with each other on degree 2 under a four-server set: internally
        // uniform, but not a response of the t = 1 deployment the client is configured for, and
        // reconstruction would run Shamir under the response's own parameters.
        let (pks, sks) = node_keys(4);
        let request = canonical_request();
        let agg_resp = canonical_threshold_response(&request, &pks, &sks, 2);

        let result = verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp);
        assert!(
            matches!(
                result,
                Err(SolanaUserDecryptionResponseError::InconsistentShares { .. })
            ),
            "a foreign degree must fail the consistency gate, got {result:?}",
        );
    }

    #[test]
    fn shares_disagreeing_on_degree_are_not_one_response() {
        // Two shares, two degrees: no t + 1 of them agree on anything, so no pivot exists and
        // neither share's shape can borrow a majority it does not have.
        let (pks, sks) = node_keys(4);
        let request = canonical_request();
        let base = canonical_threshold_response(&request, &pks, &sks, 1);

        let skewed = mutated_and_resigned(base[1].clone(), &sks[1], |payload| payload.degree = 2);
        let two = vec![base[0].clone(), skewed];

        let result = verify_solana_user_decryption_response(&request, &trusted(&pks), &two);
        assert!(
            matches!(
                result,
                Err(SolanaUserDecryptionResponseError::InconsistentShares { .. })
            ),
            "disagreeing degrees must fail the consistency gate, got {result:?}",
        );
    }

    #[test]
    fn shares_disagreeing_on_ciphertext_metadata_are_not_one_response() {
        // One mutation per round — FHE type, packing factor, external handle — each re-signed, so
        // the named field is the only inconsistency in the set. Each one changes what the shared
        // reconstruction would do with the payload bytes, so each must refuse the set.
        let (pks, sks) = node_keys(4);
        let request = canonical_request();
        let base = canonical_threshold_response(&request, &pks, &sks, 1);

        let mutations = [
            (
                "fhe type",
                (|payload: &mut UserDecryptionResponsePayload| {
                    payload.signcrypted_ciphertexts[0].fhe_type = FheTypes::Uint32 as i32;
                }) as fn(&mut UserDecryptionResponsePayload),
            ),
            ("packing factor", |payload| {
                payload.signcrypted_ciphertexts[0].packing_factor = 2;
            }),
            ("external handle", |payload| {
                payload.signcrypted_ciphertexts[0].external_handle = handle(0xb2);
            }),
        ];

        for (name, mutate) in mutations {
            let skewed = mutated_and_resigned(base[1].clone(), &sks[1], mutate);
            let two = vec![base[0].clone(), skewed];

            let result = verify_solana_user_decryption_response(&request, &trusted(&pks), &two);
            assert!(
                matches!(
                    result,
                    Err(SolanaUserDecryptionResponseError::InconsistentShares { .. })
                ),
                "a {name} mismatch must fail the consistency gate, got {result:?}",
            );
        }
    }

    #[test]
    fn byte_identical_key_cannot_vote_under_two_party_ids() {
        // A trusted set that (mis)registers one address under two party ids is the only way one
        // key can pass the per-share address binding twice. The set-level rule refuses the
        // byte-identical pair — a verification key backs at most one accepted party, so the two
        // shares collapse to one and the response is no quorum. That rule compares the key's
        // exact bytes, so it pins the replay case only: the same key re-encoded would slip past
        // it, and a registry with a distinct address per party id is what rules that out.
        let (pks, sks) = node_keys(4);
        let request = canonical_request();
        let link = request.expected_link().expect("a canonical request");

        let mut signers = trusted(&pks);
        signers.insert(2, pks[&1].address());

        let double = vec![
            signed_response(
                payload(1, &pks[&1], link.clone(), 1, dummy_signcrypted()),
                &sks[0],
            ),
            signed_response(payload(2, &pks[&1], link, 1, dummy_signcrypted()), &sks[0]),
        ];

        let result = verify_solana_user_decryption_response(&request, &signers, &double);
        assert!(
            matches!(
                result,
                Err(SolanaUserDecryptionResponseError::InconsistentShares { .. })
            ),
            "a byte-identical key under two party ids must fail the consistency gate, got {result:?}",
        );
    }

    #[test]
    fn gate_verifies_external_signatures_with_request_fields() {
        // The gate re-checks signatures through the shared validation, whose external branch
        // rebuilds the signed message from the request's transport key, extra_data and response
        // domain. A fully external-signed threshold set passing end to end pins that the Solana
        // request supplies those fields to the shared code exactly as an EVM request would — the
        // liveness half of reusing the EVM validation.
        let (pks, sks) = node_keys(4);
        let request = canonical_request();
        let link = request.expected_link().expect("a canonical request");

        let agg_resp: Vec<UserDecryptionResponse> = sks
            .iter()
            .enumerate()
            .map(|(index, sk)| {
                let party_id = index as u32 + 1;
                external_signed_response(
                    &request,
                    payload(
                        party_id,
                        &pks[&party_id],
                        link.clone(),
                        1,
                        dummy_signcrypted(),
                    ),
                    sk,
                )
            })
            .collect();

        let verified = verify_solana_user_decryption_response(&request, &trusted(&pks), &agg_resp)
            .expect("an external-signed threshold set passes both gates");
        assert_eq!(party_ids(&verified), vec![1, 2, 3, 4]);
    }

    // ---------------------------------------------------------------------------------------
    // The stable JS/WASM test vectors (`wasm_tests` builds only).
    // ---------------------------------------------------------------------------------------

    /// The Solana counterpart of the EVM transcript generation: a deterministic fixture written as
    /// a stable JSON vector that `tests/js/test.js` drives through the *public* wasm API
    /// (`new_solana_client` + `process_user_decryption_resp_solana_from_js`). Unlike the EVM
    /// transcripts it needs no running KMS — the responses are built with the same seeded
    /// primitives the host tests above use — so the shares travel exactly as the wire carries
    /// them: no internal ECDSA signature, an EIP-712 `external_signature` only.
    #[cfg(feature = "wasm_tests")]
    mod wasm_transcripts {
        use super::*;
        use algebra::base_ring::Z128;
        use kms_grpc::rpc_types::alloy_to_protobuf_domain;

        use crate::client::user_decryption_wasm::{
            CiphertextHandle, ParsedUserDecryptionRequest, ParsedUserDecryptionRequestHex,
            StableExpectedPlaintext, StableServerIdAddr, UserDecryptionResponseHex,
        };

        /// The stable JSON shape `tests/js/test.js` loads for the Solana path. Like the EVM
        /// [crate::client::user_decryption_wasm::StableUserDecryptionTestVector], every field is
        /// encoded in the exact hex/JSON form the stable public wasm API already accepts, and the
        /// format is append-only: new fields must be optional so an older `test.js` keeps working.
        #[derive(serde::Serialize)]
        struct StableSolanaUserDecryptionTestVector {
            /// FHE parameter name accepted by `new_solana_client` (`"test"` or `"default"`).
            fhe_parameter: String,
            /// The registered KMS signer set, the trust anchor `new_solana_client` is built from.
            server_addrs: Vec<StableServerIdAddr>,
            /// The recipient's raw 32-byte ed25519 wallet key, hex.
            solana_user_pubkey: String,
            /// The host chain id as a decimal string: bit 63 is set, so the value does not fit a
            /// JS number exactly and must cross the boundary as a `BigInt`.
            host_chain_id: String,
            /// The on-chain verifying program id, 32 bytes hex.
            verifying_program_id: String,
            /// The KMS context id, 32 bytes hex.
            kms_context_id: String,
            /// The KMS epoch id, 32 bytes hex.
            kms_epoch_id: String,
            /// The request in the hex shape `process_user_decryption_resp_solana_from_js` expects.
            request: ParsedUserDecryptionRequestHex,
            /// The EIP-712 domain the responses' external signatures were produced under.
            eip712_domain: kms_grpc::kms::v1::Eip712DomainMsg,
            /// The aggregated responses in hex shape: external signature only, as on the wire.
            responses: Vec<UserDecryptionResponseHex>,
            /// Ephemeral public encryption key, hex of `ml_kem_pke_pk_to_u8vec` (safe-serialized).
            enc_pk: String,
            /// Ephemeral private decryption key, hex of `ml_kem_pke_sk_to_u8vec` (bincode).
            enc_sk: String,
            /// Expected plaintext(s) for assertions.
            expected: Vec<StableExpectedPlaintext>,
        }

        /// Assembles the stable vector from the very values the fixture was built from.
        fn stable_solana_vector(
            request: &SolanaUserDecryptionRequest,
            pks: &HashMap<u32, PublicSigKey>,
            agg_resp: &[UserDecryptionResponse],
            dec_key: &UnifiedPrivateEncKey,
            expected: &[TypedPlaintext],
        ) -> StableSolanaUserDecryptionTestVector {
            let mut server_addrs: Vec<StableServerIdAddr> = pks
                .iter()
                .map(|(id, pk)| StableServerIdAddr {
                    id: *id,
                    addr: pk.address().to_checksum(None),
                })
                .collect();
            // A HashMap iterates in random order; the file must not change bytes between runs.
            server_addrs.sort_by_key(|id_addr| id_addr.id);

            let verifying_contract = request
                .response_domain
                .verifying_contract
                .expect("the fixture domain names a verifying contract");
            let request_hex =
                ParsedUserDecryptionRequestHex::from(&ParsedUserDecryptionRequest::new(
                    None,
                    // The Solana path has no wallet address; the field is only part of the EVM-shaped
                    // request marshalling and is ignored by the Solana rules.
                    alloy_primitives::Address::ZERO,
                    request.enc_key.clone(),
                    request
                        .handles
                        .iter()
                        .map(|handle| CiphertextHandle::new(handle.clone()))
                        .collect(),
                    verifying_contract,
                    request.extra_data.clone(),
                ));

            StableSolanaUserDecryptionTestVector {
                fhe_parameter: "test".to_string(),
                server_addrs,
                solana_user_pubkey: hex::encode(request.user_pubkey),
                host_chain_id: request.host_chain_id.to_string(),
                verifying_program_id: hex::encode(request.verifying_program_id),
                kms_context_id: hex::encode(request.kms_context_id),
                kms_epoch_id: hex::encode(request.kms_epoch_id),
                request: request_hex,
                eip712_domain: alloy_to_protobuf_domain(&request.response_domain)
                    .expect("the fixture domain converts"),
                responses: agg_resp
                    .iter()
                    .map(UserDecryptionResponseHex::try_from)
                    .collect::<anyhow::Result<Vec<_>>>()
                    .expect("responses serialize to the hex shape"),
                enc_pk: hex::encode(&request.enc_key),
                enc_sk: hex::encode(
                    bc2wrap::serialize(&dec_key.clone().unwrap_ml_kem_512())
                        .expect("serialize the ephemeral private key"),
                ),
                expected: expected
                    .iter()
                    .map(|plaintext| StableExpectedPlaintext {
                        fhe_type: plaintext.fhe_type,
                        plaintext_hex: hex::encode(&plaintext.bytes),
                    })
                    .collect(),
            }
        }

        fn write_stable_solana_vector(path: &str, vector: &StableSolanaUserDecryptionTestVector) {
            if let Some(parent) = std::path::Path::new(path).parent() {
                std::fs::create_dir_all(parent).expect("create the transcript directory");
            }
            std::fs::write(
                path,
                serde_json::to_string_pretty(vector).expect("serialize the vector"),
            )
            .expect("write the transcript");
        }

        /// An `n = 4`, `t = 1` threshold response whose shares reconstruct under
        /// `NoiseFloodSmall` — the decryption mode `new_solana_client` (like `new_client`)
        /// defaults to, which is why the wasm-facing fixture cannot reuse the `BitDecSmall`
        /// fixture of the host tests above. Under this mode a server publishes shares of the
        /// *expanded* blocks — the block value in the top bits below one padding bit, the layout
        /// `from_expanded_msg` inverts — packed four blocks to a residue polynomial, one
        /// coefficient each.
        fn reconstructable_noiseflood_threshold_response(
            request: &SolanaUserDecryptionRequest,
            pks: &HashMap<u32, PublicSigKey>,
            sks: &[PrivateSigKey],
            enc_key: &UnifiedPublicEncKey,
            rng: &mut AesRng,
        ) -> (Vec<UserDecryptionResponse>, TypedPlaintext) {
            const DEGREE: usize = 1;
            const PACKING: usize = 4;
            let num_parties = sks.len();
            assert_eq!(num_parties, 3 * DEGREE + 1, "the fixture is n = 3t + 1");

            let link = request.expected_link().expect("a canonical request");
            let receiver_id = SigncryptionReceiver::Solana(PUBKEY).as_bytes().to_vec();
            let expected = TypedPlaintext::new(0xAB, FheTypes::Uint8);

            let pbs = TEST_PARAM.classic_pbs();
            let bits_in_block = pbs.message_modulus_log();
            let total_block_bits = pbs.total_block_bits() as usize;
            let delta_pad_bits = 128 - (total_block_bits + 1);
            let num_blocks =
                fhe_types_to_num_blocks(FheTypes::Uint8, &pbs, 1).expect("block count for Uint8");

            // Least significant block first, in expanded form with zero noise.
            let mut expanded_blocks = Vec::with_capacity(num_blocks);
            let mut value = 0xABu128;
            for _ in 0..num_blocks {
                let block = value & ((1u128 << bits_in_block) - 1);
                value >>= bits_in_block;
                expanded_blocks.push(Wrapping(block << delta_pad_bits));
            }

            // One Shamir sharing per packed polynomial: party i's payload is its share of every
            // polynomial, in order — the byte layout `recover_sharings` expects for this mode.
            let mut per_party_polys = vec![Vec::new(); num_parties];
            for chunk in expanded_blocks.chunks(PACKING) {
                let mut coefs = [Wrapping(0u128); PACKING];
                coefs[..chunk.len()].copy_from_slice(chunk);
                let sharing = ShamirSharings::share(
                    rng,
                    ResiduePolyF4::<Z128>::from_array(coefs),
                    num_parties,
                    DEGREE,
                )
                .expect("share a packed block");
                for (party_polys, share) in per_party_polys.iter_mut().zip(&sharing.shares) {
                    party_polys.push(share.value());
                }
            }

            let responses = per_party_polys
                .iter()
                .enumerate()
                .map(|(index, polys)| {
                    let party_id = index as u32 + 1;
                    let serialized = bc2wrap::serialize(polys).expect("serialize the share vector");
                    let signcrypted =
                        UnifiedSigncryptionKey::new(&sks[index], enc_key, &receiver_id)
                            .signcrypt_plaintext(
                                rng,
                                &DSEP_USER_DECRYPTION,
                                &serialized,
                                FheTypes::Uint8,
                                &link,
                            )
                            .expect("signcrypt the share")
                            .payload;
                    external_signed_response(
                        request,
                        UserDecryptionResponsePayload {
                            verification_key: bc2wrap::serialize(&pks[&party_id])
                                .expect("serialize a verification key"),
                            digest: link.clone(),
                            signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                                fhe_type: FheTypes::Uint8 as i32,
                                signcrypted_ciphertext: signcrypted,
                                external_handle: handle(0xa1),
                                packing_factor: 1,
                            }],
                            party_id,
                            degree: DEGREE as u32,
                        },
                        &sks[index],
                    )
                })
                .collect();
            (responses, expected)
        }

        /// Writes the two Solana vectors — centralized and threshold — after proving on the host
        /// that each releases its expected plaintext through the very client configuration the JS
        /// test will build (`new_solana_client` semantics: `"test"` parameters, the default
        /// decryption mode). A vector that fails here is never written.
        #[test]
        fn test_user_decryption_solana_and_write_transcript() {
            // Centralized: one node, one externally signed share, real signcryption.
            let mut rng = AesRng::seed_from_u64(7);
            let (pks, sks) = node_keys(1);
            let request = canonical_request();
            let link = request.expected_link().expect("a canonical request");
            let (dec_key, enc_key, enc_key_bytes) = transport_key(0);
            assert_eq!(request.enc_key, enc_key_bytes, "the request binds this key");

            let expected = TypedPlaintext::new(42, FheTypes::Uint64);
            let receiver_id = SigncryptionReceiver::Solana(PUBKEY).as_bytes().to_vec();
            let signcrypted = UnifiedSigncryptionKey::new(&sks[0], &enc_key, &receiver_id)
                .signcrypt_plaintext(
                    &mut rng,
                    &DSEP_USER_DECRYPTION,
                    &expected.bytes,
                    FheTypes::Uint64,
                    &link,
                )
                .expect("signcrypt the share")
                .payload;
            let agg_resp = vec![external_signed_response(
                &request,
                payload(1, &pks[&1], link, 0, signcrypted),
                &sks[0],
            )];

            let client = Client::new_solana(trusted(&pks), TEST_PARAM, None);
            let released = client
                .process_user_decryption_resp_solana(&request, &enc_key, &dec_key, &agg_resp)
                .expect("the centralized fixture releases");
            assert_eq!(released, vec![expected]);

            write_stable_solana_vector(
                crate::consts::TEST_SOLANA_CENTRAL_WASM_TRANSCRIPT_PATH,
                &stable_solana_vector(&request, &pks, &agg_resp, &dec_key, &released),
            );

            // Threshold: four nodes, externally signed shares that reconstruct under the default
            // decryption mode.
            let mut rng = AesRng::seed_from_u64(9);
            let (pks, sks) = node_keys(4);
            let request = canonical_request();
            let (dec_key, enc_key, _) = transport_key(0);
            let (agg_resp, expected) = reconstructable_noiseflood_threshold_response(
                &request, &pks, &sks, &enc_key, &mut rng,
            );

            let client = Client::new_solana(trusted(&pks), TEST_PARAM, None);
            let released = client
                .process_user_decryption_resp_solana(&request, &enc_key, &dec_key, &agg_resp)
                .expect("the threshold fixture reconstructs");
            assert_eq!(released, vec![expected]);

            write_stable_solana_vector(
                crate::consts::TEST_SOLANA_THRESHOLD_WASM_TRANSCRIPT_PATH,
                &stable_solana_vector(&request, &pks, &agg_resp, &dec_key, &released),
            );
        }
    }
}
