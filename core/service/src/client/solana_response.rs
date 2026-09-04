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
use kms_grpc::rpc_types::PlaintextReceiver;
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
        // The expected link is the Solana binding recomputed above, not the EVM EIP-712 link the
        // validation would otherwise derive from the parsed request.
        let trusted_ctx = UserDecTrustedValidationContext::new_with_expected_link(
            trusted_signers,
            &parsed,
            &request.response_domain,
            None,
            expected_link.clone(),
        )
        .map_err(
            |error| SolanaUserDecryptionResponseError::InconsistentShares {
                reason: error.to_string(),
            },
        )?;
        let consistent = validate_user_decrypt_responses(&trusted_ctx, &accepted_responses)
            .map_err(
                |error| SolanaUserDecryptionResponseError::InconsistentShares {
                    reason: error.to_string(),
                },
            )?;
        let (_invariants, authenticated, _rejected) = consistent.into_parts();
        let surviving: BTreeSet<u32> = authenticated
            .iter()
            .map(|response| response.role.one_based() as u32)
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
    let receiver = PlaintextReceiver::Solana(receiver_id);

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
