//! A signature made under several schemes at once.
//!
//! A composite signature is worth no more than the guarantee that *every* one of
//! its parts is present. Dropping the post-quantum half of an ECDSA+ML-DSA pair
//! must not leave something a verifier accepts, or the hedge the composite was
//! built for is gone.
//!
//! # Relation to the IETF composite signature draft
//!
//! The IETF supports exactly one legacy scheme and ML-DSA, whereas we want more
//! flexibility and hence will support both a single scheme choice and more than 2.
//! Our construction follows `draft-ietf-lamps-pq-composite-sigs` in its form but
//! does not interoperate with the draft.
//!
//! Concretely we transform a message to be signed, M, to another one, M', as follows:
//! ```text
//! M' = COMPOSITE_PREFIX ‖ scheme count ‖ scheme tags ‖ safe_serialize(M)
//! ```
//! In the IETF draft the format is as follows:
//! ```text
//! M' = COMPOSITE_PREFIX || Label || len(ctx) || ctx || Hash( M )
//! ```
//!
//! Each backend prepends the domain separator, so a component signs
//! `dsep ‖ preimage`. The parts of the draft map onto this encoding:
//!
//! - **[`COMPOSITE_PREFIX`]** marks the bytes as a composite
//!   preimage, so no component reads as a signature of another construction. The
//!   node's ECDSA key also signs EIP-712 messages and the frozen signcryption
//!   layout, so the draft's prohibition on key reuse does not hold here. The
//!   draft names the Prefix as what covers that case.
//! - **Label** is the scheme count and the scheme tags, together with the name
//!   the message type carries inside `safe_serialize(M)`. The draft's Label names
//!   one registered combination of schemes and one usage. Ours names the set of
//!   schemes, which the draft fixes per combination, and the usage, which the
//!   message type states: `SigncryptionSignedPayload` for a signcryption,
//!   `KeygenSignedPayload` or `CrsSignedPayload` for a result, and so on.
//! - **ctx** is the domain separator. A [`DomainSep`] is exactly 8 bytes, so the
//!   length prefix the draft puts on ctx is not necessary.
//! - **Hash(M)** is the message itself. The draft pre-hashes the message and
//!   assumes that the hash resists collisions. The message keeps the same
//!   unforgeability argument without that assumption.
//!
//! The message is a type rather than bytes, and this module serializes it. That
//! is what lets the type name do the Label's second job, and it means every value
//! the message binds is framed by `safe_serialize` rather than concatenated. A
//! caller cannot pass bytes that name no usage, or declare a usage that does not
//! match what it signs.
//!
//! # What the encoding gives, and what it does not
//!
//! - Verification is all or nothing. [`verify_uniform`] requires the set of
//!   entries to equal the set of keys, then checks every entry.
//! - Every component of a [`sign_uniform`] signature names its scheme set and the
//!   type of what it signs, so none of them moves to another set, to another
//!   usage, or out of the composite.
//! - The composite is unforgeable if any one component is, as in the draft.
//! - The ECDSA entry of [`sign_result_entries`] is the deliberate exception. It
//!   signs the EIP-712 hash, so it binds neither the set nor the usage, and it
//!   moves freely between them.
#[cfg(feature = "non-wasm")]
use super::identity::NodeSigningIdentity;
use super::typed_signature::StoredTypedSignature;
use super::verf_key_set::VerfKeySet;
use super::{Signature, SigningError, SigningSchemeType, unified_verify};
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::zeroizing_writer::ZeroizingWriter;
use hashing::DomainSep;
use serde::Serialize;
use std::io::Write;
use tfhe::Versionize;
use tfhe::named::Named;
use tfhe::safe_serialization::safe_serialize;
use zeroize::Zeroizing;

/// The marker every composite preimage starts with.
pub const COMPOSITE_PREFIX: &[u8; 32] = b"ZamaKmsCompositeSignature2026_v1";

/// Sort `schemes` into canonical order and drop duplicates.
///
/// Errors when `schemes` is empty.
pub fn canonical_schemes(
    schemes: &[SigningSchemeType],
) -> Result<Vec<SigningSchemeType>, SigningError> {
    let mut canonical = schemes.to_vec();
    canonical.sort_unstable();
    canonical.dedup();
    if canonical.is_empty() {
        return Err(SigningError::EmptySchemeSet);
    }
    Ok(canonical)
}

/// The unambiguous byte encoding of `schemes`, for use inside a signed preimage.
///
/// Length-prefixed, so no set's encoding is a prefix of a longer set's.
fn canonical_scheme_bytes(schemes: &[SigningSchemeType]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 4 * schemes.len());
    // Bounded by the number of known schemes, so the cast cannot truncate.
    out.extend_from_slice(&(schemes.len() as u32).to_le_bytes());
    for scheme in schemes {
        out.extend_from_slice(&scheme.tag());
    }
    out
}

/// Render `schemes` for an error message.
fn render_schemes(schemes: &[SigningSchemeType]) -> String {
    format!(
        "{{{}}}",
        schemes
            .iter()
            .map(|scheme| scheme.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// The bytes one component of a composite signature covers.
///
/// The layout and the reason for each part are in the module documentation.
///
/// `schemes` is canonicalised here, so callers may pass it in any order and
/// still agree on the bytes.
///
/// The result may hold a secret, because `payload` may. It is wiped on drop, and
/// so is every buffer used to build it.
pub fn scheme_bound_preimage<T>(
    schemes: &[SigningSchemeType],
    payload: &T,
) -> Result<Zeroizing<Vec<u8>>, SigningError>
where
    T: Serialize + Versionize + Named,
{
    let schemes = canonical_schemes(schemes)?;
    let mut out = ZeroizingWriter::new();
    let framed = |e: std::io::Error| SigningError::Serialization(e.to_string());
    out.write_all(COMPOSITE_PREFIX).map_err(framed)?;
    out.write_all(&canonical_scheme_bytes(&schemes))
        .map_err(framed)?;
    safe_serialize(payload, &mut out, SAFE_SER_SIZE_LIMIT)
        .map_err(|e| SigningError::Serialization(e.to_string()))?;
    Ok(out.into_inner())
}

/// The schemes `entries` were made under, in the order they are stored.
pub fn entry_schemes(entries: &[StoredTypedSignature]) -> Vec<SigningSchemeType> {
    entries.iter().map(|entry| entry.scheme).collect()
}

/// Sign `payload` under every scheme in `schemes`, each over the same bytes.
///
/// The entries come back ordered by scheme, with no duplicate scheme, which is
/// the shape [`verify_uniform`] requires. `verify_uniform` has to be called with
/// an equal `payload` of the same type.
#[cfg(feature = "non-wasm")]
pub fn sign_uniform<T>(
    identity: &NodeSigningIdentity,
    schemes: &[SigningSchemeType],
    dsep: &DomainSep,
    payload: &T,
) -> Result<Vec<StoredTypedSignature>, SigningError>
where
    T: Serialize + Versionize + Named,
{
    let schemes = canonical_schemes(schemes)?;
    identity.ensure_supported(&schemes)?;
    let preimage = scheme_bound_preimage(&schemes, payload)?;
    schemes
        .iter()
        .map(|&scheme| {
            identity
                .unified_sign_with(scheme, dsep, &preimage)
                .map(|signature| StoredTypedSignature {
                    scheme,
                    signature: signature.to_bytes(),
                })
        })
        .collect()
}

/// Check every signature in `entries` against `keys`, having first checked that
/// they were made under exactly the schemes `keys` holds keys for.
///
/// Every signature must verify. `entries` is untrusted: it may come straight
/// from storage or from the network, so its shape is checked here rather than
/// assumed.
pub fn verify_uniform<T>(
    entries: &[StoredTypedSignature],
    keys: &VerfKeySet,
    dsep: &DomainSep,
    payload: &T,
) -> Result<(), SigningError>
where
    T: Serialize + Versionize + Named,
{
    let expected = keys.schemes();
    // The scheme-set comparison happens before any cryptography, so a composite
    // signature presented with one of its parts removed, reordered or repeated
    // is rejected for being the wrong shape. `expected` is canonical and
    // non-empty by the `VerfKeySet` invariants.
    let schemes = entry_schemes(entries);
    if schemes != expected {
        return Err(SigningError::UnexpectedSchemeSet {
            expected: render_schemes(&expected),
            actual: render_schemes(&schemes),
        });
    }
    let preimage = scheme_bound_preimage(&schemes, payload)?;
    for entry in entries {
        let signature = Signature::new(entry.scheme, entry.signature.clone());
        // Cannot fail: `schemes` equals `keys.schemes()` on this path.
        unified_verify(dsep, &preimage, &signature, keys.require(entry.scheme)?)?;
    }
    Ok(())
}

/// The per-scheme signatures of a *result*: a keygen, CRS, preprocessing or
/// decryption response.
///
/// **A scheme determines what its signature covers.** This mapping is the
/// contract every verifier relies on, so it lives here alone:
///
/// - [`SigningSchemeType::Ecdsa256k1`] signs `eip712_hash`, producing the
///   recoverable, on-chain-verifiable signature the fhevm contracts verify. It is
///   byte-identical to the result's deprecated `external_signature`, so that
///   `signatures` still carries it once that field goes away. The two match
///   because the caller derives both from one hash and ECDSA signing here is
///   deterministic.
/// - Every other scheme signs [`scheme_bound_preimage`] over `payload`, so it
///   commits to the scheme set and the payload type as well as to the payload.
///
/// The ECDSA entry is therefore the one component that binds neither the set nor
/// the payload type, and a verifier cannot read it as evidence of either. EIP-712
/// is an EVM and secp256k1 construction that a post-quantum scheme has no reason
/// to be bound to, so the asymmetry stays. It costs less than it appears to,
/// because `ensure_requested_verified` requires every requested scheme to verify,
/// so a set-bound entry pins the set as soon as a verifier asks for more than
/// ECDSA. A request for ECDSA alone, which is what an empty request resolves to,
/// pins nothing.
///
/// `schemes` may be given in any order; the entries come back ordered by
/// scheme.
#[cfg(feature = "non-wasm")]
pub fn sign_result_entries<T>(
    identity: &NodeSigningIdentity,
    schemes: &[SigningSchemeType],
    dsep: &DomainSep,
    eip712_hash: &[u8],
    payload: &T,
) -> Result<Vec<StoredTypedSignature>, SigningError>
where
    T: Serialize + Versionize + Named,
{
    if schemes.is_empty() {
        return Ok(Vec::new());
    }
    let schemes = canonical_schemes(schemes)?;
    // Every non-ECDSA entry commits to the scheme set, so one cannot be lifted
    // out of a larger response and presented as a complete smaller one.
    let signed = scheme_bound_preimage(&schemes, payload)?;
    schemes
        .iter()
        .map(|&scheme| {
            let signature = match scheme {
                SigningSchemeType::Ecdsa256k1 => {
                    let hash = alloy_primitives::B256::try_from(eip712_hash).map_err(|_| {
                        SigningError::Sign(format!(
                            "EIP-712 signing hash must be 32 bytes, got {}",
                            eip712_hash.len()
                        ))
                    })?;
                    crate::cryptography::signing::ecdsa::eip712_sign_hash(identity.ecdsa(), &hash)
                        .map_err(|e| SigningError::Sign(e.to_string()))?
                }
                _ => identity
                    .unified_sign_with(scheme, dsep, &signed)?
                    .to_bytes(),
            };
            Ok(StoredTypedSignature { scheme, signature })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::signatures::{SigningSchemeType, gen_sig_keys};
    use crate::cryptography::signing::test_support::seeded_identity;
    use crate::vault::storage::tests::TestType;
    use aes_prng::AesRng;
    use rand::SeedableRng;

    const DSEP: &DomainSep = b"COMPSIGT";

    /// A stand-in for the signed payload types the real callers pass.
    fn msg() -> TestType {
        TestType { i: 4711 }
    }

    fn pair() -> Vec<SigningSchemeType> {
        vec![SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa87]
    }

    fn setup(seed: u64) -> (NodeSigningIdentity, VerfKeySet, Vec<SigningSchemeType>) {
        let mut rng = AesRng::seed_from_u64(seed);
        let identity = seeded_identity(&mut rng);
        let schemes = pair();
        let keys = VerfKeySet::from_identity(&identity, &schemes).unwrap();
        (identity, keys, schemes)
    }

    /// A signature verifies under the key set that made it, and under no other
    /// party's.
    #[test]
    fn round_trip_sunshine() {
        let (identity, keys, schemes) = setup(1);
        let sig = sign_uniform(&identity, &schemes, DSEP, &msg()).unwrap();
        assert_eq!(entry_schemes(&sig), schemes);
        verify_uniform(&sig, &keys, DSEP, &msg()).unwrap();

        let (_, other_keys, _) = setup(7);
        assert!(verify_uniform(&sig, &other_keys, DSEP, &msg()).is_err());
    }

    /// Removing a signature must not leave something that verifies under the
    /// remaining scheme, and a key set that names fewer schemes than the
    /// signature must not verify it by skipping the ones it has no key for.
    #[test]
    fn a_stripped_signature_is_rejected() {
        let (identity, keys, schemes) = setup(2);
        let sig = sign_uniform(&identity, &schemes, DSEP, &msg()).unwrap();

        // Drop the ML-DSA half and relabel the set as ECDSA-only
        let stripped = vec![sig[0].clone()];

        // Against the original policy it is the wrong scheme set...
        assert!(matches!(
            verify_uniform(&stripped, &keys, DSEP, &msg()),
            Err(SigningError::UnexpectedSchemeSet { .. })
        ));

        // ...and a verifier downgraded all the way to an ECDSA-only key set —
        // the only way to ask for less, now that the key set *is* the policy —
        // still rejects it: the surviving signature covers a preimage naming the
        // *pair*, which does not match the single-scheme preimage.
        let ecdsa_only =
            VerfKeySet::from_identity(&identity, &[SigningSchemeType::Ecdsa256k1]).unwrap();
        assert!(verify_uniform(&stripped, &ecdsa_only, DSEP, &msg()).is_err());

        // The same mismatch from the other side: the *whole* pair signature
        // against that ECDSA-only key set is refused for its shape rather than
        // verified on the one entry the set holds a key for.
        assert!(matches!(
            verify_uniform(&sig, &ecdsa_only, DSEP, &msg()),
            Err(SigningError::UnexpectedSchemeSet { .. })
        ));
    }

    /// An entry list that is reordered, repeats a scheme, or is empty is refused.
    #[test]
    fn a_non_canonical_entry_list_is_rejected() {
        let (identity, keys, schemes) = setup(3);
        let sig = sign_uniform(&identity, &schemes, DSEP, &msg()).unwrap();

        let mut reversed = sig.clone();
        reversed.reverse();
        let duplicated = vec![sig[0].clone(), sig[0].clone()];

        for (case, entries) in [
            ("reversed", reversed),
            ("duplicated", duplicated),
            ("empty", Vec::new()),
        ] {
            assert!(
                matches!(
                    verify_uniform(&entries, &keys, DSEP, &msg()),
                    Err(SigningError::UnexpectedSchemeSet { .. })
                ),
                "a {case} entry list was not rejected"
            );
        }
    }

    /// Every constituent signature has to verify; one bad one fails the whole.
    #[test]
    fn one_tampered_signature_fails_the_composite() {
        let (identity, keys, schemes) = setup(4);
        let base = sign_uniform(&identity, &schemes, DSEP, &msg()).unwrap();

        for index in 0..base.len() {
            let mut tampered = base.clone();
            tampered[index].signature[0] ^= 0x01;
            assert!(
                verify_uniform(&tampered, &keys, DSEP, &msg()).is_err(),
                "tampering with signature {index} was not detected"
            );
        }
    }

    #[test]
    fn a_tampered_message_or_dsep_fails() {
        let (identity, keys, schemes) = setup(5);
        let sig = sign_uniform(&identity, &schemes, DSEP, &msg()).unwrap();
        assert!(verify_uniform(&sig, &keys, DSEP, &TestType { i: 4712 }).is_err());
        assert!(verify_uniform(&sig, &keys, b"OTHERDSP", &msg()).is_err());
    }

    /// An identity with no root seed can only do ECDSA, so asking it for the
    /// composite pair fails rather than producing a one-scheme signature.
    #[test]
    fn a_seedless_identity_cannot_sign_the_composite() {
        let mut rng = AesRng::seed_from_u64(9);
        let identity = NodeSigningIdentity::ecdsa_only(gen_sig_keys(&mut rng).1);
        assert!(matches!(
            sign_uniform(&identity, &pair(), DSEP, &msg()),
            Err(SigningError::MissingRootSeed(_))
        ));
    }

    /// The result shape splits by scheme: ECDSA signs the EIP-712 hash, every
    /// other scheme signs the scheme-set-bound payload.
    #[test]
    fn result_entries_split_ecdsa_from_the_rest() {
        let mut rng = AesRng::seed_from_u64(20);
        let identity = seeded_identity(&mut rng);
        let schemes = [
            SigningSchemeType::Ecdsa256k1,
            SigningSchemeType::Ed25519,
            SigningSchemeType::MlDsa65,
        ];
        let eip712_hash = [0x11u8; 32];
        let payload = msg();
        let bound = scheme_bound_preimage(&schemes, &payload).unwrap();

        let entries =
            sign_result_entries(&identity, &schemes, DSEP, &eip712_hash, &payload).unwrap();
        assert_eq!(entries.len(), 3);

        for entry in &entries {
            if entry.scheme == SigningSchemeType::Ecdsa256k1 {
                // Recoverable EIP-712 signature: 65 bytes, and not a signature
                // over the payload.
                assert_eq!(entry.signature.len(), 65);
                continue;
            }
            let vk = identity.unified_verifying_key(entry.scheme).unwrap();
            let sig = Signature::new(entry.scheme, entry.signature.clone());
            unified_verify(DSEP, &bound, &sig, &vk).unwrap_or_else(|e| {
                panic!("{:?} should sign the bound payload: {e}", entry.scheme)
            });
            // ...and neither the serialized payload alone nor the EIP-712 hash.
            let mut bare = Vec::new();
            tfhe::safe_serialization::safe_serialize(&payload, &mut bare, SAFE_SER_SIZE_LIMIT)
                .unwrap();
            assert!(unified_verify(DSEP, &bare, &sig, &vk).is_err());
            assert!(unified_verify(DSEP, &eip712_hash, &sig, &vk).is_err());
        }
    }

    /// Result entries use the same ordering convention as [`sign_uniform`]:
    /// by scheme, duplicate-free, whatever order the request arrived in.
    #[test]
    fn result_entries_are_ordered_by_scheme() {
        let mut rng = AesRng::seed_from_u64(21);
        let identity = seeded_identity(&mut rng);
        let requested = [
            SigningSchemeType::MlDsa65,
            SigningSchemeType::Ecdsa256k1,
            SigningSchemeType::MlDsa65,
            SigningSchemeType::Ed25519,
        ];
        let canonical = canonical_schemes(&requested).unwrap();

        let entries =
            sign_result_entries(&identity, &requested, DSEP, &[0x11u8; 32], &msg()).unwrap();

        assert_eq!(
            entries.iter().map(|e| e.scheme).collect::<Vec<_>>(),
            canonical
        );
    }

    /// No schemes requested means no per-scheme entries, which is why this
    /// returns a plain list of entries.
    #[test]
    fn result_entries_tolerate_an_empty_request() {
        let mut rng = AesRng::seed_from_u64(21);
        let identity = seeded_identity(&mut rng);
        assert!(
            sign_result_entries(&identity, &[], DSEP, &[0u8; 32], &msg())
                .unwrap()
                .is_empty()
        );
    }

    /// Distinct scheme sets give distinct preimages, which is what stops a
    /// signature crossing between them.
    #[test]
    fn preimages_separate_scheme_sets() {
        let single = vec![SigningSchemeType::Ecdsa256k1];
        assert_ne!(
            scheme_bound_preimage(&single, &msg()).unwrap(),
            scheme_bound_preimage(&pair(), &msg()).unwrap()
        );

        // The count in front of the tags is what separates a set from a longer
        // one starting with it, so the shorter set's encoding appears nowhere in
        // the longer set's preimage.
        let pair_preimage = scheme_bound_preimage(&pair(), &msg()).unwrap();
        let single_scheme_bytes = canonical_scheme_bytes(&single);
        assert!(
            !pair_preimage
                .windows(single_scheme_bytes.len())
                .any(|window| window == single_scheme_bytes)
        );
    }

    /// Canonicalisation normalises order and duplicates, and refuses the empty
    /// set — the case that would make "every scheme verified" vacuous.
    #[test]
    fn canonicalisation_normalises_and_refuses_empty() {
        let reordered = [
            SigningSchemeType::MlDsa87,
            SigningSchemeType::Ecdsa256k1,
            SigningSchemeType::MlDsa87,
        ];
        assert_eq!(canonical_schemes(&reordered).unwrap(), pair());

        // So callers may pass any order and still agree on the signed bytes.
        assert_eq!(
            scheme_bound_preimage(&reordered, &msg()).unwrap(),
            scheme_bound_preimage(&pair(), &msg()).unwrap()
        );

        assert!(matches!(
            canonical_schemes(&[]),
            Err(SigningError::EmptySchemeSet)
        ));
    }
}
