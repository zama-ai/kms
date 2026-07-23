//! ECDSA over secp256k1 signing backend.
//!
//! This is the home of the low-level `internal_sign` / `internal_verify_sig` /
//! `check_normalized` primitives (re-exported from
//! [`crate::cryptography::signatures`] so existing callers keep their import
//! paths), plus the byte-oriented [`sign`] / [`verify`] used by the
//! multi-scheme dispatcher. It stays outside the `non-wasm` gate because the
//! ECDSA path is exercised by the in-browser wasm verifier.

use crate::anyhow_tracked;
use crate::cryptography::error::CryptographyError;
use crate::cryptography::signatures::{PrivateSigKey, PublicSigKey, SIG_SIZE, Signature};
use ::signature::{Signer, Verifier};
use hashing::DomainSep;

/// Compute the signature on message based on the server's signing key.
///
/// Returns the [`Signature`]. Concretely r || s.
pub(crate) fn internal_sign<T>(
    dsep: &DomainSep,
    msg: &T,
    server_sig_key: &PrivateSigKey,
) -> anyhow::Result<Signature>
where
    T: AsRef<[u8]> + ?Sized,
{
    let sig: k256::ecdsa::Signature = server_sig_key
        .raw_signing_key()
        .try_sign(&[dsep, msg.as_ref()].concat())?;
    // Normalize s value to ensure a consistent signature and protect against malleability
    let sig = sig.normalize_s().unwrap_or(sig);
    Ok(Signature { sig })
}

/// Verify a plain signature.
///
/// Returns Ok if the signature is ok.
pub(crate) fn internal_verify_sig<T>(
    dsep: &DomainSep,
    payload: &T,
    sig: &Signature,
    server_verf_key: &PublicSigKey,
) -> anyhow::Result<()>
where
    T: AsRef<[u8]> + ?Sized,
{
    // Check that the signature is normalized
    check_normalized(sig)?;

    // Verify signature
    server_verf_key
        .raw_verifying_key()
        .verify(&[dsep, payload.as_ref()].concat(), &sig.sig)
        .map_err(|e| anyhow_tracked(e.to_string()))
}

/// Check if a signature is normalized in "low S" form as described in
/// [BIP 0062: Dealing with Malleability][1].
///
/// [1]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
pub(crate) fn check_normalized(sig: &Signature) -> Result<(), CryptographyError> {
    if sig.sig.normalize_s().is_some() {
        return Err(CryptographyError::VerificationError(format!(
            "Signature {:X?} is not normalized",
            sig.sig
        )));
    };
    Ok(())
}

/// Sign `dsep ‖ msg`, returning the normalized 64-byte `r‖s` encoding.
pub fn sign(dsep: &DomainSep, msg: &[u8], sk: &PrivateSigKey) -> anyhow::Result<Vec<u8>> {
    Ok(internal_sign(dsep, msg, sk)?.sig.to_vec())
}

/// Verify a 64-byte `r‖s` ECDSA signature over `dsep ‖ msg`.
///
/// Also enforces low-S normalization (via [`internal_verify_sig`]).
pub fn verify(dsep: &DomainSep, msg: &[u8], sig: &[u8], vk: &PublicSigKey) -> anyhow::Result<()> {
    if sig.len() != SIG_SIZE {
        anyhow::bail!("expected {SIG_SIZE}-byte ECDSA signature, got {}", sig.len());
    }
    let ecdsa_sig = k256::ecdsa::Signature::from_slice(sig)
        .map_err(|e| anyhow::anyhow!("could not decode ECDSA signature: {e}"))?;
    internal_verify_sig(dsep, msg, &Signature { sig: ecdsa_sig }, vk)
}

/// Derive the ECDSA verification key from the signing key.
pub fn verifying_key(sk: &PrivateSigKey) -> PublicSigKey {
    sk.verf_key()
}
