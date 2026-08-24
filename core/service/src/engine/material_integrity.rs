//! Digest primitives for checking published key material against a recorded digest.
//!
//! These are the lowest-level building blocks of material integrity: pure functions over raw
//! bytes with no storage, no key metadata and no orchestration. They live below both the
//! storage layer and the startup checks in
//! [`crate::engine::storage_material_verification`], so either can call them without depending
//! on boot logic.
//!
//! Every function takes the **raw bytes as they were stored** rather than a deserialized value.
//! Re-serializing a value can produce different bytes than the digest was originally computed
//! over — a tfhe format change between releases is enough — which would report intact material
//! as corrupt. Callers must therefore hash what they read, not what they parsed.

use crate::engine::base::{DSEP_PUBDATA_CRS, DSEP_PUBDATA_KEY};
use hashing::hash_element;

pub(crate) const ERR_SERVER_KEY_DIGEST_MISMATCH: &str = "Server key digest mismatch";
pub(crate) const ERR_PUBLIC_KEY_DIGEST_MISMATCH: &str = "Public key digest mismatch";
pub(crate) const ERR_COMPRESSED_KEYSET_DIGEST_MISMATCH: &str =
    "Compressed xof keyset digest mismatch";
pub(crate) const ERR_CRS_DIGEST_MISMATCH: &str = "CRS digest mismatch";

/// Verify key digests using raw bytes from storage.
/// This avoids re-serializing the keys, which would produce different bytes
/// if there was a version upgrade since the original digest was computed.
pub(crate) fn verify_key_digest_from_bytes(
    server_key_bytes: &[u8],
    public_key_bytes: &[u8],
    expected_server_key_digest: &[u8],
    expected_public_key_digest: &[u8],
) -> anyhow::Result<()> {
    verify_server_key_digest_from_bytes(server_key_bytes, expected_server_key_digest)?;
    verify_public_key_digest_from_bytes(public_key_bytes, expected_public_key_digest)
}

/// Verify a standalone server key digest using raw bytes from storage.
pub(crate) fn verify_server_key_digest_from_bytes(
    server_key_bytes: &[u8],
    expected_digest: &[u8],
) -> anyhow::Result<()> {
    let actual_digest = hash_element(&DSEP_PUBDATA_KEY, server_key_bytes);
    if actual_digest != expected_digest {
        anyhow::bail!(ERR_SERVER_KEY_DIGEST_MISMATCH);
    }
    Ok(())
}

/// Verify a standalone public key digest using raw bytes from storage.
/// This avoids re-serializing the key, which would produce different bytes
/// if there was a version upgrade since the original digest was computed.
pub(crate) fn verify_public_key_digest_from_bytes(
    public_key_bytes: &[u8],
    expected_digest: &[u8],
) -> anyhow::Result<()> {
    let actual_digest = hash_element(&DSEP_PUBDATA_KEY, public_key_bytes);
    if actual_digest != expected_digest {
        anyhow::bail!(ERR_PUBLIC_KEY_DIGEST_MISMATCH);
    }
    Ok(())
}

/// Verify compressed key digest using raw bytes from storage.
/// This avoids re-serializing the keys, which would produce different bytes
/// if there was a version upgrade since the original digest was computed.
pub(crate) fn verify_compressed_key_digest_from_bytes(
    compressed_keyset_bytes: &[u8],
    expected_digest: &[u8],
) -> anyhow::Result<()> {
    let actual_digest = hash_element(&DSEP_PUBDATA_KEY, compressed_keyset_bytes);
    if actual_digest != expected_digest {
        anyhow::bail!(ERR_COMPRESSED_KEYSET_DIGEST_MISMATCH);
    }
    Ok(())
}

/// Verify CRS digest using raw bytes from storage.
/// This avoids re-serializing the CRS, which would produce different bytes
/// if there was a version upgrade since the original digest was computed.
pub(crate) fn verify_crs_digest_from_bytes(
    crs_bytes: &[u8],
    expected_digest: &[u8],
) -> anyhow::Result<()> {
    let actual_digest = hash_element(&DSEP_PUBDATA_CRS, crs_bytes);
    if actual_digest != expected_digest {
        anyhow::bail!(ERR_CRS_DIGEST_MISMATCH);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_KEY: &[u8] = b"server key bytes";
    const PUBLIC_KEY: &[u8] = b"public key bytes";

    fn key_digest(bytes: &[u8]) -> Vec<u8> {
        hash_element(&DSEP_PUBDATA_KEY, bytes)
    }

    fn crs_digest(bytes: &[u8]) -> Vec<u8> {
        hash_element(&DSEP_PUBDATA_CRS, bytes)
    }

    #[test]
    fn key_pair_digests_accept_matching_bytes() {
        verify_key_digest_from_bytes(
            SERVER_KEY,
            PUBLIC_KEY,
            &key_digest(SERVER_KEY),
            &key_digest(PUBLIC_KEY),
        )
        .expect("digests computed from the same bytes must match");
    }

    #[test]
    fn key_pair_digests_reject_wrong_server_key() {
        let err = verify_key_digest_from_bytes(
            b"other server key",
            PUBLIC_KEY,
            &key_digest(SERVER_KEY),
            &key_digest(PUBLIC_KEY),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains(ERR_SERVER_KEY_DIGEST_MISMATCH),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn key_pair_digests_reject_wrong_public_key() {
        let err = verify_key_digest_from_bytes(
            SERVER_KEY,
            b"other public key",
            &key_digest(SERVER_KEY),
            &key_digest(PUBLIC_KEY),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains(ERR_PUBLIC_KEY_DIGEST_MISMATCH),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn public_key_digest_accepts_matching_and_rejects_altered_bytes() {
        let expected = key_digest(PUBLIC_KEY);
        verify_public_key_digest_from_bytes(PUBLIC_KEY, &expected).expect("matching digest");

        let err = verify_public_key_digest_from_bytes(b"altered", &expected).unwrap_err();
        assert!(
            err.to_string().contains(ERR_PUBLIC_KEY_DIGEST_MISMATCH),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn compressed_keyset_digest_accepts_matching_and_rejects_altered_bytes() {
        let keyset = b"compressed keyset bytes";
        let expected = key_digest(keyset);
        verify_compressed_key_digest_from_bytes(keyset, &expected).expect("matching digest");

        let err = verify_compressed_key_digest_from_bytes(b"altered", &expected).unwrap_err();
        assert!(
            err.to_string()
                .contains(ERR_COMPRESSED_KEYSET_DIGEST_MISMATCH),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn crs_digest_accepts_matching_and_rejects_altered_bytes() {
        let crs = b"crs bytes";
        let expected = crs_digest(crs);
        verify_crs_digest_from_bytes(crs, &expected).expect("matching digest");

        let err = verify_crs_digest_from_bytes(b"altered", &expected).unwrap_err();
        assert!(
            err.to_string().contains(ERR_CRS_DIGEST_MISMATCH),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn key_and_crs_domain_separators_do_not_interchange() {
        // The same bytes hash differently under each domain separator, so a CRS digest must not
        // validate as a key digest and vice versa.
        let bytes = b"same bytes, different purpose";
        assert_ne!(key_digest(bytes), crs_digest(bytes));

        assert!(verify_public_key_digest_from_bytes(bytes, &crs_digest(bytes)).is_err());
        assert!(verify_crs_digest_from_bytes(bytes, &key_digest(bytes)).is_err());
    }

    #[test]
    fn digest_of_wrong_length_is_rejected() {
        // A truncated digest, as a partially written metadata blob could leave behind.
        let mut truncated = key_digest(PUBLIC_KEY);
        truncated.pop();
        let err = verify_public_key_digest_from_bytes(PUBLIC_KEY, &truncated).unwrap_err();
        assert!(
            err.to_string().contains(ERR_PUBLIC_KEY_DIGEST_MISMATCH),
            "unexpected error: {err}"
        );
    }
}
