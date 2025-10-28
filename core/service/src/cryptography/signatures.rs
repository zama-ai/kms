use crate::{
    anyhow_tracked,
    cryptography::{
        error::CryptographyError,
        internal_crypto_types::{PrivateSigKey, PublicSigKey, Signature},
    },
};
use ::signature::{Signer, Verifier};
use threshold_fhe::hashing::DomainSep;

/// Compute the signature on message based on the server's signing key.
///
/// Returns the [Signature]. Concretely r || s.
pub(crate) fn internal_sign<T>(
    dsep: &DomainSep,
    msg: &T,
    server_sig_key: &PrivateSigKey,
) -> anyhow::Result<Signature>
where
    T: AsRef<[u8]> + ?Sized,
{
    let sig: k256::ecdsa::Signature = server_sig_key
        .sk()
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
        .pk()
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

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use rand::SeedableRng;

    use crate::cryptography::{
        internal_crypto_types::{gen_sig_keys, Signature},
        signatures::{internal_sign, internal_verify_sig},
    };

    #[test]
    fn plain_signing() {
        let mut rng = AesRng::seed_from_u64(1);
        let (server_verf_key, server_sig_key) = gen_sig_keys(&mut rng);
        let msg = "A relatively long message that we wish to be able to later validate".as_bytes();
        let sig = internal_sign(b"TESTTEST", &msg, &server_sig_key).unwrap();
        assert!(internal_verify_sig(b"TESTTEST", &msg.to_vec(), &sig, &server_verf_key).is_ok());
    }

    #[test]
    fn bad_signature() {
        let mut rng = AesRng::seed_from_u64(42);
        let (server_verf_key, server_sig_key) = gen_sig_keys(&mut rng);
        let msg = "Some message".as_bytes();
        let sig = internal_sign(b"TESTTEST", &msg, &server_sig_key).unwrap();
        let wrong_msg = "Some message...longer".as_bytes();
        let res = internal_verify_sig(b"TESTTEST", &wrong_msg, &sig, &server_verf_key);
        // unwrapping fails
        assert!(res.is_err());
    }

    #[test]
    fn bad_dsep() {
        let mut rng = AesRng::seed_from_u64(42);
        let (server_verf_key, server_sig_key) = gen_sig_keys(&mut rng);
        let msg = "Some message".as_bytes();
        let sig = internal_sign(b"TESTTEST", &msg, &server_sig_key).unwrap();
        let res = internal_verify_sig(
            b"TESTTES_", // wrong domain separator
            &msg,
            &sig,
            &server_verf_key,
        );
        // unwrapping fails
        assert!(res.is_err());
    }

    #[test]
    fn unnormalized_signature() {
        let mut rng = AesRng::seed_from_u64(42);
        let (verf_key, sig_key) = gen_sig_keys(&mut rng);
        let msg = "Some message".as_bytes();

        let sig = internal_sign(b"TESTTEST", &msg, &sig_key).unwrap();
        // Ensure the signature is normalized
        let internal_sig = sig.sig.normalize_s().unwrap_or(sig.sig);
        // Ensure the signature is ok
        assert!(internal_verify_sig(b"TESTTEST", &msg, &sig, &verf_key).is_ok());
        // Undo normalization
        let bad_sig = Signature {
            sig: k256::ecdsa::Signature::from_scalars(internal_sig.r(), internal_sig.s().negate())
                .unwrap(),
        };
        let res = internal_verify_sig(b"TESTTEST", &msg, &bad_sig, &verf_key);
        // unwrapping fails
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("is not normalized"));
    }
}
