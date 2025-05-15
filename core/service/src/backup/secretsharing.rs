use rand::{CryptoRng, Rng};
use threshold_fhe::{
    algebra::{galois_rings::degree_4::ResiduePolyF4Z64, structure_traits::Ring},
    execution::sharing::shamir::{InputOp, RevealOp, ShamirSharings},
};

use super::error::BackupError;

// This is an implementation of PKCS7, taken from
// aws_lc_rs/cipher/padded.rs
mod pkcs7 {
    use crate::backup::error::BackupError;

    const MAX_CIPHER_BLOCK_LEN: usize = 32;

    pub(crate) fn add_padding<InOut>(
        block_len: usize,
        in_out: &mut InOut,
    ) -> Result<(), BackupError>
    where
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        let mut padding_buffer = [0u8; MAX_CIPHER_BLOCK_LEN];

        let in_out_len = in_out.as_mut().len();
        // This implements PKCS#7 padding scheme, used by aws-lc if we were using EVP_CIPHER API's
        let remainder = in_out_len % block_len;
        let padding_size = block_len - remainder;
        let v: u8 = padding_size
            .try_into()
            .map_err(|_| BackupError::PaddingError)?;
        padding_buffer.fill(v);
        // Possible heap allocation here :(
        in_out.extend(padding_buffer[0..padding_size].iter());
        Ok(())
    }

    pub(crate) fn remove_padding(
        block_len: usize,
        in_out: &mut [u8],
    ) -> Result<&mut [u8], BackupError> {
        let block_size: u8 = block_len
            .try_into()
            .map_err(|_| BackupError::PaddingError)?;

        if in_out.is_empty() || in_out.len() < block_len {
            return Err(BackupError::PaddingError);
        }

        let padding: u8 = in_out[in_out.len() - 1];
        if padding == 0 || padding > block_size {
            return Err(BackupError::PaddingError);
        }

        for item in in_out.iter().skip(in_out.len() - padding as usize) {
            if *item != padding {
                return Err(BackupError::PaddingError);
            }
        }

        let final_len = in_out.len() - padding as usize;
        Ok(&mut in_out[0..final_len])
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use proptest::prelude::*;

        proptest! {
            #[test]
            fn padding_sunshine(msg: Vec<u8>) {
                for block_len in [16, 32] {
                    let mut in_out = msg.clone();
                    add_padding(block_len, &mut in_out).unwrap();
                    let out = remove_padding(block_len, &mut in_out).unwrap().to_vec();
                    assert_eq!(out, msg);
                }
            }

            #[test]
            fn padding_wrong_data(msg: Vec<u8>) {
                for block_len in [16, 32] {
                    let mut in_out = msg.clone();
                    add_padding(block_len, &mut in_out).unwrap();

                    let l = in_out.len();
                    in_out[l - 1] ^= 1;
                    let err = remove_padding(block_len, &mut in_out).unwrap_err();
                    assert!(matches!(err, BackupError::PaddingError));
                }
            }
        }
    }
}

/// Note, normally we'll serialize a ThresholdFheKeys and then call this function.
pub(crate) fn share<R>(
    rng: &mut R,
    secrets: &[u8],
    n: usize,
    t: usize,
) -> Result<Vec<ShamirSharings<ResiduePolyF4Z64>>, BackupError>
where
    R: Rng + CryptoRng,
{
    let mut in_out = secrets.to_vec();
    let block_len = ResiduePolyF4Z64::BIT_LENGTH / 8;
    debug_assert_eq!(block_len, 32);
    pkcs7::add_padding(block_len, &mut in_out)?;
    debug_assert_eq!(in_out.len() % block_len, 0);

    let mut buffer = [0u8; ResiduePolyF4Z64::BIT_LENGTH / 8];
    let mut out = vec![];
    for i in 0..(in_out.len() / block_len) {
        buffer.copy_from_slice(&in_out[i * block_len..(i + 1) * block_len]);
        let x = ResiduePolyF4Z64::from_bytes(&buffer);
        let share = ShamirSharings::share(rng, x, n, t)
            .map_err(|e| BackupError::SharingError(e.to_string()))?;
        out.push(share);
    }

    Ok(out)
}

pub(crate) fn reconstruct(
    shares: Vec<ShamirSharings<ResiduePolyF4Z64>>,
    t: usize,
) -> Result<Vec<u8>, BackupError> {
    let mut combined = vec![];
    for current_block in shares {
        let opened = current_block
            .reconstruct(t)
            .map_err(|e| BackupError::ReconstructError(e.to_string()))?;
        let mut buf = opened.to_byte_vec();
        combined.append(&mut buf);
    }

    let block_len = ResiduePolyF4Z64::BIT_LENGTH / 8;
    debug_assert_eq!(block_len, 32);
    let res = pkcs7::remove_padding(block_len, &mut combined)?;

    Ok(res.to_vec())
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use proptest::prelude::*;
    use rand::SeedableRng;
    use threshold_fhe::{algebra::structure_traits::One, execution::sharing::share::Share};

    use super::*;

    const NTS: [(usize, usize); 3] = [(4, 1), (7, 3), (10, 4)];

    #[test]
    fn sharing_wrong_params() {
        let mut rng = AesRng::seed_from_u64(42);
        let secret = vec![0u8];
        let err = share(&mut rng, &secret, 4, 4 + 1).unwrap_err();
        assert!(matches!(err, BackupError::SharingError(..)));
    }

    proptest! {
        #[test]
        fn sharing_no_error(seed: u64, secret: Vec<u8>) {
            let mut rng = AesRng::seed_from_u64(seed);

            for (n, t) in NTS {
                let shares = share(&mut rng, &secret, n, t).unwrap();
                let result = reconstruct(shares, t).unwrap();

                assert_eq!(result, secret);
            }
        }

        #[test]
        fn sharing_missing_shares(seed: u64, secret: Vec<u8>, first_shares: bool) {
            let mut rng = AesRng::seed_from_u64(seed);

            for (n, t) in NTS {
                let mut shares = share(&mut rng, &secret, n, t).unwrap();

                // drop the first or last t shares from every block
                for block in &mut shares {
                    if first_shares {
                        let _ = block.shares.drain((t + 1)..);
                    } else {
                        let _ = block.shares.drain(..(n - t - 1));
                    }
                    assert_eq!(block.shares.len(), t + 1);
                }

                let result = reconstruct(shares, t).unwrap();

                assert_eq!(result, secret);
            }
        }

        #[test]
        fn sharing_wrong_shares(seed: u64, secret: Vec<u8>) {
            let mut rng = AesRng::seed_from_u64(seed);

            for (n, t) in NTS {
                let mut shares = share(&mut rng, &secret, n, t).unwrap();

                for block in &mut shares {
                    for i in n-t..n {
                        let owner = block.shares[i].owner();
                        let bad_value = block.shares[i].value() + ResiduePolyF4Z64::ONE;
                        block.shares[i] = Share::new(owner, bad_value);
                    }
                }

                // our scheme does not support error correction
                let err = reconstruct(shares, t).unwrap_err();
                assert!(matches!(err, BackupError::ReconstructError(..)));
            }
        }

        #[test]
        fn sharing_too_many_missing_shares(seed: u64, secret: Vec<u8>) {
            let mut rng = AesRng::seed_from_u64(seed);

            for (n, t) in NTS {
                let mut shares = share(&mut rng, &secret, n, t).unwrap();

                for block in &mut shares {
                    // t is not enough to reconstruct, need at least t + 1
                    let _ = block.shares.split_off(t);
                }

                let err = reconstruct(shares, t).unwrap_err();
                assert!(matches!(err, BackupError::ReconstructError(..)));
            }
        }
    }
}
