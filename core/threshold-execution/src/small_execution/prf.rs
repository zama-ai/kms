use crate::constants::{CHI_XOR_CONSTANT, PHI_XOR_CONSTANT};
use aes::Aes128;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
pub use algebra::PRSSConversions;
use algebra::galois_rings::common::ResiduePoly;
use algebra::structure_traits::{BaseRing, Ring};
use error_utils::anyhow_error_and_log;
use serde::{Deserialize, Serialize};
use tfhe_versionable::{Versionize, VersionsDispatch};
use threshold_types::commitment::KEY_BYTE_LEN;
use threshold_types::session_id::SessionId;

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum PrfKeyVersions {
    V0(PrfKey),
}

/// key for the PRF
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq, Versionize)]
#[versionize(PrfKeyVersions)]
pub struct PrfKey(pub [u8; 16]);

/// helper function that compute bit-wise xor of two byte arrays in place (overwriting the first argument `arr1`)
/// TODO maybe not the best place for this function
pub(crate) fn xor_u8_arr_in_place(arr1: &mut [u8; KEY_BYTE_LEN], arr2: &[u8; KEY_BYTE_LEN]) {
    for i in 0..KEY_BYTE_LEN {
        arr1[i] ^= arr2[i];
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PhiAes {
    aes: Aes128,
}

impl PhiAes {
    pub fn new(key: &PrfKey, sid: SessionId) -> Self {
        // initialize AES cipher here to do the key schedule just once.
        let mut phi_key = key.0;

        // XOR key with 2 to ensure domain separation, since we're using the same key for two kinds of PRSS and a PRZS
        phi_key[0] ^= PHI_XOR_CONSTANT;

        // XOR sid into key
        xor_u8_arr_in_place(&mut phi_key, &sid.to_le_bytes());

        PhiAes {
            aes: Aes128::new(&phi_key.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ChiAes {
    aes: Aes128,
}

impl ChiAes {
    pub fn new(key: &PrfKey, sid: SessionId) -> Self {
        // initialize AES cipher here to do the key schedule just once.
        let mut chi_key = key.0;
        // XOR key with 1 to ensure domain separation, since we're using the same key for two kinds of PRSS and a PRZS
        chi_key[0] ^= CHI_XOR_CONSTANT;

        // XOR sid into key
        xor_u8_arr_in_place(&mut chi_key, &sid.to_le_bytes());

        ChiAes {
            aes: Aes128::new(&chi_key.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PsiAes {
    aes: Aes128,
}

impl PsiAes {
    pub fn new(key: &PrfKey, sid: SessionId) -> Self {
        // initialize AES cipher here to do the key schedule just once.
        let mut psi_key = key.0;

        // deliberately no tweak/constant XOR here as we use the key in psi as-is.

        // XOR sid into key
        xor_u8_arr_in_place(&mut psi_key, &sid.to_le_bytes());

        PsiAes {
            aes: Aes128::new(&psi_key.into()),
        }
    }
}

//NOTE: I BELIEVE WE NEVER NEED PRSS-MASK TO GENERATE MASK BIGGER THAN 2^126 EVEN FOR BGV
//AFAICT, ONLY USED IN BGV DDEC WITH BD1<Q1 AND Q1 IS 94BIT LONG
/// Function Phi that generates bounded randomness for PRSS-Mask.Next(), evaluated over the
/// contiguous counter range `[start, start + count)`.
///
/// This currently assumes that the value Bd_1 in the NIST doc is smaller than 2^126. A single
/// `encrypt_blocks` call is issued so the AES-NI backend can pipeline the blocks, and the
/// (loop-invariant) bounds are checked only once for the whole range.
pub(crate) fn phi_range(
    pa: &PhiAes,
    start: u128,
    count: usize,
    bd1: u128,
) -> anyhow::Result<Vec<i128>> {
    if count == 0 {
        return Ok(Vec::new());
    }

    // we currently assume that Bd1 is at most 126 bits large, so we only need a single block of
    // AES per value and can fit the result in an i128.
    // check that bd1 is small enough to not cause overflow of the result
    if bd1 > (1 << 126) {
        return Err(anyhow_error_and_log(
            "Bd1 must be at most 2^126 to not overflow, but is larger".to_string(),
        ));
    }

    // the highest counter touched; since the range is contiguous and increasing, checking it
    // bounds the whole range so nothing gets overwritten by setting the block-counter byte below.
    // saturating_add so an out-of-range `start` can never wrap past the guard below (it would
    // saturate to u128::MAX and trip it) instead of panicking in debug / wrapping in release.
    let max_ctr = start.saturating_add(count as u128 - 1);
    if max_ctr >= 1 << 120 {
        return Err(anyhow_error_and_log(format!(
            "ctr in phi must be smaller than 2^120 but was {max_ctr}."
        )));
    }

    // number of AES blocks per value, currently limited to 1. See NOTE above.
    let v = (((bd1 + 1) as f32).log2() / 128_f32).ceil() as u32;
    debug_assert_eq!(v, 1);

    // TODO iterate over blocks from 0..v here if we ever need Bd1 > 2^126
    let mut blocks = Vec::with_capacity(count);
    for k in 0..count {
        let mut ctr_bytes = (start + k as u128).to_le_bytes();
        ctr_bytes[15] = 0; // v - the block counter, currently fixed to zero
        let block = Array::from(ctr_bytes);
        blocks.push(block);
    }

    // single pipelined AES call over the whole range
    pa.aes.encrypt_blocks(&mut blocks);

    let modulus = 2 * bd1;
    let neg_bd1 = -(bd1 as i128);
    let mut res = Vec::with_capacity(count);
    for block in blocks {
        let out = u128::from_le_bytes(block.into());
        // compute output as -BD1 + (AES (mod 2*BD1)), a uniform random value in [-BD1 .. BD1)
        res.push(neg_bd1 + (out % modulus) as i128);
    }
    Ok(res)
}

/// Number of AES blocks encrypted per `encrypt_blocks` call in psi/chi. Sized to the AES-NI /
/// ARMv8 parallel width so a single batch covers the common degree-8 case, while a stack buffer
/// (rather than a per-call heap allocation) holds the blocks.
const AES_BATCH: usize = 8;

/// Function Psi that generates bounded randomness for PRSS.next()
pub(crate) fn psi<Z: Ring + PRSSConversions>(pa: &PsiAes, ctr: u128) -> anyhow::Result<Z> {
    // check ctr is smaller 2^112, so nothing gets overwritten by setting the indices below
    if ctr >= 1 << 112 {
        return Err(anyhow_error_and_log(format!(
            "ctr in psi must be smaller than 2^112 but was {ctr}."
        )));
    }

    //Compute v = ceil(log(q)/128) if q power of 2, v = (dist + log(q)/128) else
    let num_u128_base_ring = Z::NUM_BITS_STAT_SEC_BASE_RING.div_ceil(128);
    let n_blocks = Z::EXTENSION_DEGREE * num_u128_base_ring;
    let base = ctr.to_le_bytes();

    // Block (i, block_ctr) carries the dimension index i and the block counter in its MSBs; the
    // outputs are laid out as coefs[i * num_u128_base_ring + block_ctr] (i outer, block_ctr inner).
    // Encrypt in fixed stack-buffer batches so the AES backend still pipelines, without a per-call
    // heap allocation for the block buffer.
    let mut coefs = vec![0_u128; n_blocks];
    let mut buf = [Array::from([0u8; 16]); AES_BATCH];
    let mut start = 0;
    while start < n_blocks {
        let chunk = (n_blocks - start).min(AES_BATCH);
        for (slot, block) in buf[..chunk].iter_mut().enumerate() {
            let idx = start + slot;
            let mut ctr_bytes = base;
            ctr_bytes[15] = (idx % num_u128_base_ring) as u8; // v - the block counter
            ctr_bytes[14] = (idx / num_u128_base_ring) as u8; // i - the dimension index
            block.copy_from_slice(&ctr_bytes);
        }
        pa.aes.encrypt_blocks(&mut buf[..chunk]);
        for (slot, block) in buf[..chunk].iter().enumerate() {
            coefs[start + slot] = u128::from_le_bytes((*block).into());
        }
        start += chunk;
    }

    Ok(Z::from_u128_chunks(coefs))
}

/// Concrete fast path for [`psi`] over the residue-polynomial rings used by PRSS.
#[allow(dead_code)] // Alternate implementation kept next to `psi` for review and benchmarking.
pub(crate) fn psi_2<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    pa: &PsiAes,
    ctr: u128,
) -> anyhow::Result<ResiduePoly<Z, EXTENSION_DEGREE>> {
    // check ctr is smaller 2^112, so nothing gets overwritten by setting the indices below
    if ctr >= 1 << 112 {
        return Err(anyhow_error_and_log(format!(
            "ctr in psi must be smaller than 2^112 but was {ctr}."
        )));
    }

    // These are the concrete PRSS residue-ring invariants this non-general fast path relies on.
    assert_eq!(
        Z::NUM_BITS_STAT_SEC_BASE_RING.div_ceil(128),
        1,
        "psi_2 assumes one AES block per base-ring coefficient"
    );
    assert!(
        EXTENSION_DEGREE <= AES_BATCH,
        "psi_2 assumes the whole residue polynomial fits in one AES batch"
    );

    let mut ctr_bytes = ctr.to_le_bytes();
    ctr_bytes[15] = 0; // v - the block counter, fixed to zero for the concrete residue rings
    let mut buf = [Array::from([0u8; 16]); AES_BATCH];

    for (i, block) in buf[..EXTENSION_DEGREE].iter_mut().enumerate() {
        ctr_bytes[14] = i as u8; // i - the dimension index
        *block = Array::from(ctr_bytes);
    }

    pa.aes.encrypt_blocks(&mut buf[..EXTENSION_DEGREE]);

    let mut coefs = [Z::ZERO; EXTENSION_DEGREE];
    let mut i = 0;
    while i < EXTENSION_DEGREE {
        coefs[i] = Z::from_u128(u128::from_le_bytes(buf[i].into()));
        coefs[i + 1] = Z::from_u128(u128::from_le_bytes(buf[i + 1].into()));
        i += 2;
    }

    Ok(ResiduePoly { coefs })
}

#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use super::*;

    /// Reusable AES state for benchmarking the Psi PRF variants.
    #[derive(Clone)]
    pub struct PsiAesHandle {
        aes: PsiAes,
    }

    /// Reusable AES state for benchmarking the Chi PRF variants.
    #[derive(Clone)]
    pub struct ChiAesHandle {
        aes: ChiAes,
    }

    impl PsiAesHandle {
        /// Builds a Psi AES handle with the same key schedule as production PRSS.
        pub fn new(key: &PrfKey, sid: SessionId) -> Self {
            Self {
                aes: PsiAes::new(key, sid),
            }
        }
    }

    impl ChiAesHandle {
        /// Builds a Chi AES handle with the same key schedule as production PRZS.
        pub fn new(key: &PrfKey, sid: SessionId) -> Self {
            Self {
                aes: ChiAes::new(key, sid),
            }
        }
    }

    /// Runs the original generic Psi implementation.
    pub fn psi_original<Z: Ring + PRSSConversions>(
        pa: &PsiAesHandle,
        ctr: u128,
    ) -> anyhow::Result<Z> {
        super::psi(&pa.aes, ctr)
    }

    /// Runs the concrete residue-polynomial Psi fast path.
    pub fn psi_2<Z: BaseRing, const EXTENSION_DEGREE: usize>(
        pa: &PsiAesHandle,
        ctr: u128,
    ) -> anyhow::Result<ResiduePoly<Z, EXTENSION_DEGREE>> {
        super::psi_2(&pa.aes, ctr)
    }

    /// Runs the original generic Chi implementation.
    pub fn chi_original<Z: Ring + PRSSConversions>(
        pa: &ChiAesHandle,
        ctr: u128,
        j: u8,
    ) -> anyhow::Result<Z> {
        super::chi(&pa.aes, ctr, j)
    }

    /// Runs the concrete residue-polynomial Chi fast path.
    pub fn chi_2<Z: BaseRing, const EXTENSION_DEGREE: usize>(
        pa: &ChiAesHandle,
        ctr: u128,
        j: u8,
    ) -> anyhow::Result<ResiduePoly<Z, EXTENSION_DEGREE>> {
        super::chi_2(&pa.aes, ctr, j)
    }
}

/// Function Chi that generates bounded randomness for PRZS.next()
/// This currently assumes that q = 2^128
pub(crate) fn chi<Z: Ring + PRSSConversions>(pa: &ChiAes, ctr: u128, j: u8) -> anyhow::Result<Z> {
    // check ctr is smaller 2^104, so nothing gets overwritten by setting the indices below
    if ctr >= 1 << 104 {
        return Err(anyhow_error_and_log(format!(
            "ctr in chi must be smaller than 2^104 but was {ctr}."
        )));
    }

    //Compute v = ceil(log(q)/128) if q power of 2, v = (dist + log(q)/128) else
    let num_u128_base_ring = Z::NUM_BITS_STAT_SEC_BASE_RING.div_ceil(128);
    let n_blocks = Z::EXTENSION_DEGREE * num_u128_base_ring;
    let base = ctr.to_le_bytes();

    // Block (i, block_ctr) carries the dimension index i, threshold index j and block counter; the
    // outputs are laid out as coefs[i * num_u128_base_ring + block_ctr] (i outer, block_ctr inner).
    // Encrypt in fixed stack-buffer batches so the AES backend still pipelines, without a per-call
    // heap allocation for the block buffer.
    let mut coefs = vec![0_u128; n_blocks];
    let mut buf = [Array::from([0u8; 16]); AES_BATCH];
    let mut start = 0;
    while start < n_blocks {
        let chunk = (n_blocks - start).min(AES_BATCH);
        for (slot, block) in buf[..chunk].iter_mut().enumerate() {
            let idx = start + slot;
            let mut ctr_bytes = base;
            ctr_bytes[15] = (idx % num_u128_base_ring) as u8; // v - the block counter
            ctr_bytes[14] = (idx / num_u128_base_ring) as u8; // i - the dimension index
            ctr_bytes[13] = j; // j - the threshold index
            block.copy_from_slice(&ctr_bytes);
        }
        pa.aes.encrypt_blocks(&mut buf[..chunk]);
        for (slot, block) in buf[..chunk].iter().enumerate() {
            coefs[start + slot] = u128::from_le_bytes((*block).into());
        }
        start += chunk;
    }

    Ok(Z::from_u128_chunks(coefs))
}

/// Concrete fast path for [`chi`] over the residue-polynomial rings used by PRZS.
#[allow(dead_code)] // Alternate implementation kept next to `chi` for review and benchmarking.
pub(crate) fn chi_2<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    pa: &ChiAes,
    ctr: u128,
    j: u8,
) -> anyhow::Result<ResiduePoly<Z, EXTENSION_DEGREE>> {
    // check ctr is smaller 2^104, so nothing gets overwritten by setting the indices below
    if ctr >= 1 << 104 {
        return Err(anyhow_error_and_log(format!(
            "ctr in chi must be smaller than 2^104 but was {ctr}."
        )));
    }

    assert_eq!(
        Z::NUM_BITS_STAT_SEC_BASE_RING.div_ceil(128),
        1,
        "chi_2 assumes one AES block per base-ring coefficient"
    );
    assert!(
        EXTENSION_DEGREE <= AES_BATCH,
        "chi_2 assumes the whole residue polynomial fits in one AES batch"
    );

    let mut ctr_bytes = ctr.to_le_bytes();
    ctr_bytes[13] = j; // j - the threshold index
    ctr_bytes[15] = 0; // v - the block counter, fixed to zero for the concrete residue rings
    let mut buf = [Array::from([0u8; 16]); AES_BATCH];

    for (i, block) in buf[..EXTENSION_DEGREE].iter_mut().enumerate() {
        ctr_bytes[14] = i as u8; // i - the dimension index
        *block = Array::from(ctr_bytes);
    }

    pa.aes.encrypt_blocks(&mut buf[..EXTENSION_DEGREE]);

    let mut coefs = [Z::ZERO; EXTENSION_DEGREE];
    let mut i = 0;
    while i < EXTENSION_DEGREE {
        coefs[i] = Z::from_u128(u128::from_le_bytes(buf[i].into()));
        coefs[i + 1] = Z::from_u128(u128::from_le_bytes(buf[i + 1].into()));
        i += 2;
    }

    Ok(ResiduePoly { coefs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{B_SWITCH_SQUASH, LOG_B_SWITCH_SQUASH, STATSEC};
    use algebra::base_ring::{Z64, Z128};
    use algebra::galois_rings::degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128};

    /// Single-value convenience wrapper over [`phi_range`] used by the phi tests.
    fn phi(pa: &PhiAes, ctr: u128, bd1: u128) -> anyhow::Result<i128> {
        Ok(phi_range(pa, ctr, 1, bd1)?[0])
    }

    #[test]
    fn test_phi() {
        let key = PrfKey([123_u8; 16]);
        let aes = PhiAes::new(&key, SessionId::from(0));
        let mut prev = 0_i128;

        // test for B_SWITCH_SQUASH * 2^STATSEC  (currently even, so we can count bits using ilog2)
        for ctr in 0..100 {
            let bd1 = B_SWITCH_SQUASH * (1 << STATSEC);
            let res = phi(&aes, ctr, bd1).unwrap();
            let log = res.abs().ilog2();
            assert!(log < (LOG_B_SWITCH_SQUASH + STATSEC));
            assert!(-(bd1 as i128) <= res);
            assert!(bd1 as i128 > res);
            assert_ne!(prev, res);
            prev = res;
        }

        // test for some odd bound value
        let odd_bound = (1 << 113) + 23;
        for ctr in 0..100 {
            let res = phi(&aes, ctr, odd_bound).unwrap();
            assert!(-(odd_bound as i128) <= res);
            assert!(odd_bound as i128 > res);
            assert_ne!(prev, res);
            prev = res;
        }

        assert_eq!(
            phi(&aes, 0, B_SWITCH_SQUASH).unwrap(),
            phi(&aes, 0, B_SWITCH_SQUASH).unwrap()
        );

        let aes_2 = PhiAes::new(&key, SessionId::from(2));
        assert_ne!(
            phi(&aes, 0, B_SWITCH_SQUASH).unwrap(),
            phi(&aes_2, 0, B_SWITCH_SQUASH).unwrap()
        );

        let err_overflow = phi(&aes, 0, 1 << 127).unwrap_err().to_string();
        assert!(err_overflow.contains("Bd1 must be at most 2^126 to not overflow, but is larger"));

        let err_ctr = phi(&aes, 1 << 123, B_SWITCH_SQUASH)
            .unwrap_err()
            .to_string();
        assert!(err_ctr.contains(
            "ctr in phi must be smaller than 2^120 but was 10633823966279326983230456482242756608."
        ));
    }

    fn test_psi<Z: Ring + PRSSConversions>() {
        let key = PrfKey([23_u8; 16]);
        let aes = PsiAes::new(&key, SessionId::from(0));
        assert_ne!(psi::<Z>(&aes, 0).unwrap(), psi(&aes, 1).unwrap());
        assert_eq!(psi::<Z>(&aes, 0).unwrap(), psi(&aes, 0).unwrap());

        let aes_2 = PsiAes::new(&key, SessionId::from(2));
        assert_ne!(psi::<Z>(&aes, 0).unwrap(), psi(&aes_2, 0).unwrap());

        let err_ctr = psi::<Z>(&aes, 1 << 123).unwrap_err().to_string();
        assert!(err_ctr.contains(
            "ctr in psi must be smaller than 2^112 but was 10633823966279326983230456482242756608."
        ));
    }

    #[test]
    fn test_pi_z128() {
        test_psi::<ResiduePolyF4Z128>();
    }

    #[test]
    fn test_pi_64() {
        test_psi::<ResiduePolyF4Z64>();
    }

    fn test_psi_2<Z: BaseRing, const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z, EXTENSION_DEGREE>: Ring + PRSSConversions,
    {
        let key = PrfKey([23_u8; 16]);
        let aes = testing::PsiAesHandle::new(&key, SessionId::from(0));

        for ctr in [0, 1, 42, (1 << 112) - 1] {
            assert_eq!(
                testing::psi_original::<ResiduePoly<Z, EXTENSION_DEGREE>>(&aes, ctr).unwrap(),
                testing::psi_2::<Z, EXTENSION_DEGREE>(&aes, ctr).unwrap()
            );
        }

        let err_ctr = testing::psi_2::<Z, EXTENSION_DEGREE>(&aes, 1 << 112)
            .unwrap_err()
            .to_string();
        assert!(err_ctr.contains(
            "ctr in psi must be smaller than 2^112 but was 5192296858534827628530496329220096."
        ));
    }

    #[test]
    fn test_psi_2_f4_z128_matches_psi() {
        test_psi_2::<Z128, 4>();
    }

    #[test]
    fn test_psi_2_f4_z64_matches_psi() {
        test_psi_2::<Z64, 4>();
    }

    #[test]
    fn test_psi_2_f8_z128_matches_psi() {
        test_psi_2::<Z128, 8>();
    }

    #[test]
    fn test_psi_2_f8_z64_matches_psi() {
        test_psi_2::<Z64, 8>();
    }

    fn test_chi<Z: Ring + PRSSConversions>() {
        let key = PrfKey([23_u8; 16]);
        let aes = ChiAes::new(&key, SessionId::from(0));
        assert_ne!(chi::<Z>(&aes, 0, 0).unwrap(), chi(&aes, 1, 0).unwrap());
        assert_ne!(chi::<Z>(&aes, 0, 0).unwrap(), chi(&aes, 0, 1).unwrap());
        assert_eq!(chi::<Z>(&aes, 0, 0).unwrap(), chi(&aes, 0, 0).unwrap());

        let aes_2 = ChiAes::new(&key, SessionId::from(2));
        assert_ne!(chi::<Z>(&aes, 0, 0).unwrap(), chi(&aes_2, 0, 0).unwrap());

        let err_ctr = chi::<Z>(&aes, 1 << 123, 0).unwrap_err().to_string();
        assert!(err_ctr.contains(
            "ctr in chi must be smaller than 2^104 but was 10633823966279326983230456482242756608."
        ));
    }

    #[test]
    fn test_chi_z128() {
        test_chi::<ResiduePolyF4Z128>();
    }

    #[test]
    fn test_chi_z64() {
        test_chi::<ResiduePolyF4Z64>();
    }

    fn test_chi_2<Z: BaseRing, const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z, EXTENSION_DEGREE>: Ring + PRSSConversions,
    {
        let key = PrfKey([23_u8; 16]);
        let aes = testing::ChiAesHandle::new(&key, SessionId::from(0));

        for ctr in [0, 1, 42, (1 << 104) - 1] {
            for j in [0, 1, 7] {
                assert_eq!(
                    testing::chi_original::<ResiduePoly<Z, EXTENSION_DEGREE>>(&aes, ctr, j)
                        .unwrap(),
                    testing::chi_2::<Z, EXTENSION_DEGREE>(&aes, ctr, j).unwrap()
                );
            }
        }

        let err_ctr = testing::chi_2::<Z, EXTENSION_DEGREE>(&aes, 1 << 104, 0)
            .unwrap_err()
            .to_string();
        assert!(err_ctr.contains(
            "ctr in chi must be smaller than 2^104 but was 20282409603651670423947251286016."
        ));
    }

    #[test]
    fn test_chi_2_f4_z128_matches_chi() {
        test_chi_2::<Z128, 4>();
    }

    #[test]
    fn test_chi_2_f4_z64_matches_chi() {
        test_chi_2::<Z64, 4>();
    }

    #[test]
    fn test_chi_2_f8_z128_matches_chi() {
        test_chi_2::<Z128, 8>();
    }

    #[test]
    fn test_chi_2_f8_z64_matches_chi() {
        test_chi_2::<Z64, 8>();
    }

    /// check that all three PRFs cause different encryptions, even when initialized from the same key
    fn test_all_prfs_differ<Z: Ring + PRSSConversions>() {
        // init PRFs with identical key
        let key = PrfKey([123_u8; 16]);
        let chiaes = ChiAes::new(&key, SessionId::from(0));
        let psiaes = PsiAes::new(&key, SessionId::from(0));
        let phiaes = PhiAes::new(&key, SessionId::from(0));

        // test direct PRF calls
        assert_ne!(chi::<Z>(&chiaes, 0, 0).unwrap(), psi(&psiaes, 0).unwrap());

        // initialize identical 128-bit block
        let mut chi_block = Array::from([42u8; 16]);
        let mut psi_block = Array::from([42u8; 16]);
        let mut phi_block = Array::from([42u8; 16]);

        // encrypt with different PRFs
        chiaes.aes.encrypt_block(&mut chi_block);
        psiaes.aes.encrypt_block(&mut psi_block);
        phiaes.aes.encrypt_block(&mut phi_block);

        // encryptions must differ
        assert_ne!(chi_block, psi_block);
        assert_ne!(chi_block, phi_block);
        assert_ne!(phi_block, psi_block);
    }

    #[test]
    fn test_all_prfs_differ_z128() {
        test_all_prfs_differ::<ResiduePolyF4Z128>();
    }

    #[test]
    fn test_all_prfs_differ_z64() {
        test_all_prfs_differ::<ResiduePolyF4Z64>();
    }
}
