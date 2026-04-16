//! Shared utilities for ZK proof-of-knowledge operations.
//!
//! This module is shared between the `non-threshold-zk-pok-kat` binary and the
//! `non-threshold_tfhe-zk-pok_{speed,memory}` benchmarks.  It factors out
//! everything that is not specific to KAT file I/O or criterion/peak-alloc
//! harness setup.

use rand::RngCore;
use tfhe::XofSeed;
use tfhe::core_crypto::commons::math::random::RandomGenerator;
use tfhe_csprng::generators::SoftwareRandomGenerator;
use tfhe_zk_pok::curve_api::Bls12_446;
use tfhe_zk_pok::proofs::ComputeLoad;
use tfhe_zk_pok::proofs::pke_v2::{
    PrivateCommit, Proof as ProofV2, PublicCommit, PublicParams, VerificationPairingMode, commit,
    crs_gen, prove, verify,
};
use threshold_execution::tfhe_internals::parameters::DKGParams;
use threshold_execution::zk::ceremony::max_num_messages;
use threshold_execution::zk::constants::ZK_DEFAULT_MAX_NUM_BITS;

/// Number of bytes in the proof metadata field.
pub const METADATA_LEN: usize = 40;

/// Number of MSB zero-padding bits used in the PKE scheme.
pub const PADDED_BIT_COUNT: u64 = 1;

/// ZK PKE parameters derived from a [`DKGParams`] instance.
#[derive(Copy, Clone)]
pub struct PkeZkParams {
    pub d: usize,
    pub k: usize,
    pub b: u64,
    pub q: u64,
    pub t: u64,
    pub msbs_zero_padding_bit_count: u64,
}

/// A ciphertext produced by [`ZkTestcase::encrypt`].
pub struct ZkCiphertext {
    pub c1: Vec<i64>,
    pub c2: Vec<i64>,
}

/// A set of plaintext / noise / key samples used to build ZK proof inputs.
pub struct ZkTestcase {
    pub a: Vec<i64>,
    pub e1: Vec<i64>,
    pub e2: Vec<i64>,
    pub r: Vec<i64>,
    pub m: Vec<i64>,
    pub b: Vec<i64>,
    pub metadata: [u8; METADATA_LEN],
    pub s: Vec<i64>,
}

pub fn nist_seeded_rng(domain: [u8; 8]) -> RandomGenerator<SoftwareRandomGenerator> {
    // Seed is fixed for reproducibility
    RandomGenerator::<SoftwareRandomGenerator>::new(XofSeed::new_u128(1995, domain))
}

/// Derive ZK PKE parameters from a [`DKGParams`] instance.
pub fn nist_pke_params_from_dkg(params: DKGParams) -> PkeZkParams {
    let pke_params = params
        .get_params_basics_handle()
        .get_compact_pk_enc_params();
    let lwe_dim = pke_params.encryption_lwe_dimension;
    let noise_distribution = pke_params.encryption_noise_distribution;
    let max_num_cleartexts = max_num_messages(&pke_params, ZK_DEFAULT_MAX_NUM_BITS).unwrap();
    // Our plaintext modulus does not account for the padding bit.
    let mut plaintext_modulus = pke_params.message_modulus.0 * pke_params.carry_modulus.0;
    plaintext_modulus *= 2;

    let (d, k, b, q, t) = tfhe::zk::CompactPkeCrs::prepare_crs_parameters(
        lwe_dim,
        max_num_cleartexts,
        noise_distribution,
        pke_params.ciphertext_modulus,
        plaintext_modulus,
        tfhe::zk::CompactPkeZkScheme::V2,
    )
    .unwrap();

    PkeZkParams {
        d: d.0,
        k: k.0,
        b,
        q,
        t,
        msbs_zero_padding_bit_count: PADDED_BIT_COUNT,
    }
}

/// Polynomial multiplication in Z\[X\]/(X^d + 1) with reversed second operand,
/// to compute the body of the ciphertext during encryption.
pub fn polymul_rev(a: &[i64], b: &[i64]) -> Vec<i64> {
    assert_eq!(a.len(), b.len());
    let d = a.len();
    let mut c = vec![0i64; d];

    for i in 0..d {
        for j in 0..d {
            if i + j < d {
                c[i + j] = c[i + j].wrapping_add(a[i].wrapping_mul(b[d - j - 1]));
            } else {
                c[i + j - d] = c[i + j - d].wrapping_sub(a[i].wrapping_mul(b[d - j - 1]));
            }
        }
    }

    c
}

// Testcase helpers mostly copy pasted from tfhe-zk-pok
impl ZkTestcase {
    /// Sample a fresh testcase from `rng` according to `params`.
    pub fn generate(
        rng: &mut RandomGenerator<SoftwareRandomGenerator>,
        params: PkeZkParams,
    ) -> Self {
        let PkeZkParams {
            d,
            k,
            b,
            q: _q,
            t,
            msbs_zero_padding_bit_count,
        } = params;

        let effective_cleartext_t = t >> msbs_zero_padding_bit_count;
        let a = (0..d).map(|_| rng.next_u64() as i64).collect::<Vec<_>>();
        let s = (0..d)
            .map(|_| (rng.next_u64() % 2) as i64)
            .collect::<Vec<_>>();
        let e = (0..d)
            .map(|_| (rng.next_u64() % (2 * b)) as i64 - b as i64)
            .collect::<Vec<_>>();
        let e1 = (0..d)
            .map(|_| (rng.next_u64() % (2 * b)) as i64 - b as i64)
            .collect::<Vec<_>>();
        let e2 = (0..k)
            .map(|_| (rng.next_u64() % (2 * b)) as i64 - b as i64)
            .collect::<Vec<_>>();
        let r = (0..d)
            .map(|_| (rng.next_u64() % 2) as i64)
            .collect::<Vec<_>>();
        let m = (0..k)
            .map(|_| (rng.next_u64() % effective_cleartext_t) as i64)
            .collect::<Vec<_>>();
        let b_vec = polymul_rev(&a, &s)
            .into_iter()
            .zip(e.iter())
            .map(|(x, e): (i64, &i64)| x.wrapping_add(*e))
            .collect::<Vec<_>>();

        let mut metadata = [0u8; METADATA_LEN];
        rng.fill_bytes(&mut metadata);

        Self {
            a,
            e1,
            e2,
            r,
            m,
            b: b_vec,
            metadata,
            s,
        }
    }

    /// Encrypt the testcase's plaintext under the testcase's public key.
    ///
    /// Also asserts that decryption of the produced ciphertext recovers the
    /// original plaintext, so any bug in the arithmetic is caught early.
    pub fn encrypt(&self, params: PkeZkParams) -> ZkCiphertext {
        let PkeZkParams {
            d,
            k,
            b: _b,
            q,
            t,
            msbs_zero_padding_bit_count: _,
        } = params;

        let delta = {
            let q = if q == 0 { 1i128 << 64 } else { q as i128 };
            (q / t as i128) as u64
        };

        let c1 = polymul_rev(&self.a, &self.r)
            .into_iter()
            .zip(self.e1.iter())
            .map(|(x, e1)| x.wrapping_add(*e1))
            .collect::<Vec<_>>();

        let mut c2 = vec![0i64; k];
        for (i, c2) in c2.iter_mut().enumerate() {
            let mut dot = 0i64;
            for j in 0..d {
                let b = if i + j < d {
                    self.b[d - j - i - 1]
                } else {
                    self.b[2 * d - j - i - 1].wrapping_neg()
                };
                dot = dot.wrapping_add(self.r[d - j - 1].wrapping_mul(b));
            }

            *c2 = dot
                .wrapping_add(self.e2[i])
                .wrapping_add((delta * self.m[i] as u64) as i64);
        }

        // Sanity-check: decrypting must recover the original message.
        let mut m_roundtrip = vec![0i64; k];
        for i in 0..k {
            let mut dot = 0i128;
            for j in 0..d {
                let c = if i + j < d {
                    c1[d - j - i - 1]
                } else {
                    c1[2 * d - j - i - 1].wrapping_neg()
                };
                dot += self.s[d - j - 1] as i128 * c as i128;
            }

            let q = if q == 0 { 1i128 << 64 } else { q as i128 };
            let val = ((c2[i] as i128).wrapping_sub(dot)) * t as i128;
            let div = val.div_euclid(q);
            let rem = val.rem_euclid(q);
            let result = div as i64 + (rem > (q / 2)) as i64;
            m_roundtrip[i] = result.rem_euclid(params.t as i64);
        }

        assert_eq!(self.m, m_roundtrip);

        ZkCiphertext { c1, c2 }
    }
}

/// Deterministically generates a CRS for `params`.
pub fn nist_gen_crs(params: DKGParams) -> PublicParams<Bls12_446> {
    let pke_params = nist_pke_params_from_dkg(params);
    let mut rng = nist_seeded_rng(*b"ZK_CRS__");
    nist_gen_crs_from_params(&pke_params, &mut rng)
}

/// Generate a CRS from pre-computed [`PkeZkParams`] and a caller-supplied RNG.
pub fn nist_gen_crs_from_params(
    pke_params: &PkeZkParams,
    rng: &mut RandomGenerator<SoftwareRandomGenerator>,
) -> PublicParams<Bls12_446> {
    crs_gen::<Bls12_446>(
        pke_params.d,
        pke_params.k,
        pke_params.b,
        pke_params.q,
        pke_params.t,
        pke_params.msbs_zero_padding_bit_count,
        rng,
    )
}

/// Build the public commit, private commit, and metadata needed for proving.
pub fn nist_gen_proof_inputs(
    crs: &PublicParams<Bls12_446>,
    params: DKGParams,
) -> (
    PublicCommit<Bls12_446>,
    PrivateCommit<Bls12_446>,
    [u8; METADATA_LEN],
) {
    let pke_params = nist_pke_params_from_dkg(params);
    let mut rng = nist_seeded_rng(*b"ZK_INPUT");
    let testcase = ZkTestcase::generate(&mut rng, pke_params);
    let ciphertext = testcase.encrypt(pke_params);

    let (public_commit, private_commit) = commit(
        testcase.a,
        testcase.b,
        ciphertext.c1,
        ciphertext.c2,
        testcase.r,
        testcase.e1,
        testcase.m,
        testcase.e2,
        crs,
    );

    (public_commit, private_commit, testcase.metadata)
}

/// Generate a ZK proof.
pub fn nist_gen_proof(
    crs: &PublicParams<Bls12_446>,
    public_commit: &PublicCommit<Bls12_446>,
    private_commit: &PrivateCommit<Bls12_446>,
    metadata: &[u8; METADATA_LEN],
    compute_load: ComputeLoad,
) -> ProofV2<Bls12_446> {
    let mut proof_seed_rng = nist_seeded_rng(*b"ZK_PROOF");
    let mut proof_seed = [0u8; 16];
    proof_seed_rng.fill_bytes(&mut proof_seed);

    prove(
        (crs, public_commit),
        private_commit,
        metadata,
        compute_load,
        &proof_seed,
    )
}

/// Verify `proof` using the two-step pairing mode.
#[allow(clippy::result_unit_err)]
pub fn nist_verify_two_steps(
    proof: &ProofV2<Bls12_446>,
    crs: &PublicParams<Bls12_446>,
    public_commit: &PublicCommit<Bls12_446>,
    metadata: &[u8; METADATA_LEN],
) -> Result<(), ()> {
    verify(
        proof,
        (crs, public_commit),
        metadata,
        VerificationPairingMode::TwoSteps,
    )
}

/// Verify `proof` using the batched pairing mode.
#[allow(clippy::result_unit_err)]
pub fn nist_verify_batched(
    proof: &ProofV2<Bls12_446>,
    crs: &PublicParams<Bls12_446>,
    public_commit: &PublicCommit<Bls12_446>,
    metadata: &[u8; METADATA_LEN],
) -> Result<(), ()> {
    verify(
        proof,
        (crs, public_commit),
        metadata,
        VerificationPairingMode::Batched,
    )
}

/// Verify `proof` in both [`VerificationPairingMode::TwoSteps`] and
/// [`VerificationPairingMode::Batched`] modes.
pub fn nist_run_verify(
    proof: &ProofV2<Bls12_446>,
    crs: &PublicParams<Bls12_446>,
    public_commit: &PublicCommit<Bls12_446>,
    metadata: &[u8; METADATA_LEN],
) {
    nist_verify_two_steps(proof, crs, public_commit, metadata)
        .expect("❌ proof verification failed in TwoSteps mode");
    nist_verify_batched(proof, crs, public_commit, metadata)
        .expect("❌ proof verification failed in Batched mode");
}
