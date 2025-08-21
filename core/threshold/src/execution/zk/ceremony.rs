//! Implementation of the ceremony protocol for generating a CRS (Common Reference String)
//! that is used in our zero-knowledge proofs for proving plaintext knowledge.

use crate::{
    algebra::structure_traits::Ring,
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::broadcast::{Broadcast, SyncReliableBroadcast},
        runtime::session::BaseSessionHandles,
    },
    networking::value::BroadcastValue,
    session_id::SessionId,
};
use async_trait::async_trait;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul, Neg};
use tfhe::{
    core_crypto::{commons::math::random::RandomGenerator, prelude::LweCiphertextCount},
    prelude::CastInto,
    shortint::parameters::{CompactPublicKeyEncryptionParameters, SupportedCompactPkeZkScheme},
    zk::{
        CompactPkeCrs, CompactPkeZkScheme, ZkCompactPkeV1PublicParams, ZkCompactPkeV2PublicParams,
    },
};
use tfhe_csprng::{generators::SoftwareRandomGenerator, seeders::XofSeed};
use tfhe_zk_pok::curve_api::{bls12_446 as curve, CurveGroupOps};
use tracing::instrument;

use super::constants::{
    ZK_DEFAULT_MAX_NUM_BITS, ZK_DSEP_AGG, ZK_DSEP_CHI, ZK_DSEP_CRS_UPDA, ZK_DSEP_GAMMA,
    ZK_DSEP_HASH, ZK_DSEP_HASH_P, ZK_DSEP_LMAP, ZK_DSEP_PHI, ZK_DSEP_R, ZK_DSEP_T, ZK_DSEP_W,
    ZK_DSEP_XI, ZK_DSEP_Z,
};

pub type SecureCeremony = RealCeremony<SyncReliableBroadcast>;

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Hash)]
pub struct PartialProof {
    h_pok: curve::Zp,
    s_pok: curve::Zp,
    pub new_pp: InternalPublicParameter,
}

impl PartialProof {
    pub fn validate_points(&self) -> anyhow::Result<()> {
        let (g_list_valid, g_hat_list_valid) = rayon::join(
            || {
                self.new_pp
                    .g1g2list
                    .g1s
                    .par_iter()
                    .all(curve::G1::validate_projective)
            },
            || {
                self.new_pp
                    .g1g2list
                    .g2s
                    .par_iter()
                    .all(curve::G2::validate_projective)
            },
        );
        if !(g_list_valid && g_hat_list_valid) {
            anyhow::bail!("some points are not valid")
        }
        Ok(())
    }
}

enum MetaParameter {
    V1(MetaParameterV1),
    V2(MetaParameterV2),
}

impl MetaParameter {
    fn n(&self) -> usize {
        match self {
            MetaParameter::V1(inner) => inner.n,
            MetaParameter::V2(inner) => inner.n,
        }
    }

    fn max_num_bits(&self) -> usize {
        match self {
            MetaParameter::V1(inner) => inner.max_num_bits,
            MetaParameter::V2(inner) => inner.max_num_bits,
        }
    }
}

/// These are the parameters except the g_list in ZkCompactPkeV1PublicParams.
struct MetaParameterV1 {
    big_d: usize,
    n: usize,
    d: usize,
    k: usize,
    b: u64,
    b_r: u64,
    q: u64,
    t: u64,
    msbs_zero_padding_bit_count: u64,
    max_num_bits: usize,
}

/// These are the parameters except the g_list in ZkCompactPkeV2PublicParams.
// we allow non_snake_case to be unified with tfhe-rs
#[allow(non_snake_case)]
struct MetaParameterV2 {
    n: usize,
    d: usize,
    k: usize,
    // We store the square of the bound to avoid rounding on sqrt operations
    B_inf: u64,
    q: u64,
    t: u64,
    msbs_zero_padding_bit_count: u64,
    bound_type: tfhe_zk_pok::proofs::pke_v2::Bound,
    max_num_bits: usize,
}

fn checked_sqr(x: u128) -> Option<u128> {
    x.checked_mul(x)
}

// we allow non_snake_case to be unified with tfhe-rs
#[allow(non_snake_case)]
fn inf_norm_bound_to_euclidean_squared(B_inf: u64, dim: usize) -> u128 {
    checked_sqr(B_inf as u128)
        .and_then(|norm_squared| norm_squared.checked_mul(dim as u128))
        .unwrap_or_else(|| panic!("Invalid parameters for zk_pok, B_inf: {B_inf}, d+k: {dim}"))
}

pub fn max_num_messages(
    compact_encryption_parameters: &CompactPublicKeyEncryptionParameters,
    max_bit_size: usize,
) -> anyhow::Result<LweCiphertextCount> {
    if compact_encryption_parameters.carry_modulus.0
        < compact_encryption_parameters.message_modulus.0
    {
        anyhow::bail!(
            "In order to build a ZK-CRS for packed compact ciphertext list encryption, \
            parameters must have CarryModulus >= MessageModulus"
        );
    }

    let carry_and_message_bit_capacity = (compact_encryption_parameters.carry_modulus.0
        * compact_encryption_parameters.message_modulus.0)
        .ilog2() as usize;
    let max_num_message = max_bit_size.div_ceil(carry_and_message_bit_capacity);
    Ok(LweCiphertextCount(max_num_message))
}

// we allow non_snake_case to be unified with tfhe-rs
#[allow(non_snake_case)]
fn compute_meta_parameter(
    params: &CompactPublicKeyEncryptionParameters,
    max_num_bits: Option<usize>,
) -> anyhow::Result<MetaParameter> {
    let lwe_dim = params.encryption_lwe_dimension;
    let noise_distribution = params.encryption_noise_distribution;
    let mut plaintext_modulus = params.message_modulus.0 * params.carry_modulus.0;
    // Our plaintext modulus does not take into account the bit of padding
    plaintext_modulus *= 2;

    let max_bit_size = max_num_bits.unwrap_or(ZK_DEFAULT_MAX_NUM_BITS);
    let max_num_cleartext = max_num_messages(params, max_bit_size)?;

    let zk_scheme = match params.zk_scheme {
        SupportedCompactPkeZkScheme::ZkNotSupported => anyhow::bail!("zk is unsupported"),
        SupportedCompactPkeZkScheme::V1 => CompactPkeZkScheme::V1,
        SupportedCompactPkeZkScheme::V2 => CompactPkeZkScheme::V2,
    };

    let (d, k, b, q, t) = tfhe::zk::CompactPkeCrs::prepare_crs_parameters(
        lwe_dim,
        max_num_cleartext,
        noise_distribution,
        params.ciphertext_modulus,
        plaintext_modulus,
        zk_scheme,
    )?;

    let msbs_zero_padding_bit_count = 1u64;
    let meta_param = match zk_scheme {
        CompactPkeZkScheme::V1 => {
            let (n, big_d, b_r) =
                tfhe_zk_pok::proofs::pke::compute_crs_params(d.0, k.0, b, q, t, 1);
            debug_assert_eq!(k, max_num_cleartext);
            MetaParameter::V1(MetaParameterV1 {
                big_d,
                n,
                d: d.0,
                k: k.0,
                b,
                b_r,
                q,
                t,
                msbs_zero_padding_bit_count,
                max_num_bits: max_bit_size,
            })
        }
        CompactPkeZkScheme::V2 => {
            let bound_type = tfhe_zk_pok::proofs::pke_v2::Bound::CS;
            let B_inf = b.cast_into();
            let B_squared = inf_norm_bound_to_euclidean_squared(B_inf, d.0 + k.0);
            let (n, _D, _B_bound_squared, _) = tfhe_zk_pok::proofs::pke_v2::compute_crs_params(
                d.0, k.0, B_squared, t, 1, bound_type,
            );
            // useful for debugging
            // println!("d {}, k {}, B_inf {}, t {}, bound_type {:?}", d.0, k.0, B_inf, t, bound_type);
            MetaParameter::V2(MetaParameterV2 {
                n,
                d: d.0,
                k: k.0,
                B_inf,
                q,
                t,
                msbs_zero_padding_bit_count,
                bound_type,
                max_num_bits: max_bit_size,
            })
        }
    };

    Ok(meta_param)
}

/// Compute the witness dimension for the given parameters.
///
/// This corresponds to Step 2 of CRS.Gen from the NIST spec,
/// but the exact calculation are happening inside tfhe-rs.
pub fn compute_witness_dim(
    params: &CompactPublicKeyEncryptionParameters,
    max_num_bits: Option<usize>,
) -> anyhow::Result<usize> {
    let meta_params = compute_meta_parameter(params, max_num_bits)?;
    Ok(meta_params.n())
}

// TODO consider making this a wrapper around GroupElements,
// instead of our own WrappedG1G2s
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Hash)]
pub struct InternalPublicParameter {
    round: u64,
    max_num_bits: usize,
    g1g2list: WrappedG1G2s,
    // we do not include the version number here because
    // players might cheat and change the version number
}

impl Default for InternalPublicParameter {
    fn default() -> Self {
        Self {
            round: 0,
            max_num_bits: 0,
            g1g2list: WrappedG1G2s::new(vec![], vec![]),
        }
    }
}

#[cfg(any(test, feature = "malicious_strategies"))]
impl InternalPublicParameter {
    pub(crate) fn new_insecure(round: u64, max_num_bits: usize, witness_dim: usize) -> Self {
        Self {
            round,
            max_num_bits,
            g1g2list: WrappedG1G2s::new(
                vec![curve::G1::GENERATOR; witness_dim * 2],
                vec![curve::G2::GENERATOR; witness_dim],
            ),
        }
    }
}

pub struct FinalizedInternalPublicParameter {
    pub inner: InternalPublicParameter,
    pub sid: SessionId,
}

impl FinalizedInternalPublicParameter {
    /// Convert the final internal public parameter, which is the result of the ceremony,
    /// into a [tfhe::zk::CompactPkeCrs] that can be used for zero-knowledge proofs in tfhe-rs.
    ///
    /// This is essentially the final step (Step 4) of CRS.Gen from the NIST spec.
    pub fn try_into_tfhe_zk_pok_pp(
        &self,
        params: &CompactPublicKeyEncryptionParameters,
        sid: SessionId,
    ) -> anyhow::Result<CompactPkeCrs> {
        self.inner.try_into_tfhe_zk_pok_pp(params, sid)
    }
}

// NOTE: we need to ensure `curve::G1`, `curve::G2` is stable.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
struct WrappedG1G2s {
    g1s: Vec<curve::G1>,
    g2s: Vec<curve::G2>,
}

impl WrappedG1G2s {
    fn new(g1s: Vec<curve::G1>, g2s: Vec<curve::G2>) -> Self {
        Self { g1s, g2s }
    }
}

impl InternalPublicParameter {
    /// Convert the internal public parameter, which is the result of the ceremony,
    /// into a [tfhe::zk::CompactPkeCrs] that can be used for zero-knowledge proofs in tfhe-rs.
    ///
    /// This is essentially the final step (Step 4) of CRS.Gen from the NIST spec.
    fn try_into_tfhe_zk_pok_pp(
        &self,
        params: &CompactPublicKeyEncryptionParameters,
        sid: SessionId, // TODO(#2505) add sid to the from_vec functions
    ) -> anyhow::Result<CompactPkeCrs> {
        let g_list = self
            .g1g2list
            .g1s
            .clone()
            .into_iter()
            .map(|x| x.normalize())
            .collect_vec();
        let g_hat_list = self
            .g1g2list
            .g2s
            .clone()
            .into_iter()
            .map(|x| x.normalize())
            .collect_vec();

        let crs = match compute_meta_parameter(params, Some(self.max_num_bits))? {
            MetaParameter::V1(inner_v1) => {
                if g_list.len() != 2 * inner_v1.n || g_hat_list.len() != inner_v1.n {
                    anyhow::bail!(
                        "V1 InternalPublicParameter length does not match n in parameter g_list={}, h_hat_list={}, expected={}",
                        g_list.len(),
                        g_hat_list.len(),
                        inner_v1.n
                    );
                }
                CompactPkeCrs::PkeV1(ZkCompactPkeV1PublicParams::from_vec(
                    g_list,
                    g_hat_list,
                    inner_v1.big_d,
                    inner_v1.n,
                    inner_v1.d,
                    inner_v1.k,
                    inner_v1.b,
                    inner_v1.b_r,
                    inner_v1.q,
                    inner_v1.t,
                    inner_v1.msbs_zero_padding_bit_count,
                    sid.into(),
                    ZK_DSEP_HASH,
                    ZK_DSEP_T,
                    ZK_DSEP_AGG,
                    ZK_DSEP_LMAP,
                    ZK_DSEP_Z,
                    ZK_DSEP_W,
                    ZK_DSEP_GAMMA,
                ))
            }
            MetaParameter::V2(inner_v2) => {
                if g_list.len() != 2 * inner_v2.n || g_hat_list.len() != inner_v2.n {
                    anyhow::bail!(
                        "V2 InternalPublicParameter length does not match n in parameter g_list={}, h_hat_list={}, expected={}",
                        g_list.len(),
                        g_hat_list.len(),
                        inner_v2.n
                    );
                }
                CompactPkeCrs::PkeV2(ZkCompactPkeV2PublicParams::from_vec(
                    g_list,
                    g_hat_list,
                    inner_v2.d,
                    inner_v2.k,
                    inner_v2.B_inf,
                    inner_v2.q,
                    inner_v2.t,
                    inner_v2.msbs_zero_padding_bit_count,
                    inner_v2.bound_type,
                    sid.into(),
                    ZK_DSEP_HASH,
                    ZK_DSEP_R,
                    ZK_DSEP_T,
                    ZK_DSEP_W,
                    ZK_DSEP_AGG,
                    ZK_DSEP_LMAP,
                    ZK_DSEP_PHI,
                    ZK_DSEP_XI,
                    ZK_DSEP_Z,
                    ZK_DSEP_CHI,
                    ZK_DSEP_GAMMA,
                ))
            }
        };

        Ok(crs)
    }

    /// Create new PublicParameter for given witness dimension containing the generators
    ///
    /// This is the CRS-Gen.Init protocol from the NIST spec.
    pub fn new(witness_dim: usize, max_num_bits: Option<u32>) -> Self {
        let max_num_bits = max_num_bits.unwrap_or(ZK_DEFAULT_MAX_NUM_BITS as u32) as usize;
        InternalPublicParameter {
            round: 0,
            max_num_bits,
            g1g2list: WrappedG1G2s::new(
                vec![curve::G1::GENERATOR; witness_dim * 2],
                vec![curve::G2::GENERATOR; witness_dim],
            ),
        }
    }

    pub fn new_from_tfhe_param(
        params: &CompactPublicKeyEncryptionParameters,
        max_num_bits: Option<usize>,
    ) -> anyhow::Result<Self> {
        let meta_param = compute_meta_parameter(params, max_num_bits)?;
        let witness_dim = meta_param.n();
        let max_num_bits = meta_param.max_num_bits();
        Ok(InternalPublicParameter {
            round: 0,
            max_num_bits,
            g1g2list: WrappedG1G2s::new(
                vec![curve::G1::GENERATOR; witness_dim * 2],
                vec![curve::G2::GENERATOR; witness_dim],
            ),
        })
    }

    pub fn witness_dim(&self) -> usize {
        self.g1g2list.g2s.len()
    }

    // This is Hash' in the NIST spec
    fn hash_to_scalars(&self, n: usize, sid: SessionId) -> Vec<curve::Zp> {
        // 16 bytes for sid
        // 8 bytes for round
        // 8 bytes for inner.g1s length
        // (2*b1 - 1) * G1 point length (minus 1 since we skip the punctured element)
        // 8 bytes for inner.g2s length
        // b1 * G2 point length
        let capacity = 16
            + 8
            + 8
            + (self.g1g2list.g1s.len() - 1) * curve::G1::BYTE_SIZE
            + 8
            + self.g1g2list.g2s.len() * curve::G2::BYTE_SIZE;

        // NOTE: all the usize types need to be 8 bytes
        // independent of the architecture, so we convert them to u64
        // before serialization
        let mut buf = Vec::with_capacity(capacity);
        let sid_buf = sid.to_le_bytes();
        debug_assert_eq!(sid_buf.len(), 16);
        buf.extend(sid_buf);
        buf.extend(self.round.to_le_bytes());
        buf.extend((self.g1g2list.g1s.len() as u64 - 1).to_le_bytes());
        let b1 = self.witness_dim();
        for (i, elem) in self.g1g2list.g1s.iter().enumerate() {
            if i == b1 {
                // We skip the punctured element
                debug_assert!(elem == &curve::G1::ZERO);
                continue;
            }
            buf.extend(elem.to_le_bytes());
        }
        buf.extend((self.g1g2list.g2s.len() as u64).to_le_bytes());
        for elem in &self.g1g2list.g2s {
            buf.extend(elem.to_le_bytes());
        }
        debug_assert_eq!(buf.len(), capacity);
        let mut out = vec![curve::Zp::ZERO; n];
        // Add explicit domain separator
        curve::Zp::hash(&mut out, &[&ZK_DSEP_HASH_P, &buf]);
        out
    }
}

/// Compute a new proof round.
///
/// Note that this function is deterministic, i.e. the parameters `tau` and `r` (r_{pok, j}) must be generated freshly at random outside this function.
pub(crate) fn make_partial_proof_deterministic(
    current_pp: &InternalPublicParameter,
    tau: &curve::ZeroizeZp,
    round: u64,
    r: &curve::ZeroizeZp,
    sid: SessionId,
) -> PartialProof {
    let b1 = current_pp.witness_dim();

    // [tau_powers] should not be re-allocated (e.g., extended) because
    // zeroize does not guarantee that the deallocated memory is zeroed.
    //
    // we need \tau^1, ..., \tau^{2*b1} for the new CRS
    // but we do not use \tau^{b1 + 1}
    let tau_powers = (0..2 * b1)
        .scan(curve::ZeroizeZp::ONE, |acc, _| {
            *acc = acc.mul(tau);
            Some(acc.clone())
        })
        .collect_vec();

    // We need to set the round number instead of
    // using current_pp.round + 1 because
    // some rounds might be skipped when malicious parties
    // do not send a valid proof.
    //
    // This is Step 1 of CRS-Gen.Update from the NIST spec
    // where pp_j is computed.
    //
    // The scalar multiplication
    // with powers of tau is the most expensive step.
    let new_pp = InternalPublicParameter {
        round,
        max_num_bits: current_pp.max_num_bits,
        // Observe that `zip_eq` may panic, but this would imply a bug since `tau_powers` has been constructed based on `current_pp`
        g1g2list: WrappedG1G2s::new(
            current_pp
                .g1g2list
                .g1s
                .par_iter()
                .zip_eq(&tau_powers)
                .enumerate()
                .map(|(i, (g, t))| {
                    if i == b1 {
                        curve::G1::ZERO
                    } else {
                        g.mul_scalar_zeroize(t)
                    }
                })
                .collect(),
            current_pp
                .g1g2list
                .g2s
                .par_iter()
                .zip_eq(&tau_powers[..tau_powers.len() / 2])
                .map(|(g, t)| g.mul_scalar_zeroize(t))
                .collect(),
        ),
    };

    // This is Step 2 of CRS-Gen.Update from the NIST spec
    // where the contributor j runs NIZK to prove the knowledge of the discrete logarithm \tau.
    let g1_jm1 = current_pp.g1g2list.g1s[0]; // g_{1,j-1}
    let r_pok = g1_jm1.mul_scalar_zeroize(r); // R_{pok, j}
    let g1_j = new_pp.g1g2list.g1s[0]; // g_{1, j}
    let mut h_pok = vec![curve::Zp::ZERO; 1];
    // This is Hash from the NIST spec
    curve::Zp::hash(
        &mut h_pok,
        &[
            &ZK_DSEP_HASH, // Manually add domain separator
            &sid.to_le_bytes(),
            &round.to_le_bytes(),
            &g1_j.to_le_bytes(),
            &g1_jm1.to_le_bytes(),
            &r_pok.to_le_bytes(),
        ],
    );
    let h_pok = h_pok[0];
    let s_pok = h_pok * tau + r;

    PartialProof {
        h_pok,
        s_pok,
        new_pp,
    }
}

/// Make a new public parameter from the given TFHE parameters
/// without using any threshold protocol, so the caller must be
/// trusted to delete the toxic waste before returning the public parameter.
///
/// This is used in the centralized KMS as well as the insecure
/// version of the threshold KMS.
pub fn public_parameters_by_trusted_setup<R: Rng + CryptoRng>(
    params: &CompactPublicKeyEncryptionParameters,
    max_num_bits: Option<usize>,
    sid: SessionId,
    rng: &mut R,
) -> anyhow::Result<FinalizedInternalPublicParameter> {
    let pparam = InternalPublicParameter::new_from_tfhe_param(params, max_num_bits)?;

    let mut tau = curve::ZeroizeZp::ZERO;
    tau.rand_in_place(rng);
    let mut r = curve::ZeroizeZp::ZERO;
    r.rand_in_place(rng);

    let pproof = make_partial_proof_deterministic(&pparam, &tau, 1, &r, sid);

    Ok(FinalizedInternalPublicParameter {
        inner: pproof.new_pp,
        sid,
    })
}

// This function returns a custom error message
// for different types of error, so that we can
// test for different scenarios.
// But the error type should be swallowed when
// it is used in a public API.
fn verify_proof(
    current_pp: &InternalPublicParameter,
    partial_proof: &PartialProof,
    round: u64,
    sid: SessionId,
) -> anyhow::Result<InternalPublicParameter> {
    partial_proof.validate_points()?;

    if current_pp.round >= partial_proof.new_pp.round {
        return Err(anyhow_error_and_log("bad round number".to_string()));
    }

    let new_pp = partial_proof.new_pp.clone();
    let g1_jm1 = current_pp.g1g2list.g1s[0]; // g_{1,j-1}
    let g1_j = new_pp.g1g2list.g1s[0]; // g_{1, j}

    // Step 3 of CRS-Gen.Update from the NIST spec.
    //
    // verify the discrete log proof
    // this proof ensures that the prover
    // did not erase the previous CRS contribution
    verify_dlog_proof(
        partial_proof.s_pok,
        partial_proof.h_pok,
        &g1_jm1,
        &g1_j,
        round,
        sid,
    )?;

    // check g1_j is not zero (or 1 in multiplicative notation)
    // this is also a part of Step 3
    if g1_j == curve::G1::ZERO {
        return Err(anyhow_error_and_log(
            "non-degenerative check failed".to_string(),
        ));
    }

    // I (caller) need to make sure the lengths are correct
    // the point of reference is the current_pp
    let witness_dim = current_pp.witness_dim();
    if new_pp.g1g2list.g1s.len() != witness_dim * 2 {
        return Err(anyhow_error_and_log(
            "crs length check failed (g)".to_string(),
        ));
    }
    if new_pp.witness_dim() != witness_dim {
        return Err(anyhow_error_and_log(
            "crs length check failed (g_hat)".to_string(),
        ));
    }

    if new_pp.g1g2list.g1s[witness_dim] != curve::G1::ZERO {
        return Err(anyhow_error_and_log(
            "the list of G1s is not correctly punctured".to_string(),
        ));
    }

    // Step 4 of CRS-Gen.Update from the NIST spec.
    //
    // perform the well-formedness check
    // this check guarantees that the prover
    // is raising the elements in the CRS by the correct powers of tau
    verify_wellformedness(&new_pp, sid)?;

    Ok(new_pp)
}

fn verify_dlog_proof(
    s_pok: curve::Zp,
    h_pok: curve::Zp,
    g1_jm1: &curve::G1,
    g1_j: &curve::G1,
    round: u64,
    sid: SessionId,
) -> anyhow::Result<()> {
    let g1_to_s = g1_jm1.mul_scalar(s_pok);
    let g1_to_h = g1_j.mul_scalar(h_pok.neg());
    let h_pok_2 = {
        let tmp = g1_to_s.add(g1_to_h);
        let mut out = vec![curve::Zp::ZERO; 1];
        // This is Hash from the NIST spec
        curve::Zp::hash(
            &mut out,
            &[
                &ZK_DSEP_HASH, // Manually add domain separator
                &sid.to_le_bytes(),
                &round.to_le_bytes(),
                &g1_j.to_le_bytes(),
                &g1_jm1.to_le_bytes(),
                &tmp.to_le_bytes(),
            ],
        );
        out[0]
    };

    if h_pok_2 != h_pok {
        return Err(anyhow_error_and_log("dlog check failed".to_string()));
    }
    Ok(())
}

/// Step 4 of CRS-Gen.Update from the NIST spec
fn verify_wellformedness(new_pp: &InternalPublicParameter, sid: SessionId) -> anyhow::Result<()> {
    // verify the other parts of the new CRS
    let rhos = new_pp.hash_to_scalars(2, sid);
    let b1 = new_pp.witness_dim();
    debug_assert_eq!(new_pp.g1g2list.g1s.len(), b1 * 2);

    // e(\tau_j^{B1+2} [G1], [G2]) = e(\tau_j^{B1} [G1], \tau_j^2 [G2])
    let e = curve::Gt::pairing;
    if e(new_pp.g1g2list.g1s[b1 + 1], curve::G2::GENERATOR)
        != e(new_pp.g1g2list.g1s[b1 - 1], new_pp.g1g2list.g2s[1])
    {
        return Err(anyhow_error_and_log(
            "well-formedness check failed (1)".to_string(),
        ));
    }

    // powers of rho start at rho^0
    // this is because the spec uses \rho^{i - 1} for i starting at 1
    let rho1_powers = std::iter::once(curve::Zp::ONE)
        .chain((0..2 * b1 - 1).scan(curve::Zp::ONE, |acc, _| {
            *acc = acc.mul(rhos[0]);
            Some(*acc)
        }))
        .collect_vec();
    let rho2_powers = std::iter::once(curve::Zp::ONE)
        .chain((0..b1 - 1).scan(curve::Zp::ONE, |acc, _| {
            *acc = acc.mul(rhos[1]);
            Some(*acc)
        }))
        .collect_vec();

    // \prod_{i=1, i != b1+1, i!= b1+2}^{2*b1} g_{i,j}^{\rho_1^{i-1}}
    let lhs1 = new_pp
        .g1g2list
        .g1s
        .par_iter()
        .enumerate()
        .filter_map(|(i, g)| {
            // note that rho1_powers[i] is \rho_1^{i - 1} in the NIST spec
            if i == b1 || i == b1 + 1 {
                None
            } else {
                Some(g.mul_scalar(rho1_powers[i]))
            }
        })
        .sum::<curve::G1>();

    // \hat{g} \cdot \sum_{\ell = 1}^{b1 - 1} \hat{g}_{\ell,j}^{\rho_2^{\ell}}
    let lhs2 = new_pp
        .g1g2list
        .g2s
        .par_iter()
        .take(b1 - 1)
        .enumerate()
        .map(|(l, g_hat)| g_hat.mul_scalar(rho2_powers[l + 1]))
        .sum::<curve::G2>()
        .add(curve::G2::GENERATOR);

    debug_assert_eq!(new_pp.g1g2list.g1s.len(), b1 * 2);

    // g \cdot \prod_{i=1, i != b1, i!= b1+1}^{2*b1-1} g_{i,j}^{\rho_1^i}
    let rhs1 = new_pp
        .g1g2list
        .g1s
        .par_iter()
        .take(b1 * 2 - 1)
        .enumerate()
        .filter_map(|(i, g)| {
            // note that rho1_powers[i + 1] is \rho_1^i in the NIST spec
            if i == b1 - 1 || i == b1 {
                None
            } else {
                Some(g.mul_scalar(rho1_powers[i + 1]))
            }
        })
        .sum::<curve::G1>()
        .add(curve::G1::GENERATOR);

    // \prod_{l=1}^{b1} \hat{g}_{\ell,j}^{\rho_2^{\ell - 1}}
    let rhs2 = new_pp
        .g1g2list
        .g2s
        .par_iter()
        .enumerate()
        .map(|(l, g_hat)| g_hat.mul_scalar(rho2_powers[l]))
        .sum::<curve::G2>();

    if e(lhs1, lhs2) != e(rhs1, rhs2) {
        return Err(anyhow_error_and_log(
            "well-formedness check failed (2)".to_string(),
        ));
    }

    Ok(())
}

#[async_trait]
pub trait Ceremony: Send + Sync + Clone + Default {
    async fn execute<Z: Ring, S: BaseSessionHandles>(
        &self,
        session: &mut S,
        witness_dim: usize,
        max_num_pt_bits: Option<u32>,
    ) -> anyhow::Result<FinalizedInternalPublicParameter>;
}

#[derive(Default, Clone)]
pub struct RealCeremony<BCast: Broadcast + Default> {
    broadcast: BCast,
}

#[async_trait]
impl<BCast: Broadcast + Default> Ceremony for RealCeremony<BCast> {
    #[instrument(name = "CRS-Ceremony", skip_all, fields(sid=?session.session_id(),own_identity=?session.own_identity()))]
    async fn execute<Z: Ring, S: BaseSessionHandles>(
        &self,
        session: &mut S,
        witness_dim: usize,
        max_num_pt_bits: Option<u32>,
    ) -> anyhow::Result<FinalizedInternalPublicParameter> {
        // the parties need to execute the protocol in a deterministic order
        // so we sort the roles to fix this order
        // even if the adversary can pick the order, it does not affect the security
        let mut all_roles_sorted = session.role_assignments().keys().copied().collect_vec();
        all_roles_sorted.sort();
        let my_role = session.my_role();

        let mut pp = InternalPublicParameter::new(witness_dim, max_num_pt_bits);
        let sid = session.session_id();
        tracing::info!(
            "Role {my_role} starting CRS ceremony in session {}",
            session.session_id()
        );

        for (round, role) in all_roles_sorted.iter().enumerate() {
            // we use u64 since the round number is defined by the number of participants
            // i.e., Role, and internally Role stores u64
            let round = round as u64 + 1; // round starts at 1, round 0 is the trivial CRS, i.e., pp_0
            if role == &my_role {
                let mut xof = RandomGenerator::<SoftwareRandomGenerator>::new(XofSeed::new_u128(
                    session.rng().gen::<u128>(),
                    ZK_DSEP_CRS_UPDA,
                ));

                // tau and r will be zeroized automatically on drop. However they should not be
                // moved into other variables or passed by value as this might leave non-zeroized
                // copies.
                let mut tau = curve::ZeroizeZp::ZERO;
                tau.rand_in_place(&mut xof);
                let mut r = curve::ZeroizeZp::ZERO;
                r.rand_in_place(&mut xof);

                // We use the rayon's threadpool for handling CPU-intensive tasks
                // like creating the CRS. This is recommended over tokio::task::spawn_blocking
                // since the tokio threadpool has a very high default upper limit.
                // More info: https://ryhl.io/blog/async-what-is-blocking/
                let (send, recv) = tokio::sync::oneshot::channel();
                rayon::spawn_fifo(move || {
                    let partial_proof = make_partial_proof_deterministic(&pp, &tau, round, &r, sid);
                    let _ = send.send(partial_proof);
                });

                let proof = recv.await?;
                let vi = BroadcastValue::PartialProof::<Z>(proof.clone());

                // nobody else should be broadcasting so we do not process results
                // since I know I'm honest, this step should never fail since
                // we're running a robust protocol
                let _ = self
                    .broadcast
                    .broadcast_w_corrupt_set_update(session, vec![my_role], Some(vi))
                    .await?;

                // update our pp
                pp = proof.new_pp;

                tracing::info!(
                    "Role {my_role} finished my turn in CRS ceremony for session {}",
                    session.session_id()
                );
            } else {
                // do the following if it is not my turn to contribute
                match self
                    .broadcast
                    .broadcast_w_corrupt_set_update::<Z, _>(session, vec![*role], None)
                    .await
                {
                    Ok(res) => {
                        // reliable broadcast finished, we need to check the proof
                        // check that it is from the correct sender
                        for (sender, msg) in res {
                            if &sender == role {
                                if let BroadcastValue::PartialProof(proof) = msg {
                                    // We move pp and then let the blocking thread return it to pp_tmp
                                    // this will avoid cloning the whole pp which is just two vectors.
                                    // The rayon threadpool is used again (see comment above).
                                    let (send, recv) = tokio::sync::oneshot::channel();
                                    rayon::spawn_fifo(move || {
                                        let res = verify_proof(&pp, &proof, round, sid);
                                        let _ = send.send((res, pp));
                                    });
                                    let (ver, pp_tmp) = recv.await?;
                                    pp = pp_tmp;

                                    // Step 5 of CRS-Gen.Update from the NIST spec
                                    // where we receive the proof and update the public parameter if the proof is valid.
                                    match ver {
                                        // verification succeeded, we can update pp with the new value
                                        Ok(new_pp) => pp = new_pp,
                                        Err(e) => {
                                            tracing::warn!(
                                                "proof verification failed in crs ceremony with error {e}"
                                            );
                                        }
                                    }
                                } else {
                                    tracing::error!(
                                        "unexpected message type in crs ceremony from {sender}"
                                    );
                                }
                            } else {
                                // ignore the messages from other parties but warn
                                tracing::warn!(
                                    "unexpected sender in crs ceremony, expect {role} got {sender}"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        // if an error happens in reliable broadcast
                        // then we log the error and continue to the next round
                        tracing::warn!("failed to receive broadcast result with error {}", e);
                    }
                }
            }
        }

        Ok(FinalizedInternalPublicParameter { inner: pp, sid })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        algebra::galois_rings::degree_4::ResiduePolyF4Z64,
        execution::{
            runtime::{
                session::{LargeSession, ParameterHandles},
                test_runtime::{generate_fixed_identities, DistributedTestRuntime},
            },
            tfhe_internals::parameters::BC_PARAMS_NO_SNS,
        },
        malicious_execution::zk::ceremony::InsecureCeremony,
        networking::NetworkMode,
        session_id::SessionId,
        tests::helper::tests::{
            execute_protocol_large_w_disputes_and_malicious, TestingParameters,
        },
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use rstest::rstest;
    use std::collections::HashMap;
    use tfhe_zk_pok::{curve_api::Bls12_446, proofs, proofs::LEGACY_HASH_DS_LEN_BYTES};
    use tokio::task::JoinSet;

    #[test]
    fn test_honest_crs_ceremony_secure() {
        test_honest_crs_ceremony(SecureCeremony::default)
    }

    #[test]
    fn test_honest_crs_ceremony_insecure() {
        test_honest_crs_ceremony(InsecureCeremony::default)
    }

    fn test_honest_crs_ceremony<F, C>(ceremony_f: F)
    where
        F: Fn() -> C,
        C: Ceremony + 'static,
    {
        let threshold = 1usize;
        let num_parties = 4usize;
        let witness_dim = 10usize;
        let identities = generate_fixed_identities(num_parties);
        //CRS generation is round robin, so Sync by nature
        let runtime: DistributedTestRuntime<
            ResiduePolyF4Z64,
            { ResiduePolyF4Z64::EXTENSION_DEGREE },
        > = DistributedTestRuntime::new(identities, threshold as u8, NetworkMode::Sync, None);

        let session_id = SessionId::from(2);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        for (index_id, _identity) in runtime.identities.clone().into_iter().enumerate() {
            let mut session = runtime.large_session_for_party(session_id, index_id);
            let ceremony = ceremony_f();
            set.spawn(async move {
                let out = ceremony
                    .execute::<ResiduePolyF4Z64, _>(&mut session, witness_dim, Some(1))
                    .await
                    .unwrap();
                (session.my_role(), out)
            });
        }

        let results = rt
            .block_on(async {
                let mut results = HashMap::new();
                while let Some(v) = set.join_next().await {
                    let (role, pp) = v.unwrap();
                    results.insert(role, pp);
                }
                results
            })
            .into_iter()
            .collect_vec();

        let pp = results.first().unwrap().1.inner.clone();
        assert_eq!(pp.round, num_parties as u64);
        for (_, p) in results {
            assert_eq!(p.inner, pp);
        }

        // check that we can use pp to make a proof
        let mut rng = AesRng::from_entropy();
        let g_list = pp
            .g1g2list
            .g1s
            .clone()
            .into_iter()
            .map(|x| x.normalize())
            .collect_vec();

        let g_hat_list = pp
            .g1g2list
            .g2s
            .clone()
            .into_iter()
            .map(|x| x.normalize())
            .collect_vec();

        const DUMMY_DSEP_HASH_PADDED: &[u8; LEGACY_HASH_DS_LEN_BYTES] =
            &[1; LEGACY_HASH_DS_LEN_BYTES];
        const DUMMY_DSEP_S_PADDED: &[u8; LEGACY_HASH_DS_LEN_BYTES] = &[2; LEGACY_HASH_DS_LEN_BYTES];
        const DUMMY_DSEP_T_PADDED: &[u8; LEGACY_HASH_DS_LEN_BYTES] = &[3; LEGACY_HASH_DS_LEN_BYTES];
        const DUMMY_DSEP_AGG_PADDED: &[u8; LEGACY_HASH_DS_LEN_BYTES] =
            &[4; LEGACY_HASH_DS_LEN_BYTES];

        // We use a range proof here to simplify the testing as pke and pkev2 proofs are harder to setup
        let public_params = proofs::range::PublicParams::<Bls12_446>::from_vec(
            g_list,
            g_hat_list,
            *DUMMY_DSEP_HASH_PADDED,
            *DUMMY_DSEP_S_PADDED,
            *DUMMY_DSEP_T_PADDED,
            *DUMMY_DSEP_AGG_PADDED,
        );
        let l = 6;
        let x = rng.gen::<u64>() % (1 << l);
        let (public_commit, private_commit) = proofs::range::commit(x, l, &public_params, &mut rng);
        let proof =
            proofs::range::prove((&public_params, &public_commit), &private_commit, &mut rng);
        let verify = proofs::range::verify(&proof, (&public_params, &public_commit));
        assert!(verify.is_ok());
    }

    /// create all-zero public parameters
    fn make_degenerative_pp(n: usize) -> InternalPublicParameter {
        InternalPublicParameter {
            round: 0,
            max_num_bits: 1,
            g1g2list: WrappedG1G2s::new(vec![curve::G1::ZERO; 2 * n], vec![curve::G2::ZERO; n]),
        }
    }

    #[derive(Clone, Default)]
    struct BadProofCeremony<BCast: Broadcast> {
        broadcast: BCast,
    }

    #[async_trait]
    impl<BCast: Broadcast + Default> Ceremony for BadProofCeremony<BCast> {
        async fn execute<Z: Ring, S: BaseSessionHandles>(
            &self,
            session: &mut S,
            witness_dim: usize,
            max_num_bits: Option<u32>,
        ) -> anyhow::Result<FinalizedInternalPublicParameter> {
            let mut all_roles_sorted = session.role_assignments().keys().copied().collect_vec();
            all_roles_sorted.sort();
            let my_role = session.my_role();

            let mut pp = InternalPublicParameter::new(witness_dim, max_num_bits);

            let sid = session.session_id();
            for (round, role) in all_roles_sorted.iter().enumerate() {
                let round = round as u64;
                if role == &my_role {
                    let mut tau = curve::ZeroizeZp::ZERO;
                    tau.rand_in_place(&mut session.rng());
                    let mut r = curve::ZeroizeZp::ZERO;
                    r.rand_in_place(&mut session.rng());
                    // make a bad proof
                    let mut proof: PartialProof =
                        make_partial_proof_deterministic(&pp, &tau, round + 1, &r, sid);
                    proof.h_pok += curve::Zp::ONE;
                    let vi = BroadcastValue::PartialProof::<Z>(proof.clone());

                    let _ = self
                        .broadcast
                        .broadcast_w_corrupt_set_update(session, vec![my_role], Some(vi))
                        .await?;
                    pp = proof.new_pp;
                } else {
                    let hm = self
                        .broadcast
                        .broadcast_w_corrupt_set_update::<Z, _>(session, vec![*role], None)
                        .await
                        .unwrap();
                    let msg = hm.get(role).unwrap();
                    if let BroadcastValue::PartialProof(proof) = msg {
                        pp = proof.new_pp.clone();
                    }
                }
            }

            Ok(FinalizedInternalPublicParameter {
                inner: pp,
                sid: session.session_id(),
            })
        }
    }

    fn test_ceremony_strategies_large<
        C: Ceremony + 'static,
        Z: Ring,
        const EXTENSION_DEGREE: usize,
    >(
        params: TestingParameters,
        witness_dim: usize,
        malicious_party: C,
    ) {
        let mut task_honest = |mut session: LargeSession| async move {
            let real_ceremony = SecureCeremony::default();
            (
                session.my_role(),
                real_ceremony
                    .execute::<Z, _>(&mut session, witness_dim, Some(1))
                    .await
                    .unwrap(),
                session.corrupt_roles().clone(),
            )
        };

        let mut task_malicious = |mut session: LargeSession, malicious_party: C| async move {
            let _ = malicious_party
                .execute::<Z, _>(&mut session, witness_dim, Some(1))
                .await;
            session.my_role()
        };

        //CRS generation is round robin, so Sync by nature
        let (results_honest, _) =
            execute_protocol_large_w_disputes_and_malicious::<_, _, _, _, _, Z, EXTENSION_DEGREE>(
                &params,
                &[],
                &params.malicious_roles,
                malicious_party,
                NetworkMode::Sync,
                None,
                &mut task_honest,
                &mut task_malicious,
            );

        // the honest results should be a valid crs and not the initial one
        let honest_pp = results_honest.iter().map(|(_, pp, _)| pp).collect_vec();
        let pp = honest_pp[0];
        // make sure we're not using the initial pp
        assert_ne!(pp.inner.g1g2list.g1s[0], pp.inner.g1g2list.g1s[1]);
        assert_ne!(pp.inner.g1g2list.g2s[0], pp.inner.g1g2list.g2s[1]);
        for other in honest_pp {
            assert_eq!(pp.inner, other.inner);
        }
    }

    #[rstest]
    #[case(TestingParameters::init(4,1,&[1],&[],&[],false,None), 4)]
    #[case(TestingParameters::init(4,1,&[0],&[],&[],false,None), 4)]
    fn test_dropping_ceremony(#[case] params: TestingParameters, #[case] witness_dim: usize) {
        use crate::malicious_execution::zk::ceremony::DroppingCeremony;

        let malicious_party = DroppingCeremony;
        test_ceremony_strategies_large::<_, ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }>(
            params.clone(),
            witness_dim,
            malicious_party.clone(),
        );
    }

    #[rstest]
    #[case(TestingParameters::init(4,1,&[1],&[],&[],false,None), 4)]
    #[case(TestingParameters::init(4,1,&[0],&[],&[],false,None), 4)]
    fn test_bad_proof_ceremony<BCast: Broadcast + Default + 'static>(
        #[case] params: TestingParameters,
        #[case] witness_dim: usize,
        #[values(SyncReliableBroadcast::default())] broadcast_strategy: BCast,
    ) {
        let malicious_party = BadProofCeremony {
            broadcast: broadcast_strategy,
        };
        test_ceremony_strategies_large::<_, ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }>(
            params.clone(),
            witness_dim,
            malicious_party.clone(),
        );
    }

    #[rstest]
    #[case(TestingParameters::init(4,1,&[1],&[],&[],false,None), 4)]
    #[case(TestingParameters::init(4,1,&[0],&[],&[],false,None), 4)]
    fn test_rushing_ceremony<BCast: Broadcast + Default + 'static>(
        #[case] params: TestingParameters,
        #[case] witness_dim: usize,
        #[values(SyncReliableBroadcast::default())] broadcast_strategy: BCast,
    ) {
        use crate::malicious_execution::zk::ceremony::RushingCeremony;

        let malicious_party = RushingCeremony {
            broadcast: broadcast_strategy,
        };
        test_ceremony_strategies_large::<_, ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }>(
            params.clone(),
            witness_dim,
            malicious_party.clone(),
        );
    }

    #[test]
    fn test_pairing() {
        // sanity check for the pairing operation
        let mut rng = AesRng::seed_from_u64(42);
        let mut tau = curve::ZeroizeZp::ZERO;
        tau.rand_in_place(&mut rng);
        let mut r = curve::ZeroizeZp::ZERO;
        r.rand_in_place(&mut rng);
        let tau_powers = (0..2 * 2)
            .scan(curve::ZeroizeZp::ONE, |acc, _| {
                *acc = acc.mul(&tau);
                Some(acc.clone())
            })
            .collect_vec();

        let e = curve::Gt::pairing;
        assert_eq!(
            e(
                curve::G1::GENERATOR.mul_scalar_zeroize(&tau_powers[3]),
                curve::G2::GENERATOR
            ),
            e(
                curve::G1::GENERATOR.mul_scalar_zeroize(&tau_powers[1]),
                curve::G2::GENERATOR.mul_scalar_zeroize(&tau_powers[1])
            )
        );

        let sid = SessionId::from(1);
        let pp = InternalPublicParameter::new(2, Some(1));
        let proof = make_partial_proof_deterministic(&pp, &tau, 0, &r, sid);
        assert_eq!(
            proof.new_pp.g1g2list.g1s[3],
            curve::G1::GENERATOR.mul_scalar_zeroize(&tau_powers[3])
        );
        assert_eq!(
            proof.new_pp.g1g2list.g1s[1],
            curve::G1::GENERATOR.mul_scalar_zeroize(&tau_powers[1])
        );
        assert_eq!(
            proof.new_pp.g1g2list.g2s[1],
            curve::G2::GENERATOR.mul_scalar_zeroize(&tau_powers[1])
        );
    }

    #[test]
    fn test_intermediate_proof() {
        let n = 4usize;
        let mut rng = AesRng::seed_from_u64(42);
        let pp1 = InternalPublicParameter::new(n, Some(1));
        let mut tau1 = curve::ZeroizeZp::ZERO;
        tau1.rand_in_place(&mut rng);
        let mut r = curve::ZeroizeZp::ZERO;
        r.rand_in_place(&mut rng);
        let sid = SessionId::from(1);

        assert_eq!(pp1.g1g2list.g1s.len(), n * 2);
        assert_eq!(pp1.g1g2list.g2s.len(), n);

        {
            // first round
            let proof1 = make_partial_proof_deterministic(&pp1, &tau1, 1, &r, sid);
            assert!(verify_proof(&pp1, &proof1, 1, sid).is_ok());

            // second round
            let pp2 = proof1.new_pp;
            let mut tau2 = curve::ZeroizeZp::ZERO;
            tau2.rand_in_place(&mut rng);
            let proof2 = make_partial_proof_deterministic(&pp2, &tau2, 2, &r, sid);
            assert!(verify_proof(&pp2, &proof2, 2, sid).is_ok());
        }
        {
            let proof1 = make_partial_proof_deterministic(&pp1, &tau1, 1, &r, sid);
            let bad_sid = SessionId::from(2); // originally it was 1

            // dlog check failed because input to Hash has the wrong session ID
            assert!(verify_proof(&pp1, &proof1, 1, bad_sid)
                .unwrap_err()
                .to_string()
                .contains("dlog check failed"));
        }
        {
            let proof1 = make_partial_proof_deterministic(&pp1, &tau1, 1, &r, sid);

            // dlog check failed because input to Hash has the wrong round number
            assert!(verify_proof(&pp1, &proof1, 11, sid)
                .unwrap_err()
                .to_string()
                .contains("dlog check failed"));
        }
        {
            let proof = make_partial_proof_deterministic(&pp1, &tau1, 0, &r, sid);
            assert!(verify_proof(&pp1, &proof, 0, sid)
                .unwrap_err()
                .to_string()
                .contains("bad round number"));
        }
        {
            let mut proof = make_partial_proof_deterministic(&pp1, &tau1, 1, &r, sid);
            proof.h_pok += curve::Zp::ONE;
            assert!(verify_proof(&pp1, &proof, 1, sid)
                .unwrap_err()
                .to_string()
                .contains("dlog check failed"));
        }
        {
            let mut proof = make_partial_proof_deterministic(&pp1, &tau1, 1, &r, sid);
            proof.s_pok += curve::Zp::ONE;
            assert!(verify_proof(&pp1, &proof, 1, sid)
                .unwrap_err()
                .to_string()
                .contains("dlog check failed"));
        }
        {
            // note that tau=0
            let proof = make_partial_proof_deterministic(&pp1, &curve::ZeroizeZp::ZERO, 1, &r, sid);
            assert!(verify_proof(&pp1, &proof, 1, sid)
                .unwrap_err()
                .to_string()
                .contains("non-degenerative check failed"));
        }
        {
            let pp1 = make_degenerative_pp(n);
            let proof = make_partial_proof_deterministic(&pp1, &tau1, 1, &r, sid);
            assert!(verify_proof(&pp1, &proof, 1, sid)
                .unwrap_err()
                .to_string()
                .contains("non-degenerative check failed"));
        }
        {
            let mut proof = make_partial_proof_deterministic(&pp1, &tau1, 1, &r, sid);
            proof.new_pp.g1g2list.g1s.push(curve::G1::GENERATOR);
            assert!(verify_proof(&pp1, &proof, 1, sid)
                .unwrap_err()
                .to_string()
                .contains("crs length check failed (g)"));
        }
        {
            let mut proof = make_partial_proof_deterministic(&pp1, &tau1, 1, &r, sid);
            proof.new_pp.g1g2list.g2s.push(curve::G2::GENERATOR);
            assert!(verify_proof(&pp1, &proof, 1, sid)
                .unwrap_err()
                .to_string()
                .contains("crs length check failed (g_hat)"));
        }
        {
            let mut proof = make_partial_proof_deterministic(&pp1, &tau1, 1, &r, sid);
            proof.new_pp.g1g2list.g1s[n + 1] += curve::G1::GENERATOR;
            assert!(verify_proof(&pp1, &proof, 1, sid)
                .unwrap_err()
                .to_string()
                .contains("well-formedness check failed (1)"));
        }
        {
            let mut proof = make_partial_proof_deterministic(&pp1, &tau1, 1, &r, sid);
            proof.new_pp.g1g2list.g1s[n - 1] += curve::G1::GENERATOR;
            assert!(verify_proof(&pp1, &proof, 1, sid)
                .unwrap_err()
                .to_string()
                .contains("well-formedness check failed (1)"));
        }
        {
            let mut proof = make_partial_proof_deterministic(&pp1, &tau1, 1, &r, sid);
            proof.new_pp.g1g2list.g2s[1] += curve::G2::GENERATOR;
            assert!(verify_proof(&pp1, &proof, 1, sid)
                .unwrap_err()
                .to_string()
                .contains("well-formedness check failed (1)"));
        }
        {
            let mut proof = make_partial_proof_deterministic(&pp1, &tau1, 1, &r, sid);
            proof.new_pp.g1g2list.g1s[2] += curve::G1::GENERATOR;
            assert!(verify_proof(&pp1, &proof, 1, sid)
                .unwrap_err()
                .to_string()
                .contains("well-formedness check failed (2)"));
        }
        {
            let mut proof = make_partial_proof_deterministic(&pp1, &tau1, 1, &r, sid);
            proof.new_pp.g1g2list.g1s[2 * n - 1] += curve::G1::GENERATOR;
            assert!(verify_proof(&pp1, &proof, 1, sid)
                .unwrap_err()
                .to_string()
                .contains("well-formedness check failed (2)"));
        }
        {
            let mut proof = make_partial_proof_deterministic(&pp1, &tau1, 1, &r, sid);
            proof.new_pp.g1g2list.g2s[2] += curve::G2::GENERATOR;
            assert!(verify_proof(&pp1, &proof, 1, sid)
                .unwrap_err()
                .to_string()
                .contains("well-formedness check failed (2)"));
        }
        {
            let mut proof = make_partial_proof_deterministic(&pp1, &tau1, 1, &r, sid);
            proof.new_pp.g1g2list.g2s[n - 1] += curve::G2::GENERATOR;
            assert!(verify_proof(&pp1, &proof, 1, sid)
                .unwrap_err()
                .to_string()
                .contains("well-formedness check failed (2)"));
        }
        {
            let mut proof = make_partial_proof_deterministic(&pp1, &tau1, 1, &r, sid);
            proof.new_pp.g1g2list.g1s[n] = curve::G1::GENERATOR;
            assert!(verify_proof(&pp1, &proof, 1, sid)
                .unwrap_err()
                .to_string()
                .contains("the list of G1s is not correctly punctured"));
        }
    }

    #[test]
    fn test_param_computation() {
        // need number need to be consistent with what tfhe-rs gives us
        // a simple script can be used to obtain these numbers such as
        // ```
        // let params = tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        // let cpk_params = tfhe::shortint::parameters::v0_11::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        // let casting_params = tfhe::shortint::parameters::v0_11::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        // let config = tfhe::ConfigBuilder::with_custom_parameters(params)
        //     .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
        //     .build();

        // let max_bit_size = 64;
        // let crs = CompactPkeCrs::from_config(config, max_bit_size).unwrap();
        // match crs {
        //     CompactPkeCrs::PkeV1(ref public_params) => {
        //         println!("v1 n: {}", public_params.n);
        //     }
        //     CompactPkeCrs::PkeV2(ref public_params) => {
        //         println!("v2 n: {}", public_params.n);
        //     }
        // }
        // ```

        let max_bit_size = 64;

        let param_v0_11_zkv1 = tfhe::shortint::parameters::v0_11::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64_ZKV1;
        assert_eq!(
            58289,
            compute_witness_dim(&param_v0_11_zkv1, Some(max_bit_size)).unwrap()
        );

        let param_v0_11_zkv2 = tfhe::shortint::parameters::v0_11::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        assert_eq!(
            5952,
            compute_witness_dim(&param_v0_11_zkv2, Some(max_bit_size)).unwrap()
        );

        let param_v1_zkv2 = BC_PARAMS_NO_SNS
            .get_params_basics_handle()
            .get_compact_pk_enc_params();
        assert_eq!(
            5952,
            compute_witness_dim(&param_v1_zkv2, Some(max_bit_size)).unwrap()
        );
    }
}
