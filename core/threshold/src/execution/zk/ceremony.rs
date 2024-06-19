use crate::{
    algebra::structure_traits::Ring,
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::broadcast::broadcast_w_corruption, runtime::session::BaseSessionHandles,
    },
    networking::value::BroadcastValue,
};
use async_trait::async_trait;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul, Neg};
use tfhe::shortint::ClassicPBSParameters;
use tfhe_zk_pok::{curve_api::bls12_446 as curve, proofs::pke};
use tracing::instrument;
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Hash)]
pub struct PartialProof {
    h_pok: curve::Zp,
    s_pok: curve::Zp,
    pub new_pp: PublicParameter,
}

struct MetaParameter {
    big_d: usize,
    n: usize,
    d: usize,
    k: usize,
    b: u64,
    b_r: u64,
    q: u64,
    t: u64,
}

fn compute_meta_parameter(params: &ClassicPBSParameters) -> anyhow::Result<MetaParameter> {
    let params: tfhe::shortint::PBSParameters = (*params).into();
    let (size, noise_distribution) = match params.encryption_key_choice() {
        tfhe::shortint::EncryptionKeyChoice::Big => {
            let size = params
                .glwe_dimension()
                .to_equivalent_lwe_dimension(params.polynomial_size());
            (size, params.glwe_noise_distribution())
        }
        tfhe::shortint::EncryptionKeyChoice::Small => {
            (params.lwe_dimension(), params.lwe_noise_distribution())
        }
    };

    let mut plaintext_modulus = (params.message_modulus().0 * params.carry_modulus().0) as u64;
    // Our plaintext modulus does not take into account the bit of padding
    plaintext_modulus *= 2;

    // Our default parameter set will use 4 * 64
    // in the future we may set this dynamically.
    // For testing we just use 1, anything below lwe dimension 256 is
    // not likely to be secure.
    let max_num_cleartext = if size.0 >= 256 { 4 * 64 } else { 1 };
    let (d, k, b, q, t) = tfhe::zk::CompactPkeCrs::prepare_crs_parameters(
        size,
        max_num_cleartext,
        noise_distribution,
        params.ciphertext_modulus(),
        plaintext_modulus,
    )?;
    let (n, big_d, b_r) = tfhe_zk_pok::proofs::pke::compute_crs_params(d.0, k, b, q, t);

    Ok(MetaParameter {
        big_d,
        n,
        d: d.0,
        k,
        b,
        b_r,
        q,
        t,
    })
}

pub fn compute_witness_dim(params: &ClassicPBSParameters) -> anyhow::Result<usize> {
    Ok(compute_meta_parameter(params)?.n)
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Hash)]
pub struct PublicParameter {
    round: usize,
    inner: (Vec<curve::G1>, Vec<curve::G2>),
}

impl PublicParameter {
    pub fn try_into_tfhe_zk_pok_pp(
        &self,
        params: &ClassicPBSParameters,
    ) -> anyhow::Result<pke::PublicParams<tfhe_zk_pok::curve_api::Bls12_446>> {
        let MetaParameter {
            big_d,
            n,
            d,
            k,
            b,
            b_r,
            q,
            t,
        } = compute_meta_parameter(params)?;

        Ok(
            pke::PublicParams::<tfhe_zk_pok::curve_api::Bls12_446>::from_vec(
                self.inner.0.clone(),
                self.inner.1.clone(),
                big_d,
                n,
                d,
                k,
                b,
                b_r,
                q,
                t,
            ),
        )
    }

    /// Create new PublicParamter for given witness dimension containing the generators
    pub fn new(witness_dim: usize) -> Self {
        PublicParameter {
            round: 0,
            inner: (
                vec![curve::G1::GENERATOR; witness_dim * 2],
                vec![curve::G2::GENERATOR; witness_dim],
            ),
        }
    }

    pub fn new_from_tfhe_param(params: &ClassicPBSParameters) -> anyhow::Result<Self> {
        let witness_dim = compute_meta_parameter(params)?.n;
        Ok(PublicParameter {
            round: 0,
            inner: (
                vec![curve::G1::GENERATOR; witness_dim * 2],
                vec![curve::G2::GENERATOR; witness_dim],
            ),
        })
    }

    pub fn witness_dim(&self) -> usize {
        self.inner.1.len()
    }

    fn hash_to_scalars(&self, n: usize) -> Vec<curve::Zp> {
        // 8 bytes for round
        // 8 bytes for inner.0 length
        // 2*b1 * G1 point length
        // 8 bytes for inner.1 length
        // b1 * G2 point length
        let capacity = 8
            + 8
            + self.inner.0.len() * curve::G1::BYTE_SIZE
            + 8
            + self.inner.1.len() * curve::G2::BYTE_SIZE;

        // NOTE: all the usize types need to be 8 bytes
        // independent of the architecture, so we convert them to u64
        // before serialization
        let mut buf = Vec::with_capacity(capacity);
        buf.extend((self.round as u64).to_le_bytes());
        buf.extend((self.inner.0.len() as u64).to_le_bytes());
        for elem in &self.inner.0 {
            buf.extend(elem.to_bytes());
        }
        buf.extend((self.inner.1.len() as u64).to_le_bytes());
        for elem in &self.inner.1 {
            buf.extend(elem.to_bytes());
        }
        debug_assert_eq!(buf.len(), capacity);
        let mut out = vec![curve::Zp::ZERO; n];
        curve::Zp::hash(&mut out, &[&buf]);
        out
    }
}

/// Compute a new proof round.
///
/// Note that this function is deterministic, i.e. the parameters `tau` and `r` (r_{pok, j}) must be generated freshly at random outside this function.
pub fn make_proof_deterministic(
    current_pp: &PublicParameter,
    tau: curve::Zp,
    round: usize,
    r: curve::Zp,
) -> PartialProof {
    let b1 = current_pp.witness_dim();
    let tau_powers = (0..2 * b1)
        .scan(curve::Zp::ONE, |acc, _| {
            *acc = acc.mul(tau);
            Some(*acc)
        })
        .collect_vec();

    // We need to set the round number instead of
    // using current_pp.round + 1 because
    // some rounds might be skipped when malicious parties
    // do not send a valid proof.
    //
    // The scalar multiplication
    // with powers of tau is the most expensive step.
    let new_pp = PublicParameter {
        round,
        inner: (
            current_pp
                .inner
                .0
                .par_iter()
                .zip(&tau_powers)
                .map(|(g, t)| g.mul_scalar(*t))
                .collect(),
            current_pp
                .inner
                .1
                .par_iter()
                .zip(&tau_powers)
                .map(|(g, t)| g.mul_scalar(*t))
                .collect(),
        ),
    };

    let g1_jm1 = current_pp.inner.0[0]; // g_{1,j-1}
    let r_pok = g1_jm1.mul_scalar(r); // R_{pok, j}
    let g1_j = new_pp.inner.0[0]; // g_{1, j}
    let mut h_pok = vec![curve::Zp::ZERO; 1];
    curve::Zp::hash(
        &mut h_pok,
        &[&g1_j.to_bytes(), &g1_jm1.to_bytes(), &r_pok.to_bytes()],
    );
    let h_pok = h_pok[0];
    let s_pok = h_pok * (tau) + r;

    PartialProof {
        h_pok,
        s_pok,
        new_pp,
    }
}

// This function returns a custom error message
// for different types of error, so that we can
// test for different scenarios.
// But the error type should be swallowed when
// it is used in a public API.
fn verify_proof(
    current_pp: &PublicParameter,
    partial_proof: &PartialProof,
) -> anyhow::Result<PublicParameter> {
    if current_pp.round >= partial_proof.new_pp.round {
        return Err(anyhow_error_and_log("bad round number".to_string()));
    }

    let new_pp = partial_proof.new_pp.clone();
    let g1_jm1 = current_pp.inner.0[0]; // g_{1,j-1}
    let g1_j = new_pp.inner.0[0]; // g_{1, j}

    // verify the discrete log proof
    // this proof ensures that the prover
    // did not erase the previous CRS contribution
    verify_dlog_proof(partial_proof.s_pok, partial_proof.h_pok, &g1_jm1, &g1_j)?;

    // check g1_j is not zero (or 1 in multiplicative notation)
    if g1_j == curve::G1::ZERO {
        return Err(anyhow_error_and_log(
            "non-degenerative check failed".to_string(),
        ));
    }

    // I (caller) need to make sure the lengths are correct
    // the point of refernce is the current_pp
    let witness_dim = current_pp.witness_dim();
    if new_pp.inner.0.len() != witness_dim * 2 {
        return Err(anyhow_error_and_log(
            "crs length check failed (g)".to_string(),
        ));
    }

    if new_pp.witness_dim() != witness_dim {
        return Err(anyhow_error_and_log(
            "crs length check failed (g_hat)".to_string(),
        ));
    }

    // perform the well-formedness check
    // this check guarantees that the prover
    // is raising the elements in the CRS by the correct powers of tau
    verify_wellformedness(&new_pp)?;

    Ok(new_pp)
}

fn verify_dlog_proof(
    s_pok: curve::Zp,
    h_pok: curve::Zp,
    g1_jm1: &curve::G1,
    g1_j: &curve::G1,
) -> anyhow::Result<()> {
    let g1_to_s = g1_jm1.mul_scalar(s_pok);
    let g1_to_h = g1_j.mul_scalar(h_pok.neg());
    let h_pok_2 = {
        let tmp = g1_to_s.add(g1_to_h);
        let mut out = vec![curve::Zp::ZERO; 1];
        curve::Zp::hash(
            &mut out,
            &[&g1_j.to_bytes(), &g1_jm1.to_bytes(), &tmp.to_bytes()],
        );
        out[0]
    };

    if h_pok_2 != h_pok {
        return Err(anyhow_error_and_log("dlog check failed".to_string()));
    }
    Ok(())
}

fn verify_wellformedness(new_pp: &PublicParameter) -> anyhow::Result<()> {
    // verify the other parts of the new CRS
    let rhos = new_pp.hash_to_scalars(2);
    let b1 = new_pp.witness_dim();
    debug_assert_eq!(new_pp.inner.0.len(), b1 * 2);

    // e(\tau_j^{B1+2} [G1], [G2]) = e(\tau_j^{B1} [G1], \tau_j^2 [G2])
    let e = curve::Gt::pairing;
    if e(new_pp.inner.0[b1 + 1], curve::G2::GENERATOR)
        != e(new_pp.inner.0[b1 - 1], new_pp.inner.1[1])
    {
        return Err(anyhow_error_and_log(
            "well-formedness check failed (1)".to_string(),
        ));
    }

    // powers of rho start at rho^0
    let rho0_powers = std::iter::once(curve::Zp::ONE)
        .chain((0..2 * b1 - 1).scan(curve::Zp::ONE, |acc, _| {
            *acc = acc.mul(rhos[0]);
            Some(*acc)
        }))
        .collect_vec();
    let rho1_powers = std::iter::once(curve::Zp::ONE)
        .chain((0..b1 - 1).scan(curve::Zp::ONE, |acc, _| {
            *acc = acc.mul(rhos[1]);
            Some(*acc)
        }))
        .collect_vec();

    let lhs0 = new_pp
        .inner
        .0
        .par_iter()
        .enumerate()
        .filter_map(|(i, g)| {
            if i == b1 || i == b1 + 1 {
                None
            } else {
                Some(g.mul_scalar(rho0_powers[i]))
            }
        })
        .sum::<curve::G1>();

    let lhs1 = new_pp
        .inner
        .1
        .par_iter()
        .take(b1 - 1)
        .enumerate()
        .map(|(l, g_hat)| g_hat.mul_scalar(rho1_powers[l + 1]))
        .sum::<curve::G2>()
        .add(curve::G2::GENERATOR);

    debug_assert_eq!(new_pp.inner.0.len(), b1 * 2);
    let rhs0 = new_pp
        .inner
        .0
        .par_iter()
        .take(b1 * 2 - 1)
        .enumerate()
        .filter_map(|(i, g)| {
            if i == b1 - 1 || i == b1 {
                None
            } else {
                Some(g.mul_scalar(rho0_powers[i + 1]))
            }
        })
        .sum::<curve::G1>()
        .add(curve::G1::GENERATOR);

    let rhs1 = new_pp
        .inner
        .1
        .par_iter()
        .enumerate()
        .map(|(l, g_hat)| g_hat.mul_scalar(rho1_powers[l]))
        .sum::<curve::G2>();

    if e(lhs0, lhs1) != e(rhs0, rhs1) {
        return Err(anyhow_error_and_log(
            "well-formedness check failed (2)".to_string(),
        ));
    }

    Ok(())
}

#[async_trait]
pub trait Ceremony: Send + Sync + Clone + Default {
    async fn execute<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
        witness_dim: usize,
    ) -> anyhow::Result<PublicParameter>;
}

#[derive(Default, Clone)]
pub struct RealCeremony {}

#[async_trait]
impl Ceremony for RealCeremony {
    #[instrument(name = "CRS-Ceremony", skip_all)]
    async fn execute<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
        witness_dim: usize,
    ) -> anyhow::Result<PublicParameter> {
        // the parties need to execute the protocol in a deterministic order
        // so we sort the roles to fix this order
        // even if the adversary can pick the order, it does not affect the security
        let mut all_roles_sorted = session.role_assignments().keys().copied().collect_vec();
        all_roles_sorted.sort();
        let my_role = session.my_role()?;

        let mut pp = PublicParameter::new(witness_dim);
        tracing::info!(
            "Role {my_role} starting CRS ceremony in session {}",
            session.session_id()
        );

        for (round, role) in all_roles_sorted.iter().enumerate() {
            if role == &my_role {
                // We use the rayon's threadpool for handling CPU-intensive tasks
                // like creating the CRS. This is recommended over tokio::task::spawn_blocking
                // since the tokio threadpool has a very high default upper limit.
                // More info: https://ryhl.io/blog/async-what-is-blocking/
                let mut tau = curve::Zp::rand(&mut session.rng());
                let mut r = curve::Zp::rand(&mut session.rng());
                let (send, recv) = tokio::sync::oneshot::channel();
                rayon::spawn(move || {
                    let partial_proof = make_proof_deterministic(&pp, tau, round + 1, r);
                    tau.zeroize();
                    r.zeroize();
                    let _ = send.send(partial_proof);
                });

                // WARNING: [tau] and [r] are of Type [Zp] which is a [Copy].
                // this means if they're used again outside of [rayon::spawn],
                // then the secret data is copied implicitly.
                // Do not use [tau] and [r] again outside of the rayon
                // thread since that would implicitly copy secret data.

                let proof = recv.await?;
                let vi = BroadcastValue::PartialProof::<Z>(proof.clone());

                // nobody else should be broadcasting so we do not process results
                // since I know I'm honest, this step should never fail since
                // we're running a robust protocol
                let _ = broadcast_w_corruption(session, &[my_role], Some(vi)).await?;

                // update our pp
                pp = proof.new_pp;
            } else {
                // do the following if it is not my turn to contribute
                match broadcast_w_corruption::<Z, _, _>(session, &[*role], None).await {
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
                                    rayon::spawn(move || {
                                        let res = verify_proof(&pp, &proof);
                                        let _ = send.send((res, pp));
                                    });
                                    let (ver, pp_tmp) = recv.await?;
                                    pp = pp_tmp;
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
                                    "unexpected sender in crs ceremony, expecte {role} got {sender}"
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

        Ok(pp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        algebra::residue_poly::ResiduePoly64,
        execution::runtime::{
            session::{LargeSession, ParameterHandles},
            test_runtime::{generate_fixed_identities, DistributedTestRuntime},
        },
        session_id::SessionId,
        tests::helper::tests::{
            execute_protocol_large_w_disputes_and_malicious, TestingParameters,
        },
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use rstest::rstest;
    use std::collections::HashMap;
    use tfhe_zk_pok::{curve_api::Bls12_446, proofs};
    use tokio::task::JoinSet;

    #[derive(Clone, Default)]
    struct InsecureCeremony {}

    #[async_trait]
    impl Ceremony for InsecureCeremony {
        async fn execute<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
            &self,
            session: &mut S,
            witness_dim: usize,
        ) -> anyhow::Result<PublicParameter> {
            Ok(PublicParameter {
                round: session.num_parties(),
                inner: (
                    vec![curve::G1::GENERATOR; witness_dim * 2],
                    vec![curve::G2::GENERATOR; witness_dim],
                ),
            })
        }
    }

    #[test]
    fn test_honest_crs_ceremony_secure() {
        test_honest_crs_ceremony(RealCeremony::default)
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
        let runtime: DistributedTestRuntime<ResiduePoly64> =
            DistributedTestRuntime::new(identities, threshold as u8);

        let session_id = SessionId(2);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        for (index_id, _identity) in runtime.identities.clone().into_iter().enumerate() {
            let mut session = runtime.large_session_for_party(session_id, index_id);
            let ceremony = ceremony_f();
            set.spawn(async move {
                let out = ceremony
                    .execute::<ResiduePoly64, _, _>(&mut session, witness_dim)
                    .await
                    .unwrap();
                (session.my_role().unwrap(), out)
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

        let pp = results.first().unwrap().1.clone();
        assert_eq!(pp.round, num_parties);
        for (_, p) in results {
            assert_eq!(p, pp);
        }

        // check that we can use pp to make a proof
        let mut rng = AesRng::from_entropy();
        let public_params =
            proofs::range::PublicParams::<Bls12_446>::from_vec(pp.inner.0, pp.inner.1);
        let l = 6;
        let x = rng.gen::<u64>() % (1 << l);
        let (public_commit, private_commit) = proofs::range::commit(x, l, &public_params, &mut rng);
        let proof =
            proofs::range::prove((&public_params, &public_commit), &private_commit, &mut rng);
        let verify = proofs::range::verify(&proof, (&public_params, &public_commit));
        assert!(verify.is_ok());
    }

    /// create all-zero public parameters
    fn make_degenerative_pp(n: usize) -> PublicParameter {
        PublicParameter {
            round: 0,
            inner: (vec![curve::G1::ZERO; 2 * n], vec![curve::G2::ZERO; n]),
        }
    }

    #[derive(Clone, Default)]
    struct DroppingCeremony {}

    #[async_trait]
    impl Ceremony for DroppingCeremony {
        async fn execute<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
            &self,
            session: &mut S,
            _crs_size: usize,
        ) -> anyhow::Result<PublicParameter> {
            // do nothing
            Ok(PublicParameter::new(session.num_parties()))
        }
    }

    #[derive(Clone, Default)]
    struct BadProofCeremony {}

    #[async_trait]
    impl Ceremony for BadProofCeremony {
        async fn execute<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
            &self,
            session: &mut S,
            witness_dim: usize,
        ) -> anyhow::Result<PublicParameter> {
            let mut all_roles_sorted = session.role_assignments().keys().copied().collect_vec();
            all_roles_sorted.sort();
            let my_role = session.my_role()?;

            let mut pp = PublicParameter::new(witness_dim);

            for (round, role) in all_roles_sorted.iter().enumerate() {
                if role == &my_role {
                    let tau = curve::Zp::rand(&mut session.rng());
                    let r = curve::Zp::rand(&mut session.rng());
                    // make a bad proof
                    let mut proof: PartialProof = make_proof_deterministic(&pp, tau, round + 1, r);
                    proof.h_pok += curve::Zp::ONE;
                    let vi = BroadcastValue::PartialProof::<Z>(proof.clone());

                    let _ = broadcast_w_corruption(session, &[my_role], Some(vi)).await?;
                    pp = proof.new_pp;
                } else {
                    let hm = broadcast_w_corruption::<Z, _, _>(session, &[*role], None)
                        .await
                        .unwrap();
                    let msg = hm.get(role).unwrap();
                    if let BroadcastValue::PartialProof(proof) = msg {
                        pp = proof.new_pp.clone();
                    }
                }
            }

            Ok(pp)
        }
    }

    #[derive(Clone, Default)]
    struct RushingCeremony {}

    #[async_trait]
    impl Ceremony for RushingCeremony {
        // this implements an adversary that rushes the protocol,
        // i.e., it starts before it is his turn to do run
        async fn execute<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
            &self,
            session: &mut S,
            witness_dim: usize,
        ) -> anyhow::Result<PublicParameter> {
            let mut all_roles_sorted = session.role_assignments().keys().copied().collect_vec();
            all_roles_sorted.sort();
            let my_role = session.my_role()?;

            let pp = PublicParameter {
                round: 0,
                inner: (
                    vec![curve::G1::GENERATOR; witness_dim * 2],
                    vec![curve::G2::GENERATOR; witness_dim],
                ),
            };

            for (round, role) in all_roles_sorted.iter().enumerate() {
                let tau = curve::Zp::rand(&mut session.rng());
                let r = curve::Zp::rand(&mut session.rng());
                let proof: PartialProof = make_proof_deterministic(&pp, tau, round + 1, r);
                let vi = BroadcastValue::PartialProof::<Z>(proof.clone());
                if role == &my_role {
                    let _ = broadcast_w_corruption(session, &[my_role], Some(vi)).await?;
                } else {
                    // the message sent by `my_role`, the adversary, should be ignored
                    let _ = broadcast_w_corruption(session, &[my_role, *role], Some(vi)).await?;
                }
            }

            Ok(pp)
        }
    }

    fn test_ceremony_strategies_large<Z: Ring, C: Ceremony + 'static>(
        params: TestingParameters,
        witness_dim: usize,
        malicious_party: C,
    ) {
        let mut task_honest = |mut session: LargeSession| async move {
            let real_ceremony = RealCeremony::default();
            (
                session.my_role().unwrap().zero_based(),
                real_ceremony
                    .execute::<Z, _, _>(&mut session, witness_dim)
                    .await
                    .unwrap(),
                session.corrupt_roles().clone(),
            )
        };

        let mut task_malicious = |mut session: LargeSession, malicious_party: C| async move {
            let _ = malicious_party
                .execute::<Z, _, _>(&mut session, witness_dim)
                .await;
            session.my_role().unwrap().zero_based()
        };

        let (results_honest, _) = execute_protocol_large_w_disputes_and_malicious::<Z, _, _, _, _, _>(
            &params,
            &[],
            &params.malicious_roles,
            malicious_party,
            &mut task_honest,
            &mut task_malicious,
        );

        // the honest results should be a valid crs and not the initial one
        let honest_pp = results_honest.iter().map(|(_, pp, _)| pp).collect_vec();
        let pp = honest_pp[0].clone();
        // make sure we're not using the initial pp
        assert_ne!(pp.inner.0[0], pp.inner.0[1]);
        assert_ne!(pp.inner.1[0], pp.inner.1[1]);
        for other in honest_pp {
            assert_eq!(&pp, other);
        }
    }

    #[rstest]
    #[case(TestingParameters::init(4,1,&[1],&[],&[],false,None), 4)]
    #[case(TestingParameters::init(4,1,&[0],&[],&[],false,None), 4)]
    fn test_dropping_ceremony(#[case] params: TestingParameters, #[case] witness_dim: usize) {
        let malicious_party = DroppingCeremony::default();
        test_ceremony_strategies_large::<ResiduePoly64, _>(
            params.clone(),
            witness_dim,
            malicious_party.clone(),
        );
    }

    #[rstest]
    #[case(TestingParameters::init(4,1,&[1],&[],&[],false,None), 4)]
    #[case(TestingParameters::init(4,1,&[0],&[],&[],false,None), 4)]
    fn test_bad_proof_ceremony(#[case] params: TestingParameters, #[case] witness_dim: usize) {
        let malicious_party = BadProofCeremony::default();
        test_ceremony_strategies_large::<ResiduePoly64, _>(
            params.clone(),
            witness_dim,
            malicious_party.clone(),
        );
    }

    #[rstest]
    #[case(TestingParameters::init(4,1,&[1],&[],&[],false,None), 4)]
    #[case(TestingParameters::init(4,1,&[0],&[],&[],false,None), 4)]
    fn test_rushing_ceremony(#[case] params: TestingParameters, #[case] witness_dim: usize) {
        let malicious_party = RushingCeremony::default();
        test_ceremony_strategies_large::<ResiduePoly64, _>(
            params.clone(),
            witness_dim,
            malicious_party.clone(),
        );
    }

    #[test]
    fn test_pairing() {
        // sanity check for the pairing operation
        let mut rng = AesRng::seed_from_u64(42);
        let tau = curve::Zp::rand(&mut rng);
        let r = curve::Zp::rand(&mut rng);
        let tau_powers = (0..2 * 2)
            .scan(curve::Zp::ONE, |acc, _| {
                *acc = acc.mul(tau);
                Some(*acc)
            })
            .collect_vec();

        let e = curve::Gt::pairing;
        assert_eq!(
            e(
                curve::G1::GENERATOR.mul_scalar(tau_powers[3]),
                curve::G2::GENERATOR
            ),
            e(
                curve::G1::GENERATOR.mul_scalar(tau_powers[1]),
                curve::G2::GENERATOR.mul_scalar(tau_powers[1])
            )
        );

        let pp = PublicParameter::new(2);
        let proof = make_proof_deterministic(&pp, tau, 0, r);
        assert_eq!(
            proof.new_pp.inner.0[3],
            curve::G1::GENERATOR.mul_scalar(tau_powers[3])
        );
        assert_eq!(
            proof.new_pp.inner.0[1],
            curve::G1::GENERATOR.mul_scalar(tau_powers[1])
        );
        assert_eq!(
            proof.new_pp.inner.1[1],
            curve::G2::GENERATOR.mul_scalar(tau_powers[1])
        );
    }

    #[test]
    fn test_intermediate_proof() {
        let n = 4usize;
        let mut rng = AesRng::seed_from_u64(42);
        let pp1 = PublicParameter::new(n);
        let tau1 = curve::Zp::rand(&mut rng);
        let r = curve::Zp::rand(&mut rng);

        assert_eq!(pp1.inner.0.len(), n * 2);
        assert_eq!(pp1.inner.1.len(), n);

        {
            // first round
            let proof1 = make_proof_deterministic(&pp1, tau1, 1, r);
            assert!(verify_proof(&pp1, &proof1).is_ok());

            // second round
            let pp2 = proof1.new_pp;
            let tau2 = curve::Zp::rand(&mut rng);
            let proof2 = make_proof_deterministic(&pp2, tau2, 2, r);
            assert!(verify_proof(&pp2, &proof2).is_ok());
        }
        {
            let proof = make_proof_deterministic(&pp1, tau1, 0, r);
            assert!(verify_proof(&pp1, &proof)
                .unwrap_err()
                .to_string()
                .contains("bad round number"));
        }
        {
            let mut proof = make_proof_deterministic(&pp1, tau1, 1, r);
            proof.h_pok += curve::Zp::ONE;
            assert!(verify_proof(&pp1, &proof)
                .unwrap_err()
                .to_string()
                .contains("dlog check failed"));
        }
        {
            let mut proof = make_proof_deterministic(&pp1, tau1, 1, r);
            proof.s_pok += curve::Zp::ONE;
            assert!(verify_proof(&pp1, &proof)
                .unwrap_err()
                .to_string()
                .contains("dlog check failed"));
        }
        {
            // note that tau=0
            let proof = make_proof_deterministic(&pp1, curve::Zp::ZERO, 1, r);
            assert!(verify_proof(&pp1, &proof)
                .unwrap_err()
                .to_string()
                .contains("non-degenerative check failed"));
        }
        {
            let pp1 = make_degenerative_pp(n);
            let proof = make_proof_deterministic(&pp1, tau1, 1, r);
            assert!(verify_proof(&pp1, &proof)
                .unwrap_err()
                .to_string()
                .contains("non-degenerative check failed"));
        }
        {
            let mut proof = make_proof_deterministic(&pp1, tau1, 1, r);
            proof.new_pp.inner.0.push(curve::G1::GENERATOR);
            assert!(verify_proof(&pp1, &proof)
                .unwrap_err()
                .to_string()
                .contains("crs length check failed (g)"));
        }
        {
            let mut proof = make_proof_deterministic(&pp1, tau1, 1, r);
            proof.new_pp.inner.1.push(curve::G2::GENERATOR);
            assert!(verify_proof(&pp1, &proof)
                .unwrap_err()
                .to_string()
                .contains("crs length check failed (g_hat)"));
        }
        {
            let mut proof = make_proof_deterministic(&pp1, tau1, 1, r);
            proof.new_pp.inner.0[n + 1] += curve::G1::GENERATOR;
            assert!(verify_proof(&pp1, &proof)
                .unwrap_err()
                .to_string()
                .contains("well-formedness check failed (1)"));
        }
        {
            let mut proof = make_proof_deterministic(&pp1, tau1, 1, r);
            proof.new_pp.inner.0[n - 1] += curve::G1::GENERATOR;
            assert!(verify_proof(&pp1, &proof)
                .unwrap_err()
                .to_string()
                .contains("well-formedness check failed (1)"));
        }
        {
            let mut proof = make_proof_deterministic(&pp1, tau1, 1, r);
            proof.new_pp.inner.1[1] += curve::G2::GENERATOR;
            assert!(verify_proof(&pp1, &proof)
                .unwrap_err()
                .to_string()
                .contains("well-formedness check failed (1)"));
        }
        {
            let mut proof = make_proof_deterministic(&pp1, tau1, 1, r);
            proof.new_pp.inner.0[2] += curve::G1::GENERATOR;
            assert!(verify_proof(&pp1, &proof)
                .unwrap_err()
                .to_string()
                .contains("well-formedness check failed (2)"));
        }
        {
            let mut proof = make_proof_deterministic(&pp1, tau1, 1, r);
            proof.new_pp.inner.0[2 * n - 1] += curve::G1::GENERATOR;
            assert!(verify_proof(&pp1, &proof)
                .unwrap_err()
                .to_string()
                .contains("well-formedness check failed (2)"));
        }
        {
            let mut proof = make_proof_deterministic(&pp1, tau1, 1, r);
            proof.new_pp.inner.1[2] += curve::G2::GENERATOR;
            assert!(verify_proof(&pp1, &proof)
                .unwrap_err()
                .to_string()
                .contains("well-formedness check failed (2)"));
        }
        {
            let mut proof = make_proof_deterministic(&pp1, tau1, 1, r);
            proof.new_pp.inner.1[n - 1] += curve::G2::GENERATOR;
            assert!(verify_proof(&pp1, &proof)
                .unwrap_err()
                .to_string()
                .contains("well-formedness check failed (2)"));
        }
    }
}
