use super::{
    agree_random::AgreeRandom,
    prf::{ChiAes, PRSSConversions, PsiAes},
};
use crate::{
    algebra::{
        bivariate::{compute_powers_list, MatrixMul},
        poly::Poly,
        structure_traits::Ring,
    },
    commitment::KEY_BYTE_LEN,
    computation::SessionId,
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::broadcast::broadcast_from_all_w_corruption,
        constants::PRSS_SIZE_MAX,
        large_execution::{single_sharing::init_vdm, vss::Vss},
        runtime::{
            party::Role,
            session::{BaseSessionHandles, ParameterHandles, SmallSessionHandles},
        },
        sharing::{
            open::robust_opens_to_all,
            shamir::{ErrorCorrect, HenselLiftInverse, RingEmbed},
        },
        small_execution::prf::{chi, phi, psi, PhiAes},
    },
    networking::value::BroadcastValue,
};
use anyhow::Context;
use itertools::Itertools;
use ndarray::{ArrayD, IxDyn};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::clone::Clone;
use std::collections::{HashMap, HashSet};
use std::default::Default;

pub(crate) fn create_sets(n: usize, t: usize) -> Vec<Vec<usize>> {
    (1..=n).combinations(n - t).collect()
}

#[derive(Debug, Clone)]
struct PrfAes {
    phi_aes: PhiAes,
    psi_aes: PsiAes,
    chi_aes: ChiAes,
}

/// structure for holding values for each subset of n-t parties
#[derive(Debug, Clone)]
pub struct PrssSet<Z> {
    parties: PartySet,
    prfs: Option<PrfAes>,
    set_key: PrfKey,
    f_a_points: Vec<Z>,
}

enum ComputeShareMode {
    Prss,
    Przs,
}

/// Structure to hold a n-t sized structure of party IDs
/// Assumed to be stored in increasing order, with party IDs starting from 1
pub type PartySet = Vec<usize>;

/// Structure holding the votes (in the HashSet) for different vectors of values, where each party votes for one vector
/// Note that for PRSS each vector is of length 1, while for PRZS the vectors are of length t
type ValueVotes<Z> = HashMap<Vec<Z>, HashSet<Role>>;

/// PRSS object that holds info in a certain epoch for a single party Pi
#[derive(Debug, Clone)]
pub struct PRSSSetup<Z: Default + Clone> {
    /// all possible subsets of n-t parties (A) that contain Pi and their shared PRG
    sets: Vec<PrssSet<Z>>,
    alpha_powers: Vec<Vec<Z>>,
}

/// PRSS state for use within a given session.
#[derive(Debug, Clone)]
pub struct PRSSState<Z: Default + Clone> {
    /// counters that increases on every call to the respective .next()
    pub mask_ctr: u128,
    pub prss_ctr: u128,
    pub przs_ctr: u128,
    /// PRSSSetup
    prss_setup: PRSSSetup<Z>,
}

/// key for blake3
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub struct PrfKey(pub [u8; 16]);

/// computes the points on the polys f_A for all parties in the given sets A
/// f_A is one at 0, and zero at the party indices not in set A
fn party_compute_f_a_points<Z: Ring + RingEmbed + HenselLiftInverse>(
    partysets: &Vec<PartySet>,
    num_parties: usize,
) -> anyhow::Result<Vec<Vec<Z>>> {
    let (normalized_parties_root, x_coords) = Poly::<Z>::normalized_parties_root(num_parties)?;

    let mut sets = Vec::new();

    // iterate through the A sets
    for s in partysets {
        // compute poly for this combination of parties
        // poly will be of degree T, zero at the points p not in s, and one at 0
        let mut poly = Poly::from_coefs(vec![Z::ONE]);
        for p in 1..=num_parties {
            if !s.contains(&p) {
                poly = poly * normalized_parties_root[p - 1].clone();
            }
        }

        // check that poly is 1 at position 0
        debug_assert_eq!(Z::ONE, poly.eval(&Z::ZERO));
        // check that poly is of degree t
        debug_assert_eq!(num_parties - s.len(), poly.deg());

        // evaluate the poly at the party indices gamma
        let points: Vec<_> = (1..=num_parties).map(|p| poly.eval(&x_coords[p])).collect();
        sets.push(points);
    }
    Ok(sets)
}

/// Precomputes powers of embedded party ids: alpha_i^j for all i in n and all j in t.
/// This is used in the chi prf in the PRZS
fn embed_parties_and_compute_alpha_powers<Z>(
    num_parties: usize,
    threshold: usize,
) -> anyhow::Result<Vec<Vec<Z>>>
where
    Z: Ring,
    Z: RingEmbed,
{
    let parties: Vec<_> = (1..=num_parties)
        .map(Z::embed_exceptional_set)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(compute_powers_list(&parties, threshold))
}

impl<Z> PRSSState<Z>
where
    Z: Ring,
    Z: RingEmbed,
    Z: HenselLiftInverse,
    Z: PRSSConversions,
{
    /// PRSS-Mask.Next() for a single party
    /// TODO: possibly change to Role as parameter instead of party_id
    pub fn mask_next(&mut self, party_id: usize, bd1: u128) -> anyhow::Result<Z> {
        // party IDs start from 1
        debug_assert!(party_id > 0);

        let mut res = Z::ZERO;

        for set in self.prss_setup.sets.iter_mut() {
            if set.parties.contains(&party_id) {
                if let Some(aes_prf) = &set.prfs {
                    let phi0 = phi(&aes_prf.phi_aes, self.mask_ctr, bd1)?;
                    let phi1 = phi(&aes_prf.phi_aes, self.mask_ctr + 1, bd1)?;
                    let phi = phi0 + phi1;

                    // compute f_A(alpha_i), where alpha_i is simply the embedded party ID, so we can just index into the f_a_points
                    let f_a = set.f_a_points[party_id - 1];

                    // we can treat the signed phi value as unsigned here. This conversion will handle negative values correctly and as expected.
                    res += f_a * Z::from_i128(phi);
                } else {
                    return Err(anyhow_error_and_log(
                        "PRFs not properly initialized!".to_string(),
                    ));
                }
            } else {
                return Err(anyhow_error_and_log(format!("Called prss.mask_next() with party ID {party_id} that is not in a precomputed set of parties!")));
            }
        }

        // increase counter by two, since we have two phi calls above
        self.mask_ctr += 2;

        Ok(res)
    }

    /// PRSS.Next() for a single party
    pub fn prss_next(&mut self, party_id: usize) -> anyhow::Result<Z> {
        // party IDs start from 1
        debug_assert!(party_id > 0);

        let mut res = Z::ZERO;

        for set in self.prss_setup.sets.iter_mut() {
            if set.parties.contains(&party_id) {
                if let Some(aes_prf) = &set.prfs {
                    let psi = psi(&aes_prf.psi_aes, self.prss_ctr)?;

                    // compute f_A(alpha_i), where alpha_i is simply the embedded party ID, so we can just index into the f_a_points
                    let f_a = set.f_a_points[party_id - 1];

                    res += f_a * psi;
                } else {
                    return Err(anyhow_error_and_log(
                        "PRFs not properly initialized!".to_string(),
                    ));
                }
            } else {
                return Err(anyhow_error_and_log(format!("Called prss.next() with party ID {party_id} that is not in a precomputed set of parties!")));
            }
        }

        self.prss_ctr += 1;

        Ok(res)
    }

    /// PRZS.Next() for a single party
    /// `party_id`: The 1-index party ID.
    /// `t`: The threshold parameter for the session
    pub fn przs_next(&mut self, party_id: usize, threshold: u8) -> anyhow::Result<Z> {
        // party IDs start from 1
        debug_assert!(party_id > 0);

        let mut res = Z::ZERO;

        for set in self.prss_setup.sets.iter_mut() {
            if set.parties.contains(&party_id) {
                if let Some(aes_prf) = &set.prfs {
                    for j in 1..=threshold {
                        let chi = chi(&aes_prf.chi_aes, self.przs_ctr, j)?;
                        // compute f_A(alpha_i), where alpha_i is simply the embedded party ID, so we can just index into the f_a_points
                        let f_a = set.f_a_points[party_id - 1];
                        // power of alpha_i^j
                        let alpha_j = self.prss_setup.alpha_powers[party_id - 1][j as usize];
                        res += f_a * alpha_j * chi;
                    }
                } else {
                    return Err(anyhow_error_and_log(
                        "PRFs not properly initialized!".to_string(),
                    ));
                }
            } else {
                return Err(anyhow_error_and_log(format!("Called przs.next() with party ID {party_id} that is not in a precomputed set of parties!")));
            }
        }

        self.przs_ctr += 1;

        Ok(res)
    }

    /// Compute the PRSS.check() method which returns the summed up psi value for each party based on the supplied counter `ctr`.
    /// If parties are behaving maliciously they get added to the corruption list in [SmallSessionHandles]
    pub async fn prss_check<R: Rng + CryptoRng, S: SmallSessionHandles<Z, R>>(
        &self,
        session: &mut S,
        ctr: u128,
    ) -> anyhow::Result<HashMap<Role, Z>> {
        let sets = &self.prss_setup.sets;
        let mut psi_values = Vec::with_capacity(sets.len());
        for cur_set in sets {
            if let Some(aes_prf) = &cur_set.prfs {
                let psi = vec![psi(&aes_prf.psi_aes, ctr)?];
                psi_values.push((cur_set.parties.clone(), psi));
            } else {
                return Err(anyhow_error_and_log(
                    "PRFs not properly initialized!".to_string(),
                ));
            }
        }
        let broadcast_result = broadcast_from_all_w_corruption::<Z, R, S>(
            session,
            BroadcastValue::PRSSVotes(psi_values),
        )
        .await?;

        // Count the votes received from the broadcast
        let count = Self::count_votes(&broadcast_result, session)?;
        // Find which values have received most votes
        let true_psi_vals = Self::find_winning_prf_values(&count)?;
        // Find the parties who did not vote for the results and add them to the corrupt set
        Self::handle_non_voting_parties(&true_psi_vals, &count, session)?;
        // Compute result based on majority votes
        Self::compute_party_shares(&true_psi_vals, session, ComputeShareMode::Prss)
    }

    /// Compute the PRZS.check() method which returns the summed up chi value for each party based on the supplied counter `ctr`.
    /// If parties are behaving maliciously they get added to the corruption list in [SmallSessionHandles]
    pub async fn przs_check<R: Rng + CryptoRng, S: SmallSessionHandles<Z, R>>(
        &self,
        session: &mut S,
        ctr: u128,
    ) -> anyhow::Result<HashMap<Role, Z>> {
        let sets = &self.prss_setup.sets;
        let mut chi_values = Vec::with_capacity(sets.len());
        for cur_set in sets {
            if let Some(aes_prf) = &cur_set.prfs {
                let mut chi_list = Vec::with_capacity(session.threshold() as usize);
                for j in 1..=session.threshold() {
                    chi_list.push(chi(&aes_prf.chi_aes, ctr, j)?);
                }
                chi_values.push((cur_set.parties.clone(), chi_list.clone()));
            } else {
                return Err(anyhow_error_and_log(
                    "PRFs not properly initialized!".to_string(),
                ));
            }
        }

        let broadcast_result = broadcast_from_all_w_corruption::<Z, R, S>(
            session,
            BroadcastValue::PRSSVotes(chi_values),
        )
        .await?;

        // Count the votes received from the broadcast
        let count = Self::count_votes(&broadcast_result, session)?;
        // Find which values have received most votes
        let true_chi_vals = Self::find_winning_prf_values(&count)?;
        // Find the parties who did not vote for the results and add them to the corrupt set
        Self::handle_non_voting_parties(&true_chi_vals, &count, session)?;
        // Compute result based on majority votes
        Self::compute_party_shares(&true_chi_vals, session, ComputeShareMode::Przs)
    }

    /// Helper method for counting the votes. Takes the `broadcast_result` and counts which parties has voted/replied each of the different [Value]s for each given [PrssSet].
    /// The result is a map from each unique received [PrssSet] to another map which maps from all possible received [Value]s associated
    /// with the [PrssSet] to the set of [Role]s which has voted/replied to the specific [Value] for the specific [PrssSet].
    fn count_votes<R: Rng + CryptoRng, S: SmallSessionHandles<Z, R>>(
        broadcast_result: &HashMap<Role, BroadcastValue<Z>>,
        session: &mut S,
    ) -> anyhow::Result<HashMap<PartySet, ValueVotes<Z>>> {
        // We count through a set of voting roles in order to avoid one party voting for the same value multiple times
        let mut count: HashMap<PartySet, ValueVotes<Z>> = HashMap::new();
        for (role, broadcast_val) in broadcast_result {
            let vec_pairs = match broadcast_val {
                BroadcastValue::PRSSVotes(vec_values) => vec_values,
                // If the party does not broadcast the type as expected they are considered malicious
                _ => {
                    session.add_corrupt(*role)?;
                    tracing::warn!("Party with role {:?} and identity {:?} sent values they shouldn't and is thus malicious",
                     role.one_based(), session.role_assignments().get(role));
                    continue;
                }
            };
            // Count the votes received from `role` during broadcast for each [PrssSet]
            for prss_value_pair in vec_pairs {
                let (prss_set, prf_val) = prss_value_pair;
                match count.get_mut(prss_set) {
                    Some(value_votes) => Self::add_vote(value_votes, prf_val, *role, session)?,
                    None => {
                        count.insert(
                            prss_set.clone(),
                            HashMap::from([(prf_val.clone(), HashSet::from([*role]))]),
                        );
                    }
                };
            }
        }
        Ok(count)
    }

    /// Helper method that uses a prf value, `cur_prf_val`, and counts it in `value_votes`, associated to `cur_role`.
    /// That is, if it is not present in `value_votes` it gets added and in either case `cur_role` gets counted as having
    /// voted for `cur_prf_val`.
    /// In case `cur_role` has already voted for `cur_prf_val` they get added to the list of corrupt parties.
    fn add_vote<R: Rng + CryptoRng, S: SmallSessionHandles<Z, R>>(
        value_votes: &mut ValueVotes<Z>,
        cur_prf_val: &Vec<Z>,
        cur_role: Role,
        session: &mut S,
    ) -> anyhow::Result<()> {
        match value_votes.get_mut(cur_prf_val) {
            Some(existing_roles) => {
                // If it has been seen before, insert the current contributing role
                let role_inserted = existing_roles.insert(cur_role);
                if !role_inserted {
                    // If the role was not inserted then it was already present and hence the party is trying to vote multiple times
                    // and they should be marked as corrupt
                    session.add_corrupt(cur_role)?;
                    tracing::warn!("Party with role {:?} and identity {:?} is trying to vote for the same prf value more than once and is thus malicious",
                         cur_role.one_based(), session.role_assignments().get(&cur_role));
                }
            }
            None => {
                value_votes.insert(cur_prf_val.clone(), HashSet::from([cur_role]));
            }
        };
        Ok(())
    }

    /// Helper method for finding which values have received most votes
    /// Takes as input the counts of the different PRF values from each of the parties and finds the value received
    /// by most parties for each entry in the [PrssSet].
    /// Returns a [HashMap] mapping each of the sets in [PrssSet] to the [Value] received by most parties for this set.
    fn find_winning_prf_values(
        count: &HashMap<PartySet, ValueVotes<Z>>,
    ) -> anyhow::Result<HashMap<&PartySet, &Vec<Z>>> {
        let mut true_prf_vals = HashMap::with_capacity(count.len());
        for (prss_set, value_votes) in count {
            let (value_max, _) = value_votes
                .iter()
                .max_by_key(|&(_, votes)| votes.len())
                .with_context(|| "No votes found!")?;

            true_prf_vals.insert(prss_set, value_max);
        }
        Ok(true_prf_vals)
    }

    /// Helper method for finding the parties who did not vote for the results and add them to the corrupt set.
    /// Goes through `true_prf_vals` and find which parties did not vote for the psi values it contains.
    /// This is done by cross-referencing the votes in `count`
    fn handle_non_voting_parties<R: Rng + CryptoRng, S: SmallSessionHandles<Z, R>>(
        true_prf_vals: &HashMap<&PartySet, &Vec<Z>>,
        count: &HashMap<PartySet, ValueVotes<Z>>,
        session: &mut S,
    ) -> anyhow::Result<()> {
        for (prss_set, value) in true_prf_vals {
            if let Some(roles_votes) = count
                .get(*prss_set)
                .and_then(|value_map| value_map.get(*value))
            {
                if prss_set.len() > roles_votes.len() {
                    for cur_party_id in prss_set.iter() {
                        let cur_role = Role::indexed_by_one(*cur_party_id);
                        if !roles_votes.contains(&cur_role) {
                            session.add_corrupt(cur_role)?;
                            tracing::warn!("Party with role {:?} and identity {:?} did not vote for the correct prf value and is thus malicious",
                                 cur_role.one_based(), session.role_assignments().get(&cur_role));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Helper method for computing the parties resulting share value based on the winning psi value for each [PrssSet]
    fn compute_party_shares<P: ParameterHandles>(
        true_prf_vals: &HashMap<&PartySet, &Vec<Z>>,
        param: &P,
        mode: ComputeShareMode,
    ) -> anyhow::Result<HashMap<Role, Z>> {
        let sets = create_sets(param.num_parties(), param.threshold() as usize);
        let points = party_compute_f_a_points::<Z>(&sets, param.num_parties())?;

        let alphas = match mode {
            ComputeShareMode::Przs => Some(embed_parties_and_compute_alpha_powers(
                param.num_parties(),
                param.threshold() as usize,
            )?),
            _ => None,
        };

        let mut s_values: HashMap<Role, Z> = HashMap::with_capacity(param.num_parties());
        for cur_role in param.role_assignments().keys() {
            let mut cur_s = Z::ZERO;
            for (idx, set) in sets.iter().enumerate() {
                if set.contains(&cur_role.one_based()) {
                    let f_a = points[idx][cur_role.zero_based()];

                    if let Some(cur_prf_val) = true_prf_vals.get(set) {
                        match mode {
                            ComputeShareMode::Prss => {
                                if (*cur_prf_val).len() != 1 {
                                    return Err(anyhow_error_and_log(
                                        "Did not receive a single PRSS psi value".to_string(),
                                    ));
                                }
                                cur_s += f_a * cur_prf_val[0];
                            }
                            ComputeShareMode::Przs => {
                                if cur_prf_val.len() != param.threshold() as usize {
                                    return Err(anyhow_error_and_log(
                                        "Did not receive t PRZS chi values".to_string(),
                                    ));
                                }

                                for (idx, cv) in cur_prf_val.iter().enumerate() {
                                    if let Some(alpha) = &alphas {
                                        cur_s += f_a * alpha[cur_role.zero_based()][idx + 1] * *cv;
                                    } else {
                                        return Err(anyhow_error_and_log(
                                            "alphas not initialized".to_string(),
                                        ));
                                    }
                                }
                            }
                        };
                    } else {
                        return Err(anyhow_error_and_log(
                            "A prf value which should exist does no longer exist".to_string(),
                        ));
                    }
                }
            }
            s_values.insert(*cur_role, cur_s);
        }
        Ok(s_values)
    }
}

impl<Z> PRSSSetup<Z>
where
    Z: Ring,
    Z: RingEmbed,
    Z: HenselLiftInverse,
{
    /// initialize the PRSS setup for this epoch and a given party
    pub async fn init_with_abort<
        A: AgreeRandom,
        R: Rng + CryptoRng,
        S: SmallSessionHandles<Z, R>,
    >(
        session: &mut S,
    ) -> anyhow::Result<Self> {
        let num_parties = session.num_parties();
        let binom_nt = num_integer::binomial(num_parties, session.threshold() as usize);
        let party_id = session.my_role()?.one_based();

        if binom_nt > PRSS_SIZE_MAX {
            return Err(anyhow_error_and_log(
                "PRSS set size is too large!".to_string(),
            ));
        }

        // create all the subsets A that contain the party id
        let party_sets: Vec<Vec<usize>> = create_sets(num_parties, session.threshold() as usize)
            .into_iter()
            .filter(|aset| aset.contains(&party_id))
            .collect();

        let mut party_prss_sets: Vec<PrssSet<Z>> = Vec::new();

        let ars = A::agree_random::<Z, R, S>(session)
            .await
            .with_context(|| "AgreeRandom failed!")?;

        let f_a_points = party_compute_f_a_points(&party_sets, num_parties)?;
        let alpha_powers =
            embed_parties_and_compute_alpha_powers(num_parties, session.threshold() as usize)?;

        for (idx, set) in party_sets.iter().enumerate() {
            let pset = PrssSet {
                parties: set.to_vec(),
                prfs: None,
                set_key: ars[idx].clone(),
                f_a_points: f_a_points[idx].clone(),
            };
            party_prss_sets.push(pset);
        }

        Ok(PRSSSetup {
            sets: party_prss_sets,
            alpha_powers,
        })
    }
}

impl<Z> PRSSSetup<Z>
where
    Z: Ring,
    Z: ErrorCorrect,
    Z: RingEmbed,
    Z: HenselLiftInverse,
{
    pub async fn robust_init<V: Vss, R: Rng + CryptoRng, L: BaseSessionHandles<R>>(
        session: &mut L,
        vss: &V,
    ) -> anyhow::Result<Self> {
        let n = session.num_parties();
        let t = session.threshold() as usize;
        let c = num_integer::binomial(n, t).div_ceil(n - t);
        let party_id = session.my_role()?.one_based();
        // create all the subsets A that contain the party id
        let party_sets: Vec<Vec<usize>> = create_sets(n, t).into_iter().collect();
        let mut party_prss_sets: Vec<PrssSet<Z>> = Vec::new();
        let mut to_open = Vec::with_capacity(c * (n - t));
        let m_inverse = inverse_vdm(n - t, n)?;
        let secrets = (0..c).map(|_| Z::sample(session.rng())).collect_vec();
        let vss_res = vss.execute_many(session, &secrets).await?;
        for i in 0..secrets.len() {
            let vss_s = vss_res.iter().map(|s| s[i]).collect_vec();
            let random_val = m_inverse.matmul(&ArrayD::from_shape_vec(IxDyn(&[n]), vss_s)?)?;
            to_open.append(&mut random_val.into_raw_vec());
        }
        let f_a_points = party_compute_f_a_points(&party_sets, n)?;
        let r = agree_random_robust(session, to_open).await?;
        for (prf_key, (set, f_a_point)) in r.iter().zip(party_sets.iter().zip(f_a_points)) {
            // Skip sets which the current party is not part of
            if !set.contains(&party_id) {
                continue;
            }
            let pset = PrssSet {
                parties: set.to_vec(),
                prfs: None,
                set_key: prf_key.to_owned(),
                f_a_points: f_a_point.clone(),
            };
            party_prss_sets.push(pset);
        }

        Ok(PRSSSetup {
            sets: party_prss_sets,
            alpha_powers: embed_parties_and_compute_alpha_powers(n, session.threshold() as usize)?,
        })
    }
}

impl<Z> PRSSSetup<Z>
where
    Z: Default,
    Z: Clone,
{
    /// initializes a PRSS state for a new session
    /// PRxS counters are set to zero
    /// PRFs are initialized with agreed keys XORed with the session id
    pub fn new_prss_session_state(&self, sid: SessionId) -> PRSSState<Z> {
        let mut prss_setup = self.clone();

        // initialize AES PRFs once with random agreed keys and sid
        for set in prss_setup.sets.iter_mut() {
            let chi_aes = ChiAes::new(&set.set_key, sid);
            let psi_aes = PsiAes::new(&set.set_key, sid);
            let phi_aes = PhiAes::new(&set.set_key, sid);

            set.prfs = Some(PrfAes {
                phi_aes,
                psi_aes,
                chi_aes,
            });
        }

        PRSSState {
            mask_ctr: 0,
            prss_ctr: 0,
            przs_ctr: 0,
            prss_setup,
        }
    }
}

/// Compute the inverse Vandermonde matrix with a_i = embed(i).
/// That is:
/// 1               1               1           ...    1
/// a_1             a_2             a_3         ...    a_columns
/// a_1^2           a_2^2           a_3^2       ...    a_columns^2
/// ...
/// a_1^{rows-1}    a_2^{rows-1}    a_3^{rows-1}...    a_columns^{rows-1}
fn inverse_vdm<Z: Ring + RingEmbed>(rows: usize, columns: usize) -> anyhow::Result<ArrayD<Z>> {
    Ok(init_vdm::<Z>(columns, rows)?.reversed_axes())
}

async fn agree_random_robust<
    Z: Ring + ErrorCorrect,
    Rnd: Rng + CryptoRng,
    L: BaseSessionHandles<Rnd>,
>(
    session: &mut L,
    shares: Vec<Z>,
) -> anyhow::Result<Vec<PrfKey>> {
    let converted_shares = shares.iter().map(|s| s.to_owned()).collect_vec();
    let r_vec = robust_opens_to_all(session, &converted_shares, session.threshold() as usize)
        .await?
        .with_context(|| "No valid result from open")?;
    // TODO should be updated to SHA3, see https://github.com/zama-ai/distributed-decryption/issues/196
    let mut hasher = blake3::Hasher::new();
    let s_vec = r_vec
        .iter()
        .map(|cur_r| {
            let mut digest = [0u8; KEY_BYTE_LEN];
            hasher.reset();
            hasher.update(&cur_r.to_byte_vec());
            let mut or = hasher.finalize_xof();
            or.fill(&mut digest);
            PrfKey(digest)
        })
        .collect_vec();
    Ok(s_vec)
}

#[cfg(test)]
mod tests {
    use std::num::Wrapping;

    use super::*;
    use crate::execution::sharing::shamir::RevealOp;
    use crate::{
        algebra::{
            residue_poly::{ResiduePoly, ResiduePoly128, ResiduePoly64},
            structure_traits::{One, Zero},
        },
        commitment::KEY_BYTE_LEN,
        execution::{
            constants::{BD1, LOG_BD, SMALL_TEST_KEY_PATH, STATSEC},
            endpoints::decryption::threshold_decrypt64,
            large_execution::vss::RealVss,
            runtime::party::{Identity, Role},
            runtime::{
                session::{
                    BaseSessionHandles, DecryptionMode, ParameterHandles, SessionParameters,
                    SmallSession, SmallSessionStruct,
                },
                test_runtime::{generate_fixed_identities, DistributedTestRuntime},
            },
            sharing::{shamir::ShamirSharings, share::Share},
            small_execution::agree_random::{DummyAgreeRandom, RealAgreeRandomWithAbort},
        },
        file_handling::read_element,
        lwe::{keygen_all_party_shares, KeySet},
        tests::{
            helper::tests::get_small_session_for_parties,
            helper::tests_and_benches::execute_protocol_small,
        },
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use rstest::rstest;
    use std::sync::Arc;
    use tokio::task::JoinSet;
    use tracing_test::traced_test;

    // async helper function that creates the prss setups
    async fn setup_prss_sess<Z: Ring + RingEmbed + HenselLiftInverse, A: AgreeRandom + Send>(
        sessions: Vec<SmallSession<Z>>,
    ) -> Option<HashMap<usize, PRSSSetup<Z>>> {
        let mut jobs = JoinSet::new();

        for sess in sessions.clone() {
            jobs.spawn(async move {
                let epoc = PRSSSetup::init_with_abort::<
                    A,
                    AesRng,
                    SmallSessionStruct<Z, AesRng, SessionParameters>,
                >(&mut sess.clone())
                .await;
                (sess.my_role().unwrap().zero_based(), epoc)
            });
        }

        let mut hm: HashMap<usize, PRSSSetup<Z>> = HashMap::new();

        for _ in &sessions {
            while let Some(v) = jobs.join_next().await {
                let vv = v.unwrap();
                let data = vv.1.ok().unwrap();
                let role = vv.0;
                hm.insert(role, data);
            }
        }

        Some(hm)
    }

    //NOTE: Need to generalize (some of) the tests to ResiduePoly64 ?
    impl<Z: Ring + RingEmbed + HenselLiftInverse> PRSSSetup<Z> {
        // initializes the epoch for a single party (without actual networking)
        pub fn testing_party_epoch_init(
            num_parties: usize,
            threshold: usize,
            party_id: usize,
        ) -> anyhow::Result<Self> {
            let binom_nt = num_integer::binomial(num_parties, threshold);

            if binom_nt > PRSS_SIZE_MAX {
                return Err(anyhow_error_and_log(
                    "PRSS set size is too large!".to_string(),
                ));
            }

            let party_sets = create_sets(num_parties, threshold)
                .into_iter()
                .filter(|aset| aset.contains(&party_id))
                .collect::<Vec<_>>();

            let mut sess = get_small_session_for_parties::<Z>(
                num_parties,
                threshold as u8,
                Role::indexed_by_one(party_id),
            );
            let rt = tokio::runtime::Runtime::new().unwrap();
            let _guard = rt.enter();
            let random_agreed_keys = rt
                .block_on(async { DummyAgreeRandom::agree_random::<Z, _, _>(&mut sess).await })
                .unwrap();

            let f_a_points = party_compute_f_a_points(&party_sets, num_parties)?;
            let alpha_powers = embed_parties_and_compute_alpha_powers(num_parties, threshold)?;

            let sets: Vec<PrssSet<Z>> = party_sets
                .iter()
                .enumerate()
                .map(|(idx, s)| PrssSet {
                    parties: s.to_vec(),
                    prfs: None,
                    set_key: random_agreed_keys[idx].clone(),
                    f_a_points: f_a_points[idx].clone(),
                })
                .collect();

            tracing::debug!("epoch init: {:?}", sets);

            Ok(PRSSSetup { sets, alpha_powers })
        }
    }

    #[test]
    fn test_create_sets() {
        let c = create_sets(4, 1);
        assert_eq!(
            c,
            vec![vec![1, 2, 3], vec![1, 2, 4], vec![1, 3, 4], vec![2, 3, 4],]
        )
    }

    #[test]
    fn test_prss_mask_no_network_bound() {
        let num_parties = 7;
        let threshold = 2;
        let binom_nt: usize = num_integer::binomial(num_parties, threshold);
        let log_n_choose_t = binom_nt.next_power_of_two().ilog2();

        let sid = SessionId::from(42);

        let shares = (1..=num_parties)
            .map(|p| {
                let prss_setup = PRSSSetup::<ResiduePoly128>::testing_party_epoch_init(
                    num_parties,
                    threshold,
                    p,
                )
                .unwrap();

                let mut state = prss_setup.new_prss_session_state(sid);

                assert_eq!(state.mask_ctr, 0);

                let nextval = state.mask_next(p, BD1).unwrap();

                // prss state counter must have increased after call to next
                assert_eq!(state.mask_ctr, 2);

                Share::new(Role::indexed_by_one(p), nextval)
            })
            .collect();

        let e_shares = ShamirSharings::create(shares);

        // reconstruct Mask E as signed integer
        let recon = e_shares
            .reconstruct(threshold)
            .unwrap()
            .to_scalar()
            .unwrap()
            .0 as i128;
        let log = recon.abs().ilog2();

        tracing::debug!("reconstructed prss value: {}", recon);
        tracing::debug!("bitsize of reconstructed value: {}", log);
        tracing::debug!(
            "maximum allowed bitsize: {}",
            STATSEC + LOG_BD + 1 + log_n_choose_t
        );
        tracing::debug!(
            "Value bounds: ({} .. {}]",
            -(BD1 as i128 * 2 * binom_nt as i128),
            BD1 as i128 * 2 * binom_nt as i128
        );

        // check that reconstructed PRSS random output E has limited bit length
        assert!(log < (STATSEC + LOG_BD + 1 + log_n_choose_t)); // check bit length
        assert!(-(BD1 as i128 * 2 * binom_nt as i128) <= recon); // check actual value against upper bound
        assert!((BD1 as i128 * 2 * binom_nt as i128) > recon); // check actual value against lower bound
    }

    #[test]
    fn test_prss_decrypt_distributed_local_sess() {
        let threshold = 2;
        let num_parties = 7;
        // RNG for keys
        let mut rng = AesRng::seed_from_u64(69);
        let msg: u8 = 3;
        let keys: KeySet = read_element(SMALL_TEST_KEY_PATH.to_string()).unwrap();

        let identities = generate_fixed_identities(num_parties);

        // generate keys
        let key_shares = keygen_all_party_shares(&keys, &mut rng, num_parties, threshold).unwrap();
        let ct = keys.pk.encrypt(&mut rng, msg);

        let mut runtime = DistributedTestRuntime::new(identities, threshold as u8);

        runtime.setup_sks(key_shares);
        runtime.setup_cks(Arc::new(keys.ck.clone()));

        let mut seed = [0_u8; aes_prng::SEED_SIZE];
        // create sessions for each prss party
        let sessions: Vec<SmallSession<ResiduePoly128>> = (0..num_parties)
            .map(|p| {
                seed[0] = p as u8;
                runtime
                    .small_session_for_party(SessionId(u128::MAX), p, Some(AesRng::from_seed(seed)))
                    .unwrap()
            })
            .collect();

        // Test with Real AgreeRandom with Abort
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let prss_setups = rt.block_on(async {
            setup_prss_sess::<ResiduePoly128, RealAgreeRandomWithAbort>(sessions.clone()).await
        });

        runtime.setup_prss(prss_setups);

        // test PRSS with decryption endpoint
        let results_dec = threshold_decrypt64::<ResiduePoly128>(
            &runtime,
            ct.clone(),
            DecryptionMode::PRSSDecrypt,
        )
        .unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];

        assert_eq!(out_dec[0], std::num::Wrapping(msg as u64));

        // Test with Dummy AgreeRandom
        let _guard = rt.enter();
        let prss_setups = rt.block_on(async {
            setup_prss_sess::<ResiduePoly128, DummyAgreeRandom>(sessions).await
        });

        runtime.setup_prss(prss_setups);

        // test PRSS with decryption endpoint
        let results_dec =
            threshold_decrypt64::<ResiduePoly128>(&runtime, ct, DecryptionMode::PRSSDecrypt)
                .unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];

        assert_eq!(out_dec[0], std::num::Wrapping(msg as u64));
    }

    #[rstest]
    #[case(0)]
    #[case(1)]
    #[case(2)]
    #[case(23)]
    fn test_prss_mask_next_ctr(#[case] rounds: u128) {
        let num_parties = 4;
        let threshold = 1;

        let sid = SessionId::from(23425);

        let prss = PRSSSetup::testing_party_epoch_init(num_parties, threshold, 1).unwrap();

        let mut state = prss.new_prss_session_state(sid);

        assert_eq!(state.mask_ctr, 0);

        let mut prev = ResiduePoly128::ZERO;
        for _ in 0..rounds {
            let cur = state.mask_next(1, BD1).unwrap();
            // check that values change on each call.
            assert_ne!(prev, cur);
            prev = cur;
        }

        // prss mask state counter must have increased to sid + n after n rounds
        assert_eq!(state.mask_ctr, 2 * rounds);

        // other counters must not have increased
        assert_eq!(state.prss_ctr, 0);
        assert_eq!(state.przs_ctr, 0);
    }

    #[rstest]
    #[case(4, 1)]
    #[case(10, 3)]
    /// check that points computed on f_A are well-formed
    fn test_prss_fa_poly(#[case] num_parties: usize, #[case] threshold: usize) {
        let prss = PRSSSetup::<ResiduePoly128>::testing_party_epoch_init(num_parties, threshold, 1)
            .unwrap();

        for set in prss.sets.iter() {
            for p in 1..=num_parties {
                let point = set.f_a_points[p - 1];
                if set.parties.contains(&p) {
                    assert_ne!(point, ResiduePoly128::ZERO)
                } else {
                    assert_eq!(point, ResiduePoly128::ZERO)
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "PRSS set size is too large!")]
    fn test_prss_too_large() {
        let _prss = PRSSSetup::<ResiduePoly128>::testing_party_epoch_init(22, 7, 1).unwrap();
    }

    #[test]
    // check that the combinations of party ID in A and not in A add up to all party IDs and that the indices match when reversing one list
    fn test_matching_combinations() {
        let num_parties = 10;
        let threshold = 3;

        // the combinations of party IDs *in* the sets A
        let sets = create_sets(num_parties, threshold);

        // the combinations of party IDs *not* in the sets A
        let mut combinations = (1..=num_parties)
            .combinations(threshold)
            .collect::<Vec<_>>();
        // reverse the list of party IDs, so the order matches with the combinations of parties *in* the sets A in create_sets()
        combinations.reverse();

        // the list of all party IDs 1..=N in order
        let all_parties = (1..=num_parties).collect_vec();

        for (idx, c) in combinations.iter().enumerate() {
            // merge both sets of party IDs
            let mut merge = [sets[idx].clone(), c.clone()].concat();

            // sort the list, so we can check for equality with all_parites
            merge.sort();

            assert_eq!(merge, all_parties);
        }
    }

    #[test]
    fn test_przs() {
        let num_parties = 7;
        let threshold = 2;

        let sid = SessionId::from(42);

        let shares = (1..=num_parties)
            .map(|p| {
                let prss_setup = PRSSSetup::<ResiduePoly128>::testing_party_epoch_init(
                    num_parties,
                    threshold,
                    p,
                )
                .unwrap();

                let mut state = prss_setup.new_prss_session_state(sid);

                assert_eq!(state.przs_ctr, 0);

                let nextval = state.przs_next(p, threshold as u8).unwrap();

                // przs state counter must have increased after call to next
                assert_eq!(state.przs_ctr, 1);

                Share::new(Role::indexed_by_one(p), nextval)
            })
            .collect();

        let e_shares = ShamirSharings::create(shares);
        let recon = e_shares.reconstruct(2 * threshold).unwrap();
        tracing::debug!("reconstructed PRZS value (should be all-zero): {:?}", recon);
        assert!(recon.is_zero());
    }

    #[test]
    fn test_prss_next() {
        let num_parties = 7;
        let threshold = 2;

        let sid = SessionId::from(2342);

        // create shares for each party using PRSS.next()
        let shares = (1..=num_parties)
            .map(|p| {
                // initialize PRSSSetup for this epoch
                let prss_setup =
                    PRSSSetup::testing_party_epoch_init(num_parties, threshold, p).unwrap();

                let mut state = prss_setup.new_prss_session_state(sid);

                // check that counters are initialized with sid
                assert_eq!(state.prss_ctr, 0);

                let nextval = state.prss_next(p).unwrap();

                // przs state counter must have increased after call to next
                assert_eq!(state.prss_ctr, 1);

                Share::new(Role::indexed_by_one(p), nextval)
            })
            .collect();

        // reconstruct the party shares
        let e_shares = ShamirSharings::create(shares);
        let recon = e_shares.reconstruct(threshold).unwrap();
        tracing::info!("reconstructed PRSS value: {:?}", recon);

        // form here on compute the PRSS.next() value in plain to check reconstruction above
        // *all* sets A of size n-t
        let all_sets = create_sets(num_parties, threshold)
            .into_iter()
            .collect::<Vec<_>>();

        // manually compute dummy agree random for all sets
        let keys: Vec<_> = all_sets
            .iter()
            .map(|set| {
                let mut r_a = [0u8; KEY_BYTE_LEN];

                let mut bytes: Vec<u8> = Vec::new();
                for &p in set {
                    bytes.extend_from_slice(&p.to_le_bytes());
                }

                let mut hasher = blake3::Hasher::new();
                hasher.update(&bytes);
                let mut or = hasher.finalize_xof();
                or.fill(&mut r_a);
                PrfKey(r_a)
            })
            .collect();

        // sum psi values for all sets
        // we don't need the f_A polys here, as we have all information
        let mut psi_sum = ResiduePoly128::ZERO;
        for (idx, _set) in all_sets.iter().enumerate() {
            let psi_aes = PsiAes::new(&keys[idx], sid);
            let psi: ResiduePoly128 = psi(&psi_aes, 0).unwrap();
            psi_sum += psi
        }
        tracing::info!("reconstructed psi sum: {:?}", psi_sum);

        assert_eq!(psi_sum, recon);
    }

    #[test]
    fn sunshine_prss_check() {
        let parties = 7;
        let threshold = 2;
        let identities = generate_fixed_identities(parties);

        let runtime = DistributedTestRuntime::<ResiduePoly128>::new(identities, threshold);
        let session_id = SessionId(23);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        let mut reference_values = Vec::with_capacity(parties);
        for party_id in 1..=parties {
            let rng = AesRng::seed_from_u64(party_id as u64);
            let mut session = runtime
                .small_session_for_party(session_id, party_id - 1, Some(rng))
                .unwrap();
            DistributedTestRuntime::add_dummy_prss(&mut session);
            let state = session.prss().unwrap();
            // Compute reference value based on check (we clone to ensure that they are evaluated for the same counter)
            reference_values.push(state.clone().prss_next(party_id).unwrap());
            // Do the actual computation
            set.spawn(async move {
                let res = state
                    .prss_check(&mut session, state.prss_ctr)
                    .await
                    .unwrap();
                // Ensure no corruptions happened
                assert!(session.corrupt_roles().is_empty());
                res
            });
        }

        let results = rt.block_on(async {
            let mut results = Vec::new();
            while let Some(v) = set.join_next().await {
                let data = v.unwrap();
                results.push(data);
            }
            results
        });

        // Check the result
        // First verify that we get the expected amount of results (i.e. no threads panicked)
        assert_eq!(results.len(), parties);
        for output in &results {
            // Validate that each party has the expected amount of outputs
            assert_eq!(parties, output.len());
            // Validate that all parties have the same view of output
            assert_eq!(results.first().unwrap(), output);
            for (received_role, received_poly) in output {
                // Validate against result of the "next" method
                assert_eq!(
                    reference_values.get(received_role.zero_based()).unwrap(),
                    received_poly
                );
                // Perform sanity checks (i.e. that nothing is a trivial element and party IDs are in a valid range)
                assert!(received_role.one_based() <= parties);
                assert!(received_role.one_based() > 0);
                assert_ne!(&ResiduePoly::ZERO, received_poly);
                assert_ne!(&ResiduePoly::ONE, received_poly);
            }
        }
    }

    #[test]
    fn sunshine_przs_check() {
        let parties = 7;
        let threshold = 2;
        let identities = generate_fixed_identities(parties);

        let runtime = DistributedTestRuntime::<ResiduePoly128>::new(identities, threshold);
        let session_id = SessionId(17);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        let mut reference_values = Vec::with_capacity(parties);
        for party_id in 1..=parties {
            let rng = AesRng::seed_from_u64(party_id as u64);
            let mut session = runtime
                .small_session_for_party(session_id, party_id - 1, Some(rng))
                .unwrap();
            DistributedTestRuntime::add_dummy_prss(&mut session);
            let state = session.prss().unwrap();
            // Compute reference value based on check (we clone to ensure that they are evaluated for the same counter)
            reference_values.push(
                state
                    .clone()
                    .przs_next(party_id, session.threshold())
                    .unwrap(),
            );
            // Do the actual computation
            set.spawn(async move {
                let res = state
                    .przs_check(&mut session, state.przs_ctr)
                    .await
                    .unwrap();
                // Ensure no corruptions happened
                assert!(session.corrupt_roles().is_empty());
                res
            });
        }

        let results = rt.block_on(async {
            let mut results = Vec::new();
            while let Some(v) = set.join_next().await {
                let data = v.unwrap();
                results.push(data);
            }
            results
        });

        // Check the result
        // First verify that we get the expected amount of results (i.e. no threads panicked)
        assert_eq!(results.len(), parties);
        for output in &results {
            // Validate that each party has the expected amount of outputs
            assert_eq!(parties, output.len());
            // Validate that all parties have the same view of output
            assert_eq!(results.first().unwrap(), output);
            for (received_role, received_poly) in output {
                // Validate against result of the "next" method
                assert_eq!(
                    reference_values.get(received_role.zero_based()).unwrap(),
                    received_poly
                );
                // Perform sanity checks (i.e. that nothing is a trivial element and party IDs are in a valid range)
                assert!(received_role.one_based() <= parties);
                assert!(received_role.one_based() > 0);
                assert_ne!(&ResiduePoly::ZERO, received_poly);
                assert_ne!(&ResiduePoly::ONE, received_poly);
            }
        }
    }

    #[test]
    fn test_count_votes() {
        let parties = 3;
        let my_role = Role::indexed_by_one(3);
        let mut session = get_small_session_for_parties(parties, 0, my_role);
        let set = Vec::from([1, 2, 3]);
        let value = vec![ResiduePoly128::from_scalar(Wrapping(87654))];
        let values = Vec::from([(set.clone(), value.clone())]);
        let broadcast_result = HashMap::from([
            (
                Role::indexed_by_one(1),
                BroadcastValue::PRSSVotes(values.clone()),
            ),
            (
                Role::indexed_by_one(2),
                BroadcastValue::PRSSVotes(values.clone()),
            ),
            (
                Role::indexed_by_one(3),
                BroadcastValue::PRSSVotes(values.clone()),
            ),
        ]);

        let res = PRSSState::count_votes(&broadcast_result, &mut session).unwrap();
        let reference_votes = HashMap::from([(
            value.clone(),
            HashSet::from([
                Role::indexed_by_one(1),
                Role::indexed_by_one(2),
                Role::indexed_by_one(3),
            ]),
        )]);
        let reference = HashMap::from([(set.clone(), reference_votes)]);
        assert_eq!(reference, res);
        assert!(session.corrupt_roles().is_empty());
    }

    /// Test the if a party broadcasts a wrong type then they will get added to the corruption set
    #[traced_test]
    #[test]
    fn test_count_votes_bad_type() {
        let parties = 3;
        let my_role = Role::indexed_by_one(1);
        let mut session = get_small_session_for_parties(parties, 0, my_role);
        let set = Vec::from([1, 2, 3]);
        let value = ResiduePoly64::from_scalar(Wrapping(42));
        let values = Vec::from([(set.clone(), vec![value])]);
        let broadcast_result = HashMap::from([
            (
                Role::indexed_by_one(1),
                BroadcastValue::PRSSVotes(values.clone()),
            ),
            (
                Role::indexed_by_one(2),
                BroadcastValue::RingValue(ResiduePoly64::from_scalar(Wrapping(333))),
            ), // Not the broadcast type
            (
                Role::indexed_by_one(3),
                BroadcastValue::RingVector(Vec::from([ResiduePoly64::from_scalar(Wrapping(42))])),
            ), // Not the right broadcast type again
        ]);

        let res = PRSSState::count_votes(&broadcast_result, &mut session).unwrap();
        let reference_votes =
            HashMap::from([(vec![value], HashSet::from([Role::indexed_by_one(1)]))]);
        let reference = HashMap::from([(set.clone(), reference_votes)]);
        assert_eq!(reference, res);
        assert!(session.corrupt_roles().contains(&Role::indexed_by_one(2)));
        assert!(session.corrupt_roles().contains(&Role::indexed_by_one(3)));
        assert!(logs_contain(
            "sent values they shouldn't and is thus malicious"
        ));
    }

    #[traced_test]
    #[test]
    fn test_add_votes() {
        let parties = 3;
        let my_role = Role::indexed_by_one(1);
        let mut session = get_small_session_for_parties(parties, 0, my_role);
        let value = vec![ResiduePoly128::from_scalar(Wrapping(42))];
        let mut votes = HashMap::new();

        PRSSState::add_vote(&mut votes, &value, Role::indexed_by_one(3), &mut session).unwrap();
        // Check that the vote of `my_role` was added
        assert!(votes
            .get(&value)
            .unwrap()
            .contains(&Role::indexed_by_one(3)));
        // And that the corruption set is still empty
        assert!(session.corrupt_roles().is_empty());

        PRSSState::add_vote(&mut votes, &value, Role::indexed_by_one(2), &mut session).unwrap();
        // Check that role 2 also gets added
        assert!(votes
            .get(&value)
            .unwrap()
            .contains(&Role::indexed_by_one(2)));
        // And that the corruption set is still empty
        assert!(session.corrupt_roles().is_empty());

        // Check that party 3 gets added to the set of corruptions after trying to vote a second time
        PRSSState::add_vote(&mut votes, &value, Role::indexed_by_one(3), &mut session).unwrap();
        assert!(votes
            .get(&value)
            .unwrap()
            .contains(&Role::indexed_by_one(3)));
        assert!(session.corrupt_roles().contains(&Role::indexed_by_one(3)));
        assert!(logs_contain(
            "is trying to vote for the same prf value more than once and is thus malicious"
        ));
    }

    #[test]
    fn test_find_winning_psi_values() {
        let set = Vec::from([1, 2, 3]);
        let value = vec![ResiduePoly128::from_scalar(Wrapping(42))];
        let true_psi_vals = HashMap::from([(&set, &value)]);
        let votes = HashMap::from([
            (
                vec![ResiduePoly128::from_scalar(Wrapping(1))],
                HashSet::from([Role::indexed_by_one(1), Role::indexed_by_one(2)]),
            ),
            (
                value.clone(),
                HashSet::from([
                    Role::indexed_by_one(1),
                    Role::indexed_by_one(2),
                    Role::indexed_by_one(3),
                ]),
            ),
        ]);
        let count = HashMap::from([(set.clone(), votes)]);
        let result = PRSSState::find_winning_prf_values(&count).unwrap();
        assert_eq!(result, true_psi_vals);
    }

    /// Test to identify a party which did not vote for the expected value in `handle_non_voting_parties`
    #[traced_test]
    #[test]
    fn identify_non_voting_party() {
        let parties = 4;
        let set = Vec::from([1, 3, 2]);
        let mut session = get_small_session_for_parties(parties, 0, Role::indexed_by_one(1));
        let value = vec![ResiduePoly128::from_scalar(Wrapping(42))];
        let ref_value = value.clone();
        let true_psi_vals = HashMap::from([(&set, &ref_value)]);
        // Party 3 is not voting for the correct value
        // and party 4 should not vote since they are not in the set
        let votes = HashMap::from([(
            value,
            HashSet::from([Role::indexed_by_one(1), Role::indexed_by_one(2)]),
        )]);
        let count = HashMap::from([(set.clone(), votes)]);
        PRSSState::handle_non_voting_parties(&true_psi_vals, &count, &mut session).unwrap();
        assert!(session.corrupt_roles.contains(&Role::indexed_by_one(3)));
        assert_eq!(1, session.corrupt_roles.len());
        assert!(logs_contain(
            "did not vote for the correct prf value and is thus malicious"
        ));
    }

    #[test]
    fn sunshine_compute_party_shares() {
        let parties = 1;
        let role = Role::indexed_by_one(1);
        let mut session =
            get_small_session_for_parties::<ResiduePoly128>(parties, 0, Role::indexed_by_one(1));

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let prss_setup = rt
            .block_on(async {
                PRSSSetup::init_with_abort::<DummyAgreeRandom, _, _>(&mut session).await
            })
            .unwrap();
        let state = prss_setup.new_prss_session_state(session.session_id());

        // clone state so we can iterate over the PRFs and call next/compute at the same time.
        let mut cloned_state = state.clone();

        for set in state.prss_setup.sets {
            // Compute the reference value and use clone to ensure that the same counter is used for all parties
            let psi_next = cloned_state.prss_next(role.one_based()).unwrap();

            let local_psi = psi(&set.prfs.unwrap().psi_aes, state.prss_ctr).unwrap();
            let local_psi_value = vec![local_psi];
            let true_psi_vals = HashMap::from([(&set.parties, &local_psi_value)]);

            let com_true_psi_vals =
                PRSSState::compute_party_shares(&true_psi_vals, &session, ComputeShareMode::Prss)
                    .unwrap();
            assert_eq!(&psi_next, com_true_psi_vals.get(&role).unwrap());
        }
    }

    #[test]
    fn sunshine_init_with_abort() {
        let parties = 5;
        let threshold = 1;

        async fn task(mut session: SmallSession<ResiduePoly128>) -> Share<ResiduePoly128> {
            let prss_setup = PRSSSetup::init_with_abort::<
                DummyAgreeRandom,
                AesRng,
                SmallSession<ResiduePoly128>,
            >(&mut session)
            .await
            .unwrap();
            let mut state = prss_setup.new_prss_session_state(session.session_id());
            let role = session.my_role().unwrap();
            Share::new(role, state.prss_next(role.one_based()).unwrap())
        }

        // init with Dummy AR does not send anything = 0 expected rounds
        let result = execute_protocol_small(parties, threshold, Some(0), &mut task);

        validate_prss_init(ShamirSharings::create(result), parties, threshold as usize);
    }

    fn validate_prss_init(
        result: ShamirSharings<ResiduePoly128>,
        parties: usize,
        threshold: usize,
    ) {
        let base = result.err_reconstruct(threshold, threshold).unwrap();
        // Reconstruct the shared value
        // Check that we can still
        for i in 1..=parties {
            // Exclude party i's shares
            let mut cur_sharing = result.clone();
            cur_sharing.shares = cur_sharing
                .shares
                .into_iter()
                .filter(|e| e.owner().one_based() != i)
                .collect_vec();
            // And check we still get the correct result
            assert_eq!(
                base,
                cur_sharing.err_reconstruct(threshold, threshold).unwrap()
            )
        }
    }

    #[test]
    fn sunshine_robust_init() {
        let parties: usize = 5;
        let threshold = 1;

        async fn task(mut session: SmallSession<ResiduePoly128>) -> Share<ResiduePoly128> {
            let prss_setup = PRSSSetup::robust_init(&mut session, &RealVss::default())
                .await
                .unwrap();
            let mut state = prss_setup.new_prss_session_state(session.session_id());
            let role = session.my_role().unwrap();
            Share::new(role, state.prss_next(role.one_based()).unwrap())
        }

        // BEFORE:
        // Rounds in robust init:
        // c iterations of VSS (currently not in parallel)
        //  VSS (here: only the happy path)
        //      Round 1: 1 sending to all = 1 round
        //      Round 2: 1 reliable broadcast = 3 + t rounds
        //      Round 3: no corruptions in this case = 0 rounds
        //      Round 4: no corruptions in this case = 0 rounds
        // 1 robust open in the end = 1 round
        // i.e., let c = num_integer::binomial(parties, threshold).div_ceil(parties - threshold);
        //       let rounds = c * (1 + 3 + threshold) + 1;
        //
        // NOW:
        // we're batching the vss so c is always 1
        let c = 1;
        let rounds = c * (1 + 3 + threshold) + 1;

        let result = execute_protocol_small::<ResiduePoly128, _, _>(
            parties,
            threshold,
            Some(rounds.into()),
            &mut task,
        );
        let sharing = ShamirSharings::create(result);
        validate_prss_init(sharing, parties, threshold.into());
    }

    #[test]
    fn robust_init_party_drop() {
        let parties = 5;
        let threshold = 1;
        let bad_party = 3;

        let mut task = |mut session: SmallSession<ResiduePoly128>| async move {
            if session.my_role().unwrap().one_based() != bad_party {
                let prss_setup = PRSSSetup::robust_init(&mut session, &RealVss::default())
                    .await
                    .unwrap();
                let mut state = prss_setup.new_prss_session_state(session.session_id());
                let role = session.my_role().unwrap();
                Share::new(role, state.prss_next(role.one_based()).unwrap())
            } else {
                Share::new(Role::indexed_by_one(bad_party), ResiduePoly::ZERO)
            }
        };

        let result =
            execute_protocol_small::<ResiduePoly128, _, _>(parties, threshold, None, &mut task);

        let sharing = ShamirSharings::create(result);
        validate_prss_init(sharing, parties, threshold.into());
    }

    #[test]
    fn test_vdm_inverse() {
        let res = inverse_vdm(3, 4).unwrap();
        // Check first row is
        // 1, 1, 1, 1
        assert_eq!(ResiduePoly::ONE, res[[0, 0]]);
        assert_eq!(ResiduePoly::ONE, res[[0, 1]]);
        assert_eq!(ResiduePoly::ONE, res[[0, 2]]);
        assert_eq!(ResiduePoly::ONE, res[[0, 3]]);
        // Check second row is
        // 1, 2, 3, 4 = 1, x, 1+x, 2x
        assert_eq!(ResiduePoly::embed_exceptional_set(1).unwrap(), res[[1, 0]]);
        assert_eq!(ResiduePoly::embed_exceptional_set(2).unwrap(), res[[1, 1]]);
        assert_eq!(ResiduePoly::embed_exceptional_set(3).unwrap(), res[[1, 2]]);
        assert_eq!(ResiduePoly::embed_exceptional_set(4).unwrap(), res[[1, 3]]);
        // Check third row is
        // 1, x^2, (1+x)^2, (2x)^2
        assert_eq!(ResiduePoly::embed_exceptional_set(1).unwrap(), res[[2, 0]]);
        assert_eq!(
            ResiduePoly128::embed_exceptional_set(2).unwrap()
                * ResiduePoly128::embed_exceptional_set(2).unwrap(),
            res[[2, 1]]
        );
        assert_eq!(
            ResiduePoly128::embed_exceptional_set(3).unwrap()
                * ResiduePoly128::embed_exceptional_set(3).unwrap(),
            res[[2, 2]]
        );
        assert_eq!(
            ResiduePoly128::embed_exceptional_set(4).unwrap()
                * ResiduePoly128::embed_exceptional_set(4).unwrap(),
            res[[2, 3]]
        );
    }

    /// Test that compute_result fails as expected when a set is not present in the `true_psi_vals` given as input
    #[test]
    fn expected_set_not_present() {
        let parties = 10;
        let mut session =
            get_small_session_for_parties::<ResiduePoly128>(parties, 0, Role::indexed_by_one(1));
        DistributedTestRuntime::add_dummy_prss(&mut session);
        // Use an empty hash map to ensure that
        let psi_values = HashMap::new();
        assert!(PRSSState::<ResiduePoly128>::compute_party_shares(
            &psi_values,
            &session,
            ComputeShareMode::Prss
        )
        .is_err());
    }
}
