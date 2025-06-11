use super::{
    agree_random::{
        AbortSecureAgreeRandom, AgreeRandom, AgreeRandomFromShare, RobustSecureAgreeRandom,
    },
    prf::{ChiAes, PRSSConversions, PrfKey, PsiAes},
};
use crate::{
    algebra::{
        bivariate::{compute_powers_list, MatrixMul},
        poly::Poly,
        structure_traits::{ErrorCorrect, Invert, Ring, RingEmbed},
    },
    error::error_handler::{anyhow_error_and_log, log_error_wrapper},
    execution::{
        communication::broadcast::{Broadcast, SyncReliableBroadcast},
        constants::{PRSS_SIZE_MAX, STATSEC},
        large_execution::{
            single_sharing::init_vdm,
            vss::{SecureVss, Vss},
        },
        runtime::{
            party::Role,
            session::{BaseSessionHandles, ParameterHandles},
        },
        small_execution::prf::{chi, phi, psi, PhiAes},
    },
    networking::value::BroadcastValue,
    session_id::SessionId,
    ProtocolDescription,
};
use anyhow::Context;
use itertools::Itertools;
use ndarray::{ArrayD, IxDyn};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::clone::Clone;
use std::collections::{HashMap, HashSet};
use tfhe::named::Named;
use tfhe_versionable::{Versionize, VersionsDispatch};
use tonic::async_trait;
use tracing::instrument;

/// Trait to capture the primitives of the PRSS/PRZS after init.
#[async_trait]
pub trait PRSSPrimitives<Z>: ProtocolDescription + Send + Sync {
    fn prss_next(&mut self, party_id: Role) -> anyhow::Result<Z>;
    fn przs_next(&mut self, party_id: Role, threshold: u8) -> anyhow::Result<Z>;
    fn mask_next(&mut self, party_id: Role, bd: u128) -> anyhow::Result<Z>;

    async fn prss_check<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
        ctr: u128,
    ) -> anyhow::Result<HashMap<Role, Z>>;
    async fn przs_check<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
        ctr: u128,
    ) -> anyhow::Result<HashMap<Role, Z>>;

    fn get_counters(&self) -> PRSSCounters;
}

pub trait DerivePRSSState<Z>: ProtocolDescription + Clone + Send + Sync {
    /// Defines the output of the derivation function,
    /// that is a PRSS state.
    /// A PRSS state is something that implements [`PRSSPrimitives`].
    type OutputType: PRSSPrimitives<Z> + 'static;
    fn new_prss_session_state(&self, sid: SessionId) -> Self::OutputType;
}

/// Trait to capture the init phase of the PRSS.
#[async_trait]
pub trait PRSSInit<Z>: ProtocolDescription + Send + Sync + Sized {
    /// Defines the output of PRSSInit.
    /// We need to be able to derive a PRSS state
    /// from this output.
    /// A PRSS state is something that implements [`PRSSPrimitives`]).
    type OutputType: DerivePRSSState<Z> + 'static;

    /// One time init of the PRSS by creating a [`PRSSSetup`] object
    /// which can be used to create a session specific [`PRSSState`] through
    /// [`PRSSSetup::new_prss_session_state`]
    async fn init<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
    ) -> anyhow::Result<Self::OutputType>;
}

#[derive(Clone)]
/// Secure with abort implementation of [`PrssInit`]
/// that relies on a [`AgreeRandom`] protocol.
pub struct AbortRealPrssInit<A: AgreeRandom> {
    agree_random: A,
}

impl<A: AgreeRandom> AbortRealPrssInit<A> {
    pub fn new(agree_random: A) -> Self {
        Self { agree_random }
    }
}

impl<A: AgreeRandom> ProtocolDescription for AbortRealPrssInit<A> {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!(
            "{}-AbortRealPrssInit:\n{}\n{} ",
            indent,
            A::protocol_desc(depth + 1),
            //Put a dummy Z, we just need something
            // using depth + 2 because it's not a subprotocol but a byproduct of the init
            PRSSSetup::<u8>::protocol_desc(depth + 2),
        )
    }
}

impl<A: AgreeRandom + Default> Default for AbortRealPrssInit<A> {
    fn default() -> Self {
        Self {
            agree_random: A::default(),
        }
    }
}

/// Alias for [`AbortRealPrssInit`] with a secure implementation of
/// [`AgreeRandom`].
pub type AbortSecurePrssInit = AbortRealPrssInit<AbortSecureAgreeRandom>;

#[derive(Clone)]
/// Robust secure implementation of [`PrssInit`]
/// that relies on an [`AgreeRandomFromShare`] and a [`Vss`] protocol.
pub struct RobustRealPrssInit<A: AgreeRandomFromShare, V: Vss> {
    agree_random: A,
    vss: V,
}

impl<A: AgreeRandomFromShare, V: Vss> ProtocolDescription for RobustRealPrssInit<A, V> {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!(
            "{}-RobustRealPrssInit:\n{}\n{}\n{} ",
            indent,
            A::protocol_desc(depth + 1),
            V::protocol_desc(depth + 1),
            PRSSSetup::<u8>::protocol_desc(depth + 2),
        )
    }
}

impl<A: AgreeRandomFromShare, V: Vss> RobustRealPrssInit<A, V> {
    pub fn new(agree_random: A, vss: V) -> Self {
        Self { agree_random, vss }
    }
}

impl<A: AgreeRandomFromShare + Default, V: Vss + Default> Default for RobustRealPrssInit<A, V> {
    fn default() -> Self {
        Self {
            agree_random: A::default(),
            vss: V::default(),
        }
    }
}

/// Alias for [`RobustRealPrssInit`] with a secure implementatoin of
/// [`AgreeRandomFromShare`] and [`Vss`].
pub type RobustSecurePrssInit = RobustRealPrssInit<RobustSecureAgreeRandom, SecureVss>;

#[async_trait]
impl<Z: ErrorCorrect + Invert + PRSSConversions, A: AgreeRandom> PRSSInit<Z>
    for AbortRealPrssInit<A>
{
    type OutputType = PRSSSetup<Z>;
    /// initialize the PRSS setup for this epoch and a given party
    ///
    /// __NOTE__: Needs to be instantiated with [`RealAgreeRandomWithAbort`] to match the spec
    #[instrument(name="PRSS.Init (abort)",skip(self,session),fields(sid=?session.session_id(),own_identity = ?session.own_identity()))]
    async fn init<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
    ) -> anyhow::Result<Self::OutputType> {
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

        let ars = self
            .agree_random
            .execute(session)
            .await
            .with_context(|| log_error_wrapper("AgreeRandom failed!"))?;

        let f_a_points = party_compute_f_a_points(&party_sets, num_parties)?;
        let alpha_powers =
            embed_parties_and_compute_alpha_powers(num_parties, session.threshold() as usize)?;

        for (idx, set) in party_sets.iter().enumerate() {
            let pset = PrssSet {
                parties: set.to_vec(),

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

#[async_trait]
impl<Z: ErrorCorrect + Invert + PRSSConversions, A: AgreeRandomFromShare, V: Vss> PRSSInit<Z>
    for RobustRealPrssInit<A, V>
{
    type OutputType = PRSSSetup<Z>;
    /// initialize the PRSS setup for this epoch and a given party
    ///
    /// __NOTE__: Needs to be instantiated with [`RealAgreeRandomWithAbort`] to match the spec
    #[instrument(name="PRSS.Init (robust)",skip(self,session),fields(sid=?session.session_id(),own_identity = ?session.own_identity()))]
    async fn init<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
    ) -> anyhow::Result<Self::OutputType> {
        let n = session.num_parties();
        let t = session.threshold() as usize;
        let binom_nt = num_integer::binomial(n, t);

        if binom_nt > PRSS_SIZE_MAX {
            return Err(anyhow_error_and_log(
                "PRSS set size is too large!".to_string(),
            ));
        }

        let c: usize = binom_nt.div_ceil(n - t);
        let party_id = session.my_role()?.one_based();

        //Generate random secret contribution
        let secrets = (0..c).map(|_| Z::sample(session.rng())).collect_vec();
        //Send and receive shares via VSS, format is vss_res[sender_id][contribution_id]
        let vss_res = self.vss.execute_many(session, &secrets).await?;

        let mut to_open = Vec::with_capacity(c * (n - t));
        let m_inverse = transpose_vdm(n - t, n)?;
        for i in 0..c {
            //Retrieve the ith VSSed contribution of all parties
            let vss_s = vss_res.iter().map(|s| s[i]).collect_vec();
            //Apply randomness extraction
            let random_val = m_inverse.matmul(&ArrayD::from_shape_vec(IxDyn(&[n]), vss_s)?)?;
            to_open.append(&mut random_val.into_raw_vec_and_offset().0);
        }

        // create all the subsets A that contain the party id
        let party_sets: Vec<Vec<usize>> = create_sets(n, t).into_iter().collect();
        let f_a_points = party_compute_f_a_points(&party_sets, n)?;
        let mut r: Vec<PrfKey> = self
            .agree_random
            .execute(session, to_open, &party_sets)
            .await?;

        //Reverse r to pop it in correct order
        r.reverse();
        //Populate the prss sets for setup
        let mut party_prss_sets: Vec<PrssSet<Z>> = Vec::new();
        for (set, f_a_point) in party_sets.iter().zip(f_a_points) {
            // Skip sets which the current party is not part of
            if !set.contains(&party_id) {
                continue;
            }
            let pset = PrssSet {
                parties: set.to_vec(),

                set_key: r
                    .pop()
                    .with_context(|| log_error_wrapper(format!("Missing key for set {:?}", set)))?,
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

#[derive(Debug, Clone)]
pub(crate) struct PrfAes {
    phi_aes: PhiAes,
    psi_aes: PsiAes,
    chi_aes: ChiAes,
}

#[derive(Debug, Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum PrssSetVersioned<Z> {
    V0(PrssSet<Z>),
}

/// structure for holding values for each subset of n-t parties
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(PrssSetVersioned)]
pub struct PrssSet<Z> {
    parties: PartySet,
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
#[derive(Debug, Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum PRSSSetupVersioned<Z: Default + Clone + Serialize> {
    V0(PRSSSetup<Z>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(PRSSSetupVersioned)]
pub struct PRSSSetup<Z: Default + Clone + Serialize> {
    // all possible subsets of n-t parties (A) that contain Pi and their shared PRF keys
    pub(crate) sets: Vec<PrssSet<Z>>,
    pub(crate) alpha_powers: Vec<Vec<Z>>,
}

impl<Z: Default + Clone + Serialize> ProtocolDescription for PRSSSetup<Z> {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        //Using a fat arrow here to indicate that this is a byproduct of Init and
        // not really a subprotocol
        format!(
            "{}=>PRSSSetup:\n{}",
            indent,
            SecurePRSSState::<Z>::protocol_desc(depth + 2)
        )
    }
}

impl<Z: Default + Clone + Serialize> Named for PRSSSetup<Z> {
    const NAME: &'static str = "PRSSSetup";
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PRSSCounters {
    pub mask_ctr: u128,
    pub prss_ctr: u128,
    pub przs_ctr: u128,
}

/// PRSS state for use within a given session.
/// Secure implementation of the [`PRSSPrimitives`] trait.
#[derive(Debug, Clone)]
pub struct PRSSState<Z: Default + Clone + Serialize, B: Broadcast> {
    /// set of counters that increases on every call to the respective .next()
    pub(crate) counters: PRSSCounters,
    /// PRSSSetup
    pub(crate) prss_setup: PRSSSetup<Z>,
    /// the initialized PRFs for each set
    pub(crate) prfs: Vec<PrfAes>,
    pub(crate) broadcast: B,
}

impl<Z: Default + Clone + Serialize, B: Broadcast> ProtocolDescription for PRSSState<Z, B> {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        // Using a fat arrow here to indicate that this is a byproduct of Setup
        format!("{}=>PRSSState:\n{}", indent, B::protocol_desc(depth + 1))
    }
}

/// Alias for [`PRSSState`] with a secure implementation of [`Broadcast`]
pub type SecurePRSSState<Z> = PRSSState<Z, SyncReliableBroadcast>;

/// computes the points on the polys f_A for all parties in the given sets A
/// f_A is one at 0, and zero at the party indices not in set A
fn party_compute_f_a_points<Z: Ring + RingEmbed + Invert>(
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

#[async_trait]
impl<Z, B> PRSSPrimitives<Z> for PRSSState<Z, B>
where
    Z: Ring,
    Z: RingEmbed,
    Z: Invert,
    Z: PRSSConversions,
    B: Broadcast,
{
    /// PRSS-Mask.Next() for a single party
    ///
    /// __NOTE__ : using [`STATSEC`] const.
    ///
    /// __NOTE__ : The output share is not uniformly random,
    /// and this method will panic if executed for Z an extension of Z64.
    fn mask_next(&mut self, party_id: Role, bd: u128) -> anyhow::Result<Z> {
        let bd1 = bd << STATSEC;
        let mut res = Z::ZERO;

        for (i, set) in self.prss_setup.sets.iter().enumerate() {
            if set.parties.contains(&party_id.one_based()) {
                if let Some(aes_prf) = &self.prfs.get(i) {
                    let phi0 = phi(&aes_prf.phi_aes, self.counters.mask_ctr, bd1)?;
                    let phi1 = phi(&aes_prf.phi_aes, self.counters.mask_ctr + 1, bd1)?;
                    let phi = phi0 + phi1;

                    // compute f_A(alpha_i), where alpha_i is simply the embedded party ID, so we can just index into the f_a_points (indexed from zero)
                    let f_a = set.f_a_points[party_id.zero_based()];

                    //Leave it to the Ring's implementation to deal with negative values
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
        self.counters.mask_ctr += 2;

        Ok(res)
    }

    /// PRSS.Next() for a single party
    ///
    /// __NOTE__: telemetry is done at the caller because this function isn't batched
    /// and we want to avoid creating too many telemetry spans
    fn prss_next(&mut self, party_id: Role) -> anyhow::Result<Z> {
        let mut res = Z::ZERO;

        for (i, set) in self.prss_setup.sets.iter().enumerate() {
            if set.parties.contains(&party_id.one_based()) {
                if let Some(aes_prf) = &self.prfs.get(i) {
                    let psi = psi(&aes_prf.psi_aes, self.counters.prss_ctr)?;

                    // compute f_A(alpha_i), where alpha_i is simply the embedded party ID, so we can just index into the precomputed f_a_points (indexed from zero)
                    let f_a = set.f_a_points[party_id.zero_based()];

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

        self.counters.prss_ctr += 1;

        Ok(res)
    }

    /// PRZS.Next() for a single party
    /// `party_id`: The party's role to derive IDs
    /// `t`: The threshold parameter for the session
    ///
    /// __NOTE__: telemetry is done at the caller because this function isn't batched
    /// and we want to avoid creating too many telemetry spans
    fn przs_next(&mut self, party_id: Role, threshold: u8) -> anyhow::Result<Z> {
        let mut res = Z::ZERO;

        for (i, set) in self.prss_setup.sets.iter().enumerate() {
            if set.parties.contains(&party_id.one_based()) {
                if let Some(aes_prf) = &self.prfs.get(i) {
                    for j in 1..=threshold {
                        let chi = chi(&aes_prf.chi_aes, self.counters.przs_ctr, j)?;
                        // compute f_A(alpha_i), where alpha_i is simply the embedded party ID, so we can just index into the f_a_points (indexed from zero)
                        let f_a = set.f_a_points[party_id.zero_based()];
                        // power of alpha_i^j
                        let alpha_j =
                            self.prss_setup.alpha_powers[party_id.zero_based()][j as usize];
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

        self.counters.przs_ctr += 1;

        Ok(res)
    }

    /// Compute the PRSS.check() method which returns the summed up psi value for each party based on the supplied counter `ctr`.
    /// If parties are behaving maliciously they get added to the corruption list in [SmallSessionHandles]
    #[instrument(name = "PRSS.check", skip(self, session), fields(sid=?session.session_id(),own_identity=?session.own_identity()))]
    async fn prss_check<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
        ctr: u128,
    ) -> anyhow::Result<HashMap<Role, Z>> {
        let sets = &self.prss_setup.sets;

        //Compute all psi values for subsets I am part of
        let mut psi_values = Vec::with_capacity(sets.len());
        for (i, cur_set) in sets.iter().enumerate() {
            if let Some(aes_prf) = &self.prfs.get(i) {
                let psi = vec![psi(&aes_prf.psi_aes, ctr)?];
                psi_values.push((cur_set.parties.clone(), psi));
            } else {
                return Err(anyhow_error_and_log(
                    "PRFs not properly initialized!".to_string(),
                ));
            }
        }

        //Broadcast (as sender and receiver) all the psi values
        let broadcast_result = self
            .broadcast
            .broadcast_from_all_w_corrupt_set_update::<Z, R, S>(
                session,
                BroadcastValue::PRSSVotes(psi_values),
            )
            .await?;

        // Sort the votes received from the broadcast
        let count = sort_votes(&broadcast_result, session)?;
        // Find which values have received most votes
        let true_psi_vals = find_winning_prf_values(&count, session)?;
        // Find the parties who did not vote for the results and add them to the corrupt set
        handle_non_voting_parties(&true_psi_vals, &count, session)?;
        // Compute result based on majority votes
        compute_party_shares(&true_psi_vals, session, ComputeShareMode::Prss)
    }

    /// Compute the PRZS.check() method which returns the summed up chi value for each party based on the supplied counter `ctr`.
    /// If parties are behaving maliciously they get added to the corruption list in [SmallSessionHandles]
    #[instrument(name = "PRZS.Check", skip(self, session, ctr), fields(sid=?session.session_id(),own_identity=?session.own_identity()))]
    async fn przs_check<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
        ctr: u128,
    ) -> anyhow::Result<HashMap<Role, Z>> {
        let sets = &self.prss_setup.sets;
        let mut chi_values = Vec::with_capacity(sets.len());
        for (i, cur_set) in sets.iter().enumerate() {
            if let Some(aes_prf) = &self.prfs.get(i) {
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

        let broadcast_result = self
            .broadcast
            .broadcast_from_all_w_corrupt_set_update::<Z, R, S>(
                session,
                BroadcastValue::PRSSVotes(chi_values),
            )
            .await?;

        // Sort the votes received from the broadcast
        let count = sort_votes(&broadcast_result, session)?;
        // Find which values have received most votes
        let true_chi_vals = find_winning_prf_values(&count, session)?;
        // Find the parties who did not vote for the results and add them to the corrupt set
        handle_non_voting_parties(&true_chi_vals, &count, session)?;
        // Compute result based on majority votes
        compute_party_shares(&true_chi_vals, session, ComputeShareMode::Przs)
    }

    fn get_counters(&self) -> PRSSCounters {
        self.counters
    }
}

/// Helper method for sorting the votes. Takes the `broadcast_result` and for each [PrssSet] sorts which parties has voted/replied for each of the different [Value]s.
/// The result is a map from each unique received [PrssSet] to another map which maps from all possible received [Value]s associated
/// with the [PrssSet] to the set of [Role]s which has voted/replied to the specific [Value] for the specific [PrssSet].
fn sort_votes<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
    broadcast_result: &HashMap<Role, BroadcastValue<Z>>,
    session: &mut S,
) -> anyhow::Result<HashMap<PartySet, ValueVotes<Z>>> {
    // We count through a set of voting roles in order to avoid one party voting for the same value multiple times
    let mut count: HashMap<PartySet, ValueVotes<Z>> = HashMap::new();
    for (role, broadcast_val) in broadcast_result {
        //Destructure bcast value into the voting vector
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
        // Sorts the votes received from `role` during broadcast for each [PrssSet]
        for (prss_set, prf_val) in vec_pairs {
            match count.get_mut(prss_set) {
                Some(value_votes) => add_vote(value_votes, prf_val, *role, session)?,
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
fn add_vote<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
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
///
/// __NOTE__: If for a given prss_set, the value with max vote has <= threshold votes, this means this
///  prss_set is __NOT__ a valid prss_set, and all parties that voted for this prss_set must be malicious.
fn find_winning_prf_values<'a, Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
    count: &'a HashMap<PartySet, ValueVotes<Z>>,
    session: &mut S,
) -> anyhow::Result<HashMap<&'a PartySet, &'a Vec<Z>>> {
    let mut true_prf_vals = HashMap::with_capacity(count.len());
    for (prss_set, value_votes) in count {
        let (value_max, _) = value_votes
            .iter()
            .max_by_key(|&(_, votes)| votes.len())
            .with_context(|| log_error_wrapper("No votes found!"))?;

        //Make sure there's enough votes
        //(safe to unwrap as we just checked value_max is in the map)
        if value_votes.get(value_max).unwrap().len() <= session.threshold() as usize {
            //Sanity check this set is indeed not a valid set
            if create_sets(session.num_parties(), session.threshold() as usize).contains(prss_set) {
                return Err(anyhow_error_and_log(
                    "PR*S-Check went wrong, did not find enough votes for a valid subset",
                ));
            }
            //All parties that voted for this prss_set are malicious
            for voter_set in value_votes.values() {
                for voter in voter_set {
                    session.add_corrupt(*voter)?;
                }
            }
        } else {
            true_prf_vals.insert(prss_set, value_max);
        }
    }
    Ok(true_prf_vals)
}

/// Helper method for finding the parties who did not vote for the results and add them to the corrupt set.
/// Goes through `true_prf_vals` and find which parties did not vote for the psi values it contains.
/// This is done by cross-referencing the votes in `count`
fn handle_non_voting_parties<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
    true_prf_vals: &HashMap<&PartySet, &Vec<Z>>,
    count: &HashMap<PartySet, ValueVotes<Z>>,
    session: &mut S,
) -> anyhow::Result<()> {
    for (prss_set, value) in true_prf_vals {
        if let Some(roles_votes) = count
            .get(*prss_set)
            .and_then(|value_map| value_map.get(*value))
        {
            //Note we do not need to check that prss_set is a valid set as we've already
            //discarded non valid sets in [find_winning_prf_values].
            //Hadn't we done so, we might have flagged honest parties as malicious
            //because they wouldn't participate in voting for an invalid prss_set.
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
fn compute_party_shares<Z: Ring + RingEmbed + Invert, P: ParameterHandles>(
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
        for (set_idx, set) in sets.iter().enumerate() {
            if set.contains(&cur_role.one_based()) {
                let f_a = points[set_idx][cur_role.zero_based()];

                if let Some(cur_prf_val) = true_prf_vals.get(set) {
                    match mode {
                        ComputeShareMode::Prss => {
                            if cur_prf_val.len() != 1 {
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

                            for (val_idx, cv) in cur_prf_val.iter().enumerate() {
                                if let Some(alpha) = &alphas {
                                    cur_s += f_a * alpha[cur_role.zero_based()][val_idx + 1] * *cv;
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

// Note: We force the use of the Secure version of PRSSState (i.e. use a secure broadcast)
// to make our life simpler
impl<Z: Ring + RingEmbed + Invert + PRSSConversions> DerivePRSSState<Z> for PRSSSetup<Z> {
    type OutputType = SecurePRSSState<Z>;
    /// initializes a PRSS state for a new session
    /// PRxS counters are set to zero
    /// PRFs are initialized with agreed keys XORed with the session id
    fn new_prss_session_state(&self, sid: SessionId) -> Self::OutputType {
        let mut prfs = Vec::new();

        // initialize AES PRFs once with random agreed keys and sid
        for set in &self.sets {
            let chi_aes = ChiAes::new(&set.set_key, sid);
            let psi_aes = PsiAes::new(&set.set_key, sid);
            let phi_aes = PhiAes::new(&set.set_key, sid);

            prfs.push(PrfAes {
                phi_aes,
                psi_aes,
                chi_aes,
            });
        }

        PRSSState {
            counters: PRSSCounters::default(),
            prss_setup: self.clone(),
            prfs,
            broadcast: SyncReliableBroadcast::default(),
        }
    }
}

/// Compute the transposed Vandermonde matrix with a_i = embed(i).
/// That is:
/// 1               1               1           ...    1
/// a_1             a_2             a_3         ...    a_columns
/// a_1^2           a_2^2           a_3^2       ...    a_columns^2
/// ...
/// a_1^{rows-1}    a_2^{rows-1}    a_3^{rows-1}...    a_columns^{rows-1}
fn transpose_vdm<Z: Ring + RingEmbed>(rows: usize, columns: usize) -> anyhow::Result<ArrayD<Z>> {
    Ok(init_vdm::<Z>(columns, rows)?.reversed_axes())
}

pub(crate) fn create_sets(n: usize, t: usize) -> Vec<Vec<usize>> {
    (1..=n).combinations(n - t).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::endpoints::decryption::RadixOrBoolCiphertext;
    use crate::execution::runtime::session::SmallSessionHandles;
    use crate::execution::sharing::shamir::RevealOp;
    use crate::execution::small_execution::agree_random::DSEP_AR;
    use crate::execution::tfhe_internals::test_feature::KeySet;
    use crate::execution::tfhe_internals::utils::expanded_encrypt;
    use crate::hashing::hash_element_w_size;
    use crate::malicious_execution::small_execution::malicious_prss::{
        MaliciousPrssDrop, MaliciousPrssHonestInitLieAll, MaliciousPrssHonestInitRobustThenRandom,
    };
    use crate::networking::NetworkMode;
    use crate::tests::helper::tests::{execute_protocol_small_w_malicious, TestingParameters};
    use crate::tests::randomness_check::execute_all_randomness_tests_loose;
    use crate::{
        algebra::{
            galois_rings::degree_4::{ResiduePolyF4, ResiduePolyF4Z128, ResiduePolyF4Z64},
            structure_traits::{One, Zero},
        },
        commitment::KEY_BYTE_LEN,
        execution::tfhe_internals::test_feature::keygen_all_party_shares,
        execution::{
            constants::{B_SWITCH_SQUASH, LOG_B_SWITCH_SQUASH, SMALL_TEST_KEY_PATH, STATSEC},
            endpoints::decryption::{threshold_decrypt64, DecryptionMode},
            runtime::party::{Identity, Role},
            runtime::{
                session::{
                    BaseSessionHandles, ParameterHandles, SessionParameters, SmallSession,
                    SmallSessionStruct,
                },
                test_runtime::{generate_fixed_identities, DistributedTestRuntime},
            },
            sharing::{shamir::ShamirSharings, share::Share},
            small_execution::agree_random::{
                AbortSecureAgreeRandom, AgreeRandom, DummyAgreeRandom,
            },
        },
        file_handling::tests::read_element,
        tests::helper::testing::get_networkless_base_session_for_parties,
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use rstest::rstest;
    use std::num::Wrapping;
    use std::sync::Arc;
    use tfhe::{set_server_key, FheUint8};
    use tokio::task::JoinSet;
    use tracing_test::traced_test;

    // async helper function that creates the prss setups
    async fn setup_prss_sess<Z: ErrorCorrect + Invert, P: PRSSInit<Z> + Clone + 'static>(
        sessions: Vec<SmallSession<Z>>,
        prss_init: P,
    ) -> Option<HashMap<usize, P::OutputType>> {
        let mut jobs = JoinSet::new();

        for mut sess in sessions.into_iter() {
            let prss_init = prss_init.clone();
            jobs.spawn(async move {
                let epoc = prss_init
                    .init::<AesRng, SmallSessionStruct<Z, AesRng, SessionParameters>>(&mut sess)
                    .await;
                (sess.my_role().unwrap().zero_based(), epoc)
            });
        }

        let mut hm = HashMap::new();

        while let Some(v) = jobs.join_next().await {
            let vv = v.unwrap();
            let data = vv.1.ok().unwrap();
            let role = vv.0;
            hm.insert(role, data);
        }

        Some(hm)
    }

    //NOTE: Need to generalize (some of) the tests to ResiduePolyF4Z64 ?
    impl<Z: Ring + RingEmbed + Invert> PRSSSetup<Z> {
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

            let mut sess = get_networkless_base_session_for_parties(
                num_parties,
                threshold as u8,
                Role::indexed_by_one(party_id),
            );
            let rt = tokio::runtime::Runtime::new().unwrap();
            let _guard = rt.enter();
            let random_agreed_keys = rt
                .block_on(async { DummyAgreeRandom::default().execute(&mut sess).await })
                .unwrap();

            let f_a_points = party_compute_f_a_points(&party_sets, num_parties)?;
            let alpha_powers = embed_parties_and_compute_alpha_powers(num_parties, threshold)?;

            let sets: Vec<PrssSet<Z>> = party_sets
                .iter()
                .enumerate()
                .map(|(idx, s)| PrssSet {
                    parties: s.to_vec(),

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
                let prss_setup = PRSSSetup::<ResiduePolyF4Z128>::testing_party_epoch_init(
                    num_parties,
                    threshold,
                    p,
                )
                .unwrap();

                let mut state = prss_setup.new_prss_session_state(sid);

                assert_eq!(state.counters.mask_ctr, 0);

                let nextval = state
                    .mask_next(Role::indexed_by_one(p), B_SWITCH_SQUASH)
                    .unwrap();

                // prss state counter must have increased after call to next
                assert_eq!(state.counters.mask_ctr, 2);

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
            STATSEC + LOG_B_SWITCH_SQUASH + 1 + log_n_choose_t
        );
        tracing::debug!(
            "Value bounds: ({} .. {}]",
            -(B_SWITCH_SQUASH as i128 * 2 * binom_nt as i128 * (1 << STATSEC)),
            B_SWITCH_SQUASH as i128 * 2 * binom_nt as i128 * (1 << STATSEC)
        );

        // check that reconstructed PRSS random output E has limited bit length
        assert!(log < (STATSEC + LOG_B_SWITCH_SQUASH + 1 + log_n_choose_t)); // check bit length
        assert!(-(B_SWITCH_SQUASH as i128 * 2 * binom_nt as i128 * (1 << STATSEC)) <= recon); // check actual value against upper bound
        assert!((B_SWITCH_SQUASH as i128 * 2 * binom_nt as i128 * (1 << STATSEC)) > recon);
        // check actual value against lower bound
    }

    #[test]
    fn test_prss_decrypt_distributed_local_sess() {
        let threshold = 2;
        let num_parties = 7;
        // RNG for keys
        let mut rng = AesRng::seed_from_u64(69);
        let msg: u8 = 3;
        let keys: KeySet = read_element(std::path::Path::new(SMALL_TEST_KEY_PATH)).unwrap();
        let params = keys.get_cpu_params().unwrap();

        let identities = generate_fixed_identities(num_parties);

        // generate keys
        let lwe_secret_key = keys.get_raw_lwe_client_key();
        let glwe_secret_key = keys.get_raw_glwe_client_key();
        let glwe_secret_key_sns_as_lwe = keys.get_raw_glwe_client_sns_key_as_lwe().unwrap();
        let key_shares = keygen_all_party_shares(
            lwe_secret_key,
            glwe_secret_key,
            glwe_secret_key_sns_as_lwe,
            params,
            &mut rng,
            num_parties,
            threshold,
        )
        .unwrap();

        set_server_key(keys.public_keys.server_key.clone());
        let ct: FheUint8 = expanded_encrypt(&keys.public_keys.public_key, msg, 8).unwrap();
        let (raw_ct, _id, _tag) = ct.into_raw_parts();
        let raw_ct = RadixOrBoolCiphertext::Radix(raw_ct);

        //Could probably be run Async, but NIST doc says all offline is Sync
        let mut runtime =
            DistributedTestRuntime::new(identities, threshold as u8, NetworkMode::Sync, None);

        runtime.setup_server_key(Arc::new(keys.public_keys.server_key));
        runtime.setup_sks(key_shares);

        let mut seed = [0_u8; aes_prng::SEED_SIZE];
        // create sessions for each prss party
        let sessions: Vec<SmallSession<ResiduePolyF4Z128>> = (0..num_parties)
            .map(|p| {
                seed[0] = p as u8;
                runtime.small_session_for_party(
                    SessionId::from(u128::MAX),
                    p,
                    Some(AesRng::from_seed(seed)),
                )
            })
            .collect();

        // Test with Real AgreeRandom with Abort
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let prss_setups = rt.block_on(async {
            let prss_init = AbortRealPrssInit::<AbortSecureAgreeRandom>::default();
            setup_prss_sess::<ResiduePolyF4Z128, _>(sessions.clone(), prss_init).await
        });

        runtime.setup_prss(prss_setups);

        // test PRSS with decryption endpoint
        let results_dec = threshold_decrypt64::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >(&runtime, &raw_ct, DecryptionMode::NoiseFloodSmall)
        .unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];
        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(*out_dec, ref_res);

        // Test with Dummy AgreeRandom
        let _guard = rt.enter();
        let prss_setups = rt.block_on(async {
            let prss_init = AbortRealPrssInit::<DummyAgreeRandom>::default();
            setup_prss_sess::<ResiduePolyF4Z128, _>(sessions, prss_init).await
        });

        runtime.setup_prss(prss_setups);

        // test PRSS with decryption endpoint
        let results_dec = threshold_decrypt64::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >(&runtime, &raw_ct, DecryptionMode::NoiseFloodSmall)
        .unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];
        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(*out_dec, ref_res);
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

        assert_eq!(state.counters.mask_ctr, 0);

        let mut prev = ResiduePolyF4Z128::ZERO;
        for _ in 0..rounds {
            let cur = state
                .mask_next(Role::indexed_by_one(1), B_SWITCH_SQUASH)
                .unwrap();
            // check that values change on each call.
            assert_ne!(prev, cur);
            prev = cur;
        }

        // prss mask state counter must have increased to sid + n after n rounds
        assert_eq!(state.counters.mask_ctr, 2 * rounds);

        // other counters must not have increased
        assert_eq!(state.counters.prss_ctr, 0);
        assert_eq!(state.counters.przs_ctr, 0);
    }

    #[rstest]
    #[case(4, 1)]
    #[case(10, 3)]
    /// check that points computed on f_A are well-formed
    fn test_prss_fa_poly(#[case] num_parties: usize, #[case] threshold: usize) {
        let prss =
            PRSSSetup::<ResiduePolyF4Z128>::testing_party_epoch_init(num_parties, threshold, 1)
                .unwrap();

        for set in prss.sets.iter() {
            for p in 1..=num_parties {
                let point = set.f_a_points[p - 1];
                if set.parties.contains(&p) {
                    assert_ne!(point, ResiduePolyF4Z128::ZERO)
                } else {
                    assert_eq!(point, ResiduePolyF4Z128::ZERO)
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "PRSS set size is too large!")]
    fn test_prss_too_large() {
        let _prss = PRSSSetup::<ResiduePolyF4Z128>::testing_party_epoch_init(22, 7, 1).unwrap();
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
                let prss_setup = PRSSSetup::<ResiduePolyF4Z128>::testing_party_epoch_init(
                    num_parties,
                    threshold,
                    p,
                )
                .unwrap();

                let mut state = prss_setup.new_prss_session_state(sid);

                assert_eq!(state.counters.przs_ctr, 0);

                let nextval = state
                    .przs_next(Role::indexed_by_one(p), threshold as u8)
                    .unwrap();

                // przs state counter must have increased after call to next
                assert_eq!(state.counters.przs_ctr, 1);

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
                assert_eq!(state.counters.prss_ctr, 0);

                let nextval = state.prss_next(Role::indexed_by_one(p)).unwrap();

                // przs state counter must have increased after call to next
                assert_eq!(state.counters.prss_ctr, 1);

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
                let flat_vec = set
                    .iter()
                    // Observe that we map each element to 64 bits to ensure consistency across 32, 64 and 128 bit systems, which have variable size of `usize`
                    .flat_map(|p| (*p as u64).to_le_bytes())
                    .collect::<Vec<_>>();
                let hash = hash_element_w_size(&DSEP_AR, &flat_vec, KEY_BYTE_LEN);
                let mut r_a = [0_u8; KEY_BYTE_LEN];
                r_a.copy_from_slice(&hash[..KEY_BYTE_LEN]);
                PrfKey(r_a)
            })
            .collect();

        // sum psi values for all sets
        // we don't need the f_A polys here, as we have all information
        let mut psi_sum = ResiduePolyF4Z128::ZERO;
        for (idx, _set) in all_sets.iter().enumerate() {
            let psi_aes = PsiAes::new(&keys[idx], sid);
            let psi: ResiduePolyF4Z128 = psi(&psi_aes, 0).unwrap();
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

        //Could probably be run Async, but NIST doc says all offline is Sync
        let runtime = DistributedTestRuntime::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >::new(identities, threshold, NetworkMode::Sync, None);
        let session_id = SessionId::from(23);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        let mut reference_values = Vec::with_capacity(parties);
        for party_id in 1..=parties {
            let rng = AesRng::seed_from_u64(party_id as u64);
            let mut session = runtime.small_session_for_party(session_id, party_id - 1, Some(rng));
            let state = session.prss();
            // Compute reference value based on check (we clone to ensure that they are evaluated for the same counter)
            reference_values.push(
                state
                    .clone()
                    .prss_next(Role::indexed_by_one(party_id))
                    .unwrap(),
            );
            // Do the actual computation
            set.spawn(async move {
                let res = state
                    .prss_check(&mut session, state.counters.prss_ctr)
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
                assert_ne!(&ResiduePolyF4::ZERO, received_poly);
                assert_ne!(&ResiduePolyF4::ONE, received_poly);
            }
        }
    }

    #[test]
    fn sunshine_przs_check() {
        let parties = 7;
        let threshold = 2;
        let identities = generate_fixed_identities(parties);

        //Could probably be run Async, but NIST doc says all offline is Sync
        let runtime = DistributedTestRuntime::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >::new(identities, threshold, NetworkMode::Sync, None);
        let session_id = SessionId::from(17);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        let mut reference_values = Vec::with_capacity(parties);
        for party_id in 1..=parties {
            let rng = AesRng::seed_from_u64(party_id as u64);
            let mut session = runtime.small_session_for_party(session_id, party_id - 1, Some(rng));
            let state = session.prss();
            // Compute reference value based on check (we clone to ensure that they are evaluated for the same counter)
            reference_values.push(
                state
                    .clone()
                    .przs_next(Role::indexed_by_one(party_id), session.threshold())
                    .unwrap(),
            );
            // Do the actual computation
            set.spawn(async move {
                let res = state
                    .przs_check(&mut session, state.counters.przs_ctr)
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
                assert_ne!(&ResiduePolyF4::ZERO, received_poly);
                assert_ne!(&ResiduePolyF4::ONE, received_poly);
            }
        }
    }

    #[test]
    fn test_count_votes() {
        let parties = 3;
        let my_role = Role::indexed_by_one(3);
        let mut session = get_networkless_base_session_for_parties(parties, 0, my_role);
        let set = Vec::from([1, 2, 3]);
        let value = vec![ResiduePolyF4Z128::from_scalar(Wrapping(87654))];
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

        let res = sort_votes(&broadcast_result, &mut session).unwrap();
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
        let mut session = get_networkless_base_session_for_parties(parties, 0, my_role);
        let set = Vec::from([1, 2, 3]);
        let value = ResiduePolyF4Z64::from_scalar(Wrapping(42));
        let values = Vec::from([(set.clone(), vec![value])]);
        let broadcast_result = HashMap::from([
            (
                Role::indexed_by_one(1),
                BroadcastValue::PRSSVotes(values.clone()),
            ),
            (
                Role::indexed_by_one(2),
                BroadcastValue::RingValue(ResiduePolyF4Z64::from_scalar(Wrapping(333))),
            ), // Not the broadcast type
            (
                Role::indexed_by_one(3),
                BroadcastValue::RingVector(Vec::from([ResiduePolyF4Z64::from_scalar(Wrapping(
                    42,
                ))])),
            ), // Not the right broadcast type again
        ]);

        let res = sort_votes(&broadcast_result, &mut session).unwrap();
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
        let mut session = get_networkless_base_session_for_parties(parties, 0, my_role);
        let value = vec![ResiduePolyF4Z128::from_scalar(Wrapping(42))];
        let mut votes = HashMap::new();

        add_vote(&mut votes, &value, Role::indexed_by_one(3), &mut session).unwrap();
        // Check that the vote of `my_role` was added
        assert!(votes
            .get(&value)
            .unwrap()
            .contains(&Role::indexed_by_one(3)));
        // And that the corruption set is still empty
        assert!(session.corrupt_roles().is_empty());

        add_vote(&mut votes, &value, Role::indexed_by_one(2), &mut session).unwrap();
        // Check that role 2 also gets added
        assert!(votes
            .get(&value)
            .unwrap()
            .contains(&Role::indexed_by_one(2)));
        // And that the corruption set is still empty
        assert!(session.corrupt_roles().is_empty());

        // Check that party 3 gets added to the set of corruptions after trying to vote a second time
        add_vote(&mut votes, &value, Role::indexed_by_one(3), &mut session).unwrap();
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
        let parties = 3;
        let my_role = Role::indexed_by_one(1);
        let mut session = get_networkless_base_session_for_parties(parties, 0, my_role);
        let set = Vec::from([1, 2, 3]);
        let value = vec![ResiduePolyF4Z128::from_scalar(Wrapping(42))];
        let true_psi_vals = HashMap::from([(&set, &value)]);
        let votes = HashMap::from([
            (
                vec![ResiduePolyF4Z128::from_scalar(Wrapping(1))],
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
        let result = find_winning_prf_values(&count, &mut session).unwrap();
        assert_eq!(result, true_psi_vals);
    }

    /// Test to identify a party which did not vote for the expected value in `handle_non_voting_parties`
    #[traced_test]
    #[test]
    fn identify_non_voting_party() {
        let parties = 4;
        let set = Vec::from([1, 3, 2]);
        let mut session =
            get_networkless_base_session_for_parties(parties, 0, Role::indexed_by_one(1));
        let value = vec![ResiduePolyF4Z128::from_scalar(Wrapping(42))];
        let ref_value = value.clone();
        let true_psi_vals = HashMap::from([(&set, &ref_value)]);
        // Party 3 is not voting for the correct value
        // and party 4 should not vote since they are not in the set
        let votes = HashMap::from([(
            value,
            HashSet::from([Role::indexed_by_one(1), Role::indexed_by_one(2)]),
        )]);
        let count = HashMap::from([(set.clone(), votes)]);
        handle_non_voting_parties(&true_psi_vals, &count, &mut session).unwrap();
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
            get_networkless_base_session_for_parties(parties, 0, Role::indexed_by_one(1));

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let prss_setup: PRSSSetup<ResiduePolyF4Z128> = rt
            .block_on(async {
                AbortRealPrssInit::<DummyAgreeRandom>::default()
                    .init(&mut session)
                    .await
            })
            .unwrap();
        let state = prss_setup.new_prss_session_state(session.session_id());

        // clone state so we can iterate over the PRFs and call next/compute at the same time.
        let mut cloned_state = state.clone();

        for (i, set) in state.prss_setup.sets.iter().enumerate() {
            // Compute the reference value and use clone to ensure that the same counter is used for all parties
            let psi_next = cloned_state.prss_next(role).unwrap();

            let local_psi = psi(&state.prfs[i].psi_aes, state.counters.prss_ctr).unwrap();
            let local_psi_value = vec![local_psi];
            let true_psi_vals = HashMap::from([(&set.parties, &local_psi_value)]);

            let com_true_psi_vals =
                compute_party_shares(&true_psi_vals, &session, ComputeShareMode::Prss).unwrap();
            assert_eq!(&psi_next, com_true_psi_vals.get(&role).unwrap());
        }
    }

    // Test PRSS init with abort with no malicious parties
    // Expected number of rounds is:
    // - 3 for AbortSecureAgreeRandom
    // - 3 + threshold  rounds for bcast in prss check
    // - 3 + threshold  rounds for bcast in przs check
    // total = 9 + 2t
    #[rstest]
    #[case(TestingParameters::init(4, 1, &[], &[], &[], false, Some(11)))]
    #[case(TestingParameters::init(5, 1, &[], &[], &[], false, Some(11)))]
    #[case(TestingParameters::init(7, 2, &[], &[], &[], false, Some(13)))]
    #[case(TestingParameters::init(10, 3, &[], &[], &[], false, Some(15)))]
    fn test_prss_init_abort(#[case] params: TestingParameters) {
        test_prss_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            AbortSecurePrssInit,
            _,
        >(params.clone(), AbortSecurePrssInit::default(), true, false);

        test_prss_strategies::<
            ResiduePolyF4Z64,
            { ResiduePolyF4Z64::EXTENSION_DEGREE },
            AbortSecurePrssInit,
            _,
        >(params, AbortSecurePrssInit::default(), false, false);
    }

    // Test PRSS init robust with no malicious parties
    // Expected number of rounds is:
    // - 3 + 1 + threshold  for VSS
    // - 1 for RobustAgreeRandom in Robust Init
    // - 3 + threshold  rounds for bcast in prss check
    // - 3 + threshold  rounds for bcast in przs check
    // total = 11 + 3t
    #[rstest]
    #[case(TestingParameters::init(4, 1, &[], &[], &[], false, Some(14)))]
    #[case(TestingParameters::init(5, 1, &[], &[], &[], false, Some(14)))]
    #[case(TestingParameters::init(7, 2, &[], &[], &[], false, Some(17)))]
    #[case(TestingParameters::init(10, 3, &[], &[], &[], false, Some(20)))]
    fn test_prss_init_robust(#[case] params: TestingParameters) {
        test_prss_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            RobustSecurePrssInit,
            _,
        >(params.clone(), RobustSecurePrssInit::default(), true, false);

        test_prss_strategies::<
            ResiduePolyF4Z64,
            { ResiduePolyF4Z64::EXTENSION_DEGREE },
            RobustSecurePrssInit,
            _,
        >(params, RobustSecurePrssInit::default(), false, false);
    }

    // Test PRSS init with abort with malicious parties that drop from start
    // they all should abort as we will unwrap the honest parties' result
    // which are thus errors, hence why the function should panic.
    #[rstest]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], true, None))]
    #[case(TestingParameters::init(5, 1, &[3], &[], &[], true, None))]
    #[case(TestingParameters::init(7, 2, &[2,5], &[], &[], true, None))]
    #[case(TestingParameters::init(10, 3, &[3,6,9], &[], &[], true, None))]
    #[should_panic]
    fn test_dropout_prss_init_abort(#[case] params: TestingParameters) {
        test_prss_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            AbortSecurePrssInit,
            _,
        >(params.clone(), MaliciousPrssDrop::default(), true, false);
    }

    // Test PRSS robust init with malicious parties that drop from start
    // The honest parties should execute correctly, except they catch the
    // malicious parties.
    #[rstest]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], true, None))]
    #[case(TestingParameters::init(5, 1, &[3], &[], &[], true, None))]
    #[case(TestingParameters::init(7, 2, &[2,5], &[], &[], true, None))]
    #[case(TestingParameters::init(10, 3, &[3,6,9], &[], &[], true, None))]
    fn test_dropout_prss_init_robust(#[case] params: TestingParameters) {
        test_prss_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            RobustSecurePrssInit,
            _,
        >(params.clone(), MaliciousPrssDrop::default(), true, false);

        test_prss_strategies::<
            ResiduePolyF4Z64,
            { ResiduePolyF4Z64::EXTENSION_DEGREE },
            RobustSecurePrssInit,
            _,
        >(params, MaliciousPrssDrop::default(), false, false);
    }

    // Test PRSS robust init with actively malicious parties that
    // follow the [`MaliciousPrssHonestInitRobustThenRandom`] strategy.
    // We don't expect to catch it because it tells the truth in checks.
    #[rstest]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], false, None))]
    #[case(TestingParameters::init(5, 1, &[3], &[], &[], false, None))]
    #[case(TestingParameters::init(7, 2, &[2,5], &[], &[], false, None))]
    #[case(TestingParameters::init(10, 3, &[3,6,9], &[], &[], false, None))]
    fn test_malicious_honest_init_and_check_malicious_next_prss_init_robust(
        #[case] params: TestingParameters,
    ) {
        test_prss_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            RobustSecurePrssInit,
            _,
        >(
            params.clone(),
            MaliciousPrssHonestInitRobustThenRandom::<
                RobustSecureAgreeRandom,
                SecureVss,
                SyncReliableBroadcast,
                ResiduePolyF4Z128,
            >::default(),
            true,
            false,
        );

        test_prss_strategies::<
            ResiduePolyF4Z64,
            { ResiduePolyF4Z64::EXTENSION_DEGREE },
            RobustSecurePrssInit,
            _,
        >(
            params,
            MaliciousPrssHonestInitRobustThenRandom::<
                RobustSecureAgreeRandom,
                SecureVss,
                SyncReliableBroadcast,
                ResiduePolyF4Z64,
            >::default(),
            false,
            false,
        );
    }

    // Test PRSS robust init with actively malicious parties that
    // follow the [`MaliciousPrssHonestInitLieAll`] strategy.
    // We expect to catch it because it lies in checks.
    #[rstest]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], true, None))]
    #[case(TestingParameters::init(5, 1, &[3], &[], &[], true, None))]
    #[case(TestingParameters::init(7, 2, &[2,5], &[], &[], true, None))]
    #[case(TestingParameters::init(10, 3, &[3,6,9], &[], &[], true, None))]
    fn test_malicious_honest_init_malicious_check_and_next_prss_init_robust(
        #[case] params: TestingParameters,
    ) {
        // In this test the malicious party will error out
        // because honest parties will stop talking to it after
        // during the przs check after finding out it's malicious
        // in the prss check
        test_prss_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            RobustSecurePrssInit,
            _,
        >(
            params.clone(),
            MaliciousPrssHonestInitLieAll::<
                RobustSecureAgreeRandom,
                SecureVss,
                SyncReliableBroadcast,
                ResiduePolyF4Z128,
            >::default(),
            true,
            true,
        );

        test_prss_strategies::<
            ResiduePolyF4Z64,
            { ResiduePolyF4Z64::EXTENSION_DEGREE },
            RobustSecurePrssInit,
            _,
        >(
            params,
            MaliciousPrssHonestInitLieAll::<
                RobustSecureAgreeRandom,
                SecureVss,
                SyncReliableBroadcast,
                ResiduePolyF4Z64,
            >::default(),
            false,
            true,
        );
    }

    /// Executes [`PrssInit::init`], [`DerivePRSSState::new_prss_session_state`]
    /// and all the primitives of the [`PRSSPrimitives`] trait
    /// with honest and malicious strategies where the identity of the malicious parties
    /// is dictated by the params.
    ///
    /// If [`TestingParameters::should_be_detected`] is set, we assert that the honest parties
    /// have inserted the malicious parties' identity in their corrupt set.
    /// We also validate the output of the honest parties.
    fn test_prss_strategies<
        Z: ErrorCorrect + Invert + PRSSConversions,
        const EXTENSION_DEGREE: usize,
        PRSSHonest: PRSSInit<Z> + Default + 'static,
        PRSSMalicious: PRSSInit<Z> + Clone + 'static,
    >(
        params: TestingParameters,
        malicious_prss: PRSSMalicious,
        generate_masks: bool,
        should_malicious_panic: bool,
    ) {
        //Needs to be at least SAMPLE_COUNT (=100) to run the statistical tests
        let num_secrets = 100;
        let mut task_honest = |mut session: SmallSession<Z>| async move {
            let secure_prss_init = PRSSHonest::default();
            let setup = secure_prss_init.init(&mut session).await.unwrap();
            let mut state = setup.new_prss_session_state(session.session_id());
            let role = session.my_role().unwrap();
            let prss_output_shares = (0..num_secrets)
                .map(|_| Share::<Z>::new(role, state.prss_next(role).unwrap()))
                .collect::<Vec<_>>();
            let przs_output_shares = (0..num_secrets)
                .map(|_| Share::<Z>::new(role, state.przs_next(role, session.threshold()).unwrap()))
                .collect::<Vec<_>>();
            let mask_output_shares = if generate_masks {
                (0..num_secrets)
                    .map(|_| Share::<Z>::new(role, state.mask_next(role, B_SWITCH_SQUASH).unwrap()))
                    .collect::<Vec<_>>()
            } else {
                vec![Share::<Z>::new(role, Z::ZERO)]
            };

            let prss_check_zero = state.prss_check(&mut session, 0).await.unwrap();
            let przs_check_zero = state.przs_check(&mut session, 0).await.unwrap();

            (
                session,
                role,
                (prss_output_shares, prss_check_zero),
                (przs_output_shares, przs_check_zero),
                mask_output_shares,
            )
        };

        let mut task_malicious =
            |mut session: SmallSession<Z>, malicious_prss_init: PRSSMalicious| async move {
                let setup = malicious_prss_init.init(&mut session).await.unwrap();
                let mut state = setup.new_prss_session_state(session.session_id());
                let role = session.my_role().unwrap();
                let prss_output_shares = (0..num_secrets)
                    .map(|_| Share::<Z>::new(role, state.prss_next(role).unwrap()))
                    .collect::<Vec<_>>();
                let przs_output_shares = (0..num_secrets)
                    .map(|_| {
                        Share::<Z>::new(role, state.przs_next(role, session.threshold()).unwrap())
                    })
                    .collect::<Vec<_>>();
                let mask_output_shares = if generate_masks {
                    (0..num_secrets)
                        .map(|_| {
                            Share::<Z>::new(role, state.mask_next(role, B_SWITCH_SQUASH).unwrap())
                        })
                        .collect::<Vec<_>>()
                } else {
                    vec![Share::<Z>::new(role, Z::ZERO)]
                };

                let prss_check_zero = state.prss_check(&mut session, 0).await.unwrap();
                let przs_check_zero = state.przs_check(&mut session, 0).await.unwrap();

                (
                    session,
                    role,
                    (prss_output_shares, prss_check_zero),
                    (przs_output_shares, przs_check_zero),
                    mask_output_shares,
                )
            };
        let (results_honest, results_malicious) =
            execute_protocol_small_w_malicious::<_, _, _, _, _, Z, EXTENSION_DEGREE>(
                &params,
                &params.malicious_roles,
                malicious_prss,
                NetworkMode::Sync,
                None,
                &mut task_honest,
                &mut task_malicious,
            );

        // If malicious behaviour should be detected, make sure it actually is
        // else make sure it really is not
        for (session, my_role, _, _, _) in results_honest.iter() {
            for malicious_role in params.malicious_roles.iter() {
                if params.should_be_detected {
                    assert!(
                        session.corrupt_roles().contains(malicious_role),
                        "Expected malicious set of {:?} to contain {:?} but it does not",
                        my_role,
                        malicious_role
                    );
                } else {
                    assert!(
                        session.corrupt_roles().is_empty(),
                        "Expected malicious set of {:?} set to be empty but it contains: {:?}",
                        my_role,
                        session.corrupt_roles()
                    );
                }
            }
        }

        // Parse the results for honest
        let mut prss_results = Vec::new();
        let mut prss_check_results = Vec::new();
        let mut przs_results = Vec::new();
        let mut przs_check_results = Vec::new();
        let mut masks_results = Vec::new();
        for (
            _,
            _,
            (prss_output, prss_check_output),
            (przs_output, przs_check_output),
            masks_output,
        ) in results_honest.into_iter()
        {
            assert_eq!(prss_output.len(), num_secrets);
            prss_results.push(prss_output);
            prss_check_results.push(prss_check_output);

            assert_eq!(przs_output.len(), num_secrets);
            przs_results.push(przs_output);
            przs_check_results.push(przs_check_output);

            if generate_masks {
                assert_eq!(masks_output.len(), num_secrets);
                masks_results.push(masks_output);
            }
        }

        // Parse the results for malicious, include their results in the mix
        // if they are not detected
        for result_malicious in results_malicious {
            if should_malicious_panic {
                assert!(
                    result_malicious.is_err(),
                    "Expected malicious behaviour to panic but it did not"
                );
            } else {
                assert!(
                    result_malicious.is_ok(),
                    "Expected malicious behaviour to not panic but it did ",
                );
                // We add the malicious prss_output and mask if they exist,
                // padded with 0s if the malicious strategy did not output
                // the correct number, but we discard the przs and check results
                // because przs has degree 2t and we wouldn't be able to reconstruct with it
                // (in high level protocols, if reconstruct of przs fails, we run the check)
                let (
                    _,
                    role,
                    (mut prss_output, _prss_check_output),
                    (mut _przs_output, _przs_check_output),
                    mut masks_output,
                ) = result_malicious.unwrap();
                prss_output.resize(num_secrets, Share::new(role, Z::ZERO));
                masks_output.resize(num_secrets, Share::new(role, Z::ZERO));
                prss_results.push(prss_output);
                masks_results.push(masks_output);
            }
        }

        let max_error = if should_malicious_panic {
            0
        } else {
            params.malicious_roles.len()
        };

        validate_prss(
            prss_results,
            prss_check_results,
            num_secrets,
            params.threshold,
            max_error,
        );
        validate_przs(
            przs_results,
            przs_check_results,
            num_secrets,
            2 * params.threshold,
        );

        if generate_masks {
            validate_masks(
                masks_results,
                num_secrets,
                params.num_parties,
                params.threshold,
                max_error,
            );
        }
    }

    // Validate the output of PRSS.Next and PRSS.Check
    // with prss_results that may contain the output
    // of malicious parties.
    fn validate_prss<Z: ErrorCorrect>(
        prss_results: Vec<Vec<Share<Z>>>,
        prss_check_results: Vec<HashMap<Role, Z>>,
        num_secrets: usize,
        degree: usize,
        max_error: usize,
    ) {
        // Validate randomness
        let last_honest_index = prss_results.len() - max_error;
        for shares in &prss_results[0..last_honest_index] {
            let raw_shares = shares.iter().map(|share| share.value()).collect::<Vec<_>>();
            let randomness_test = execute_all_randomness_tests_loose(&raw_shares);
            assert!(
                randomness_test.is_ok(),
                "Failed randomnness test of PRSS.Next shares: {:?}",
                randomness_test
            );
        }

        // Make sure we can properly reconstruct everything
        let results = reconstruct_all(prss_results, num_secrets, degree, max_error);

        // Validate randomness of the reconstructed results
        let randomness_test = execute_all_randomness_tests_loose(&results);
        assert!(
            randomness_test.is_ok(),
            "Failed randomness check of PRSS.Next Outputs: {:?}",
            randomness_test
        );

        // Make sure the prss_check also reconstructs (with no errors) to the same value
        let expected_result = results[0];
        validate_check(prss_check_results, expected_result, degree);
    }

    // Validate the output of PRZS.Next and PRZS.Check
    // with przs_results that only contains the output
    // of honest parties because we have a degree 2t sharing
    fn validate_przs<Z: ErrorCorrect>(
        przs_results: Vec<Vec<Share<Z>>>,
        przs_check_results: Vec<HashMap<Role, Z>>,
        num_secrets: usize,
        degree: usize,
    ) {
        // Validate randomness
        for shares in &przs_results {
            let raw_shares = shares.iter().map(|share| share.value()).collect::<Vec<_>>();
            let randomness_test = execute_all_randomness_tests_loose(&raw_shares);
            assert!(
                randomness_test.is_ok(),
                "Failed randomnness test of PRZS.Next Shares : {:?}",
                randomness_test
            );
        }

        // Make sure we can properly reconstruct everything
        let results = reconstruct_all(przs_results, num_secrets, degree, 0);

        //We expect all results to be 0
        assert!(results.into_iter().all(|result| result == Z::ZERO));

        // Make sure the prss_check also reconstructs (with no errors) to the same value
        validate_check(przs_check_results, Z::ZERO, degree);
    }

    // Validate the output of PRSS-Mask.Next
    // with masks_results that may contain the output
    // of malicious parties.
    fn validate_masks<Z: ErrorCorrect>(
        masks_results: Vec<Vec<Share<Z>>>,
        num_secrets: usize,
        num_parties: usize,
        degree: usize,
        max_error: usize,
    ) {
        // Make sure we can properly reconstruct everything
        let results = reconstruct_all(masks_results, num_secrets, degree, max_error);

        // check that reconstructed PRSS random output E has limited bit length
        let binom_nt: usize = num_integer::binomial(num_parties, degree);
        let log_n_choose_t = binom_nt.next_power_of_two().ilog2();
        results.into_iter().for_each(|result| {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&result.to_byte_vec()[0..16]);
            let recon = i128::from_le_bytes(arr);
            let log = recon.abs().ilog2();
            assert!(log < (STATSEC + LOG_B_SWITCH_SQUASH + 1 + log_n_choose_t)); // check bit length
            assert!(-(B_SWITCH_SQUASH as i128 * 2 * binom_nt as i128 * (1 << STATSEC)) <= recon); // check actual value against upper bound
            assert!((B_SWITCH_SQUASH as i128 * 2 * binom_nt as i128 * (1 << STATSEC)) > recon);
        });
    }

    fn reconstruct_all<Z: ErrorCorrect>(
        results: Vec<Vec<Share<Z>>>,
        num_secrets: usize,
        degree: usize,
        max_error: usize,
    ) -> Vec<Z> {
        (0..num_secrets)
            .map(|idx| {
                let reconstruct =
                    ShamirSharings::create(results.iter().map(|shares| shares[idx]).collect())
                        .err_reconstruct(degree, max_error);
                assert!(
                    reconstruct.is_ok(),
                    "Failed to reconstruct at idx {}: {:?}",
                    idx,
                    reconstruct
                );
                reconstruct.unwrap()
            })
            .collect::<Vec<_>>()
    }

    fn validate_check<Z: ErrorCorrect>(
        check_results: Vec<HashMap<Role, Z>>,
        expected_result: Z,
        degree: usize,
    ) {
        assert!(check_results
            .into_iter()
            .map(|check| {
                let reconstruct = ShamirSharings::create(
                    check
                        .into_iter()
                        .map(|(role, value)| Share::new(role, value))
                        .collect::<Vec<_>>(),
                )
                .reconstruct(degree);
                assert!(
                    reconstruct.is_ok(),
                    "Failed to reconstruct {:?}",
                    reconstruct
                );
                reconstruct.unwrap()
            })
            .all(|reconstruct| reconstruct == expected_result));
    }

    #[test]
    fn test_vdm_inverse() {
        let res = transpose_vdm(3, 4).unwrap();
        // Check first row is
        // 1, 1, 1, 1
        assert_eq!(ResiduePolyF4::ONE, res[[0, 0]]);
        assert_eq!(ResiduePolyF4::ONE, res[[0, 1]]);
        assert_eq!(ResiduePolyF4::ONE, res[[0, 2]]);
        assert_eq!(ResiduePolyF4::ONE, res[[0, 3]]);
        // Check second row is
        // 1, 2, 3, 4 = 1, x, 1+x, 2x
        assert_eq!(
            ResiduePolyF4::embed_exceptional_set(1).unwrap(),
            res[[1, 0]]
        );
        assert_eq!(
            ResiduePolyF4::embed_exceptional_set(2).unwrap(),
            res[[1, 1]]
        );
        assert_eq!(
            ResiduePolyF4::embed_exceptional_set(3).unwrap(),
            res[[1, 2]]
        );
        assert_eq!(
            ResiduePolyF4::embed_exceptional_set(4).unwrap(),
            res[[1, 3]]
        );
        // Check third row is
        // 1, x^2, (1+x)^2, (2x)^2
        assert_eq!(
            ResiduePolyF4::embed_exceptional_set(1).unwrap(),
            res[[2, 0]]
        );
        assert_eq!(
            ResiduePolyF4Z128::embed_exceptional_set(2).unwrap()
                * ResiduePolyF4Z128::embed_exceptional_set(2).unwrap(),
            res[[2, 1]]
        );
        assert_eq!(
            ResiduePolyF4Z128::embed_exceptional_set(3).unwrap()
                * ResiduePolyF4Z128::embed_exceptional_set(3).unwrap(),
            res[[2, 2]]
        );
        assert_eq!(
            ResiduePolyF4Z128::embed_exceptional_set(4).unwrap()
                * ResiduePolyF4Z128::embed_exceptional_set(4).unwrap(),
            res[[2, 3]]
        );
    }

    /// Test that compute_result fails as expected when a set is not present in the `true_psi_vals` given as input
    #[test]
    fn expected_set_not_present() {
        let parties = 10;
        let session = get_networkless_base_session_for_parties(parties, 0, Role::indexed_by_one(1));
        // Use an empty hash map to ensure that
        let psi_values = HashMap::new();
        assert!(compute_party_shares::<ResiduePolyF4Z128, _>(
            &psi_values,
            &session,
            ComputeShareMode::Prss
        )
        .is_err());
    }
}
