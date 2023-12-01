use super::{share::Share, triple::Triple};
use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::{distributed::reconstruct_w_errors_sync, party::Role, session::BaseSessionHandles},
    poly::{Poly, Ring},
    residue_poly::ResiduePoly,
    value::{self, IndexedValue, RingType, Value},
    Sample, Z128, Z64,
};
use itertools::Itertools;
use mockall::automock;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::num::Wrapping;

/// The amount of triples required in a distributed decryption
pub const TRIPLE_BATCH_SIZE: usize = 10_usize;
/// The amount of randoms required in a distributed decryption
pub const RANDOM_BATCH_SIZE: usize = 10_usize;

//NOTE: It's actually cumbersome to have the trait bounds define in the trait definition and not in the methods.
//It forces to define a Rnd sperately from LargeSession
/// Trait for implementing preprocessing values
#[automock]
pub trait Preprocessing<R: Ring + std::convert::From<value::Value> + Send + Sync>
where
    value::Value: std::convert::From<R>,
{
    /// Constructs a random triple
    fn next_triple(&mut self) -> anyhow::Result<Triple<R>>;

    /// Constructs a vector of random shares
    fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<R>>>;

    /// Constructs a random sharing
    fn next_random(&mut self) -> anyhow::Result<Share<R>>;

    /// Constructs a vector of random shares
    fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<R>>>;
}

#[derive(Default, Clone)]
pub struct BasePreprocessing<R>
where
    R: Ring + std::convert::From<value::Value> + Send + Sync,
    value::Value: std::convert::From<R>,
{
    pub available_triples: Vec<Triple<R>>,
    pub available_randoms: Vec<Share<R>>,
}

macro_rules! impl_base_preprocessing {
    ($z:ty, $u:ty) => {
        impl Preprocessing<ResiduePoly<$z>> for BasePreprocessing<ResiduePoly<$z>> {
            fn next_triple(&mut self) -> anyhow::Result<Triple<ResiduePoly<$z>>> {
                self.available_triples
                    .pop()
                    .ok_or_else(|| anyhow_error_and_log("available_triple is empty".to_string()))
            }

            fn next_triple_vec(
                &mut self,
                amount: usize,
            ) -> anyhow::Result<Vec<Triple<ResiduePoly<$z>>>> {
                if self.available_triples.len() >= amount {
                    let mut res = Vec::with_capacity(amount);
                    for _ in 0..amount {
                        res.push(self.next_triple()?);
                    }
                    Ok(res)
                } else {
                    Err(anyhow_error_and_log(format!(
                        "Not enough triples to pop {amount}"
                    )))
                }
            }

            fn next_random(&mut self) -> anyhow::Result<Share<ResiduePoly<$z>>> {
                self.available_randoms
                    .pop()
                    .ok_or_else(|| anyhow_error_and_log("available_random is empty".to_string()))
            }

            fn next_random_vec(
                &mut self,
                amount: usize,
            ) -> anyhow::Result<Vec<Share<ResiduePoly<$z>>>> {
                if self.available_randoms.len() >= amount {
                    let mut res = Vec::with_capacity(amount);
                    for _ in 0..amount {
                        res.push(self.next_random()?);
                    }
                    Ok(res)
                } else {
                    Err(anyhow_error_and_log(format!(
                        "Not enough randomness to pop {amount}"
                    )))
                }
            }
        }
    };
}

impl_base_preprocessing!(Z128, u128);
impl_base_preprocessing!(Z64, u64);

/// Struct for dummy preprocessing for use in interactive tests although it is constructed non-interactively.
/// The struct reflects dummy shares that are technically correct Shamir shares of a polynomial
/// with `threshold` degree.
/// Its implementation is deterministic but pseudorandomly and fully derived using the `seed`.
#[derive(Clone)]
pub struct DummyPreprocessing<Z, Rnd: RngCore, Ses: BaseSessionHandles<Rnd>> {
    seed: u64,
    session: Ses,
    rnd_ctr: u64,
    trip_ctr: u64,
    _phantom: std::marker::PhantomData<Z>,
    _phantom2: std::marker::PhantomData<Rnd>,
}
macro_rules! impl_dummy_preprocessing {
    ($z:ty, $u:ty) => {
        impl<Rnd: RngCore, Ses: BaseSessionHandles<Rnd>> DummyPreprocessing<$z, Rnd, Ses> {
            /// Dummy preprocessing which generates shares deterministically from `seed`
            pub fn new(seed: u64, session: Ses) -> Self {
                DummyPreprocessing::<$z, Rnd, Ses> {
                    seed,
                    session,
                    rnd_ctr: 0,
                    trip_ctr: 0,
                    _phantom: Default::default(),
                    _phantom2: Default::default(),
                }
            }

            /// Helper method for computing the Shamir shares of a `secret`.
            /// Returns a vector of the shares 0-indexed based on [Role]
            pub fn share(
                parties: usize,
                threshold: u8,
                secret: ResiduePoly<$z>,
                rng: &mut impl RngCore,
            ) -> anyhow::Result<Vec<Share<ResiduePoly<$z>>>> {
                let poly = Poly::sample_random(rng, secret, threshold as usize);
                (1..=parties)
                    .map(|xi| {
                        let embedded_xi = ResiduePoly::embed(xi)?;
                        Ok(Share::new(
                            Role::indexed_by_one(xi),
                            poly.eval(&embedded_xi),
                        ))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()
            }
        }
        impl<Rnd: RngCore + Send + Sync + Clone, Ses: BaseSessionHandles<Rnd>>
            Preprocessing<ResiduePoly<$z>> for DummyPreprocessing<$z, Rnd, Ses>
        {
            /// Computes a dummy triple deterministically constructed from the seed in [DummyPreprocessing].
            fn next_triple(&mut self) -> anyhow::Result<Triple<ResiduePoly<$z>>> {
                // Used to distinguish calls to next random and next triple
                const TRIP_FLAG: u64 = 0x47873E027A425DDE;
                // Use a new RNG based on the seed and counter
                let mut rng: ChaCha20Rng =
                    ChaCha20Rng::seed_from_u64(self.seed ^ self.trip_ctr ^ TRIP_FLAG);
                self.trip_ctr += 1;
                let a: ResiduePoly<Wrapping<$u>> = ResiduePoly::<$z>::sample(&mut rng);
                let a_vec = DummyPreprocessing::<$z, Rnd, Ses>::share(
                    self.session.amount_of_parties(),
                    self.session.threshold(),
                    a,
                    &mut rng,
                )?;
                // Retrive the share of the calling party
                let a_share = a_vec
                    .get(self.session.my_role()?.zero_based())
                    .ok_or_else(|| {
                        anyhow_error_and_log("My role index does not exist".to_string())
                    })?;
                let b = ResiduePoly::<$z>::sample(&mut rng);
                let b_vec = DummyPreprocessing::<$z, Rnd, Ses>::share(
                    self.session.amount_of_parties(),
                    self.session.threshold(),
                    b,
                    &mut rng,
                )?;
                // Retrive the share of the calling party
                let b_share = b_vec
                    .get(self.session.my_role()?.zero_based())
                    .ok_or_else(|| {
                        anyhow_error_and_log("My role index does not exist".to_string())
                    })?;
                // Compute the c shares based on the true values of a and b
                let c_vec = DummyPreprocessing::<$z, Rnd, Ses>::share(
                    self.session.amount_of_parties(),
                    self.session.threshold(),
                    a * b,
                    &mut rng,
                )?;
                // Retrive the share of the calling party
                let c_share = c_vec
                    .get(self.session.my_role()?.zero_based())
                    .ok_or_else(|| {
                        anyhow_error_and_log("My role index does not exist".to_string())
                    })?;
                Ok(Triple::new(*a_share, *b_share, *c_share))
            }

            /// Computes a random element deterministically but pseudorandomly constructed from the seed in [DummyPreprocessing].
            fn next_random(&mut self) -> anyhow::Result<Share<ResiduePoly<$z>>> {
                // Used to distinguish calls to next random and next triple
                const RAND_FLAG: u64 = 0x818DECF7255EBCE6;
                // Use a new RNG based on the seed and counter
                let mut rng: ChaCha20Rng =
                    ChaCha20Rng::seed_from_u64(self.seed ^ self.rnd_ctr ^ RAND_FLAG);
                self.rnd_ctr += 1;
                let secret = ResiduePoly::sample(&mut rng);
                let all_parties_shares = DummyPreprocessing::<$z, Rnd, Ses>::share(
                    self.session.amount_of_parties(),
                    self.session.threshold(),
                    secret,
                    &mut rng,
                )?;
                let my_share = all_parties_shares
                    .get(self.session.my_role()?.zero_based())
                    .ok_or_else(|| {
                        anyhow_error_and_log("Party share does not exist".to_string())
                    })?;
                Ok(*my_share)
            }

            fn next_triple_vec(
                &mut self,
                amount: usize,
            ) -> anyhow::Result<Vec<Triple<ResiduePoly<$z>>>> {
                let mut res = Vec::with_capacity(amount);
                // Since there is no communication in the dummy implementation there is no need for optimizating the list call
                for _i in 0..amount {
                    res.push(self.next_triple()?);
                }
                Ok(res)
            }

            fn next_random_vec(
                &mut self,
                amount: usize,
            ) -> anyhow::Result<Vec<Share<ResiduePoly<$z>>>> {
                let mut res = Vec::with_capacity(amount);
                // Since there is no communication in the dummy implementation there is no need for optimizating the list call
                for _i in 0..amount {
                    res.push(self.next_random()?);
                }
                Ok(res)
            }
        }
    };
}
impl_dummy_preprocessing!(Z128, u128);
impl_dummy_preprocessing!(Z64, u64);

/// Dummy preprocessing struct constructed primarely for use for debugging
/// Concretely the struct can be used _non-interactively_ since shares will all be points,
/// i.e. sharing of threshold=0
pub struct DummyDebugPreprocessing<Rnd: RngCore, Ses: BaseSessionHandles<Rnd>> {
    seed: u64,
    session: Ses,
    rnd_ctr: u64,
    trip_ctr: u64,
    _phantom: std::marker::PhantomData<Rnd>,
}
impl<Rnd: RngCore, Ses: BaseSessionHandles<Rnd>> DummyDebugPreprocessing<Rnd, Ses> {
    // Dummy preprocessing which generates shares deterministically from `seed`
    pub fn new(seed: u64, session: Ses) -> Self {
        DummyDebugPreprocessing::<Rnd, Ses> {
            seed,
            session,
            rnd_ctr: 0,
            trip_ctr: 0,
            _phantom: Default::default(),
        }
    }
}
impl<
        R: Ring + std::convert::From<value::Value> + Send + Sync,
        Rnd: RngCore,
        Ses: BaseSessionHandles<Rnd>,
    > Preprocessing<R> for DummyDebugPreprocessing<Rnd, Ses>
where
    value::Value: std::convert::From<R>,
{
    /// Computes a dummy triple deterministically constructed from the seed in [DummyPreprocessing].
    fn next_triple(&mut self) -> anyhow::Result<Triple<R>> {
        // Used to distinguish calls to next random and next triple
        const TRIP_FLAG: u64 = 0x47873E027A425DDE;
        let mut rng: ChaCha20Rng =
            ChaCha20Rng::seed_from_u64(self.seed ^ self.trip_ctr ^ TRIP_FLAG);
        self.trip_ctr += 1;
        let a = Share::new(self.session.my_role()?, R::sample(&mut rng));
        let b = Share::new(self.session.my_role()?, R::sample(&mut rng));
        let c = Share::new(self.session.my_role()?, a.value() * b.value());
        Ok(Triple::new(a, b, c))
    }

    /// Computes a random element deterministically but pseudorandomly constructed from the seed in [DummyPreprocessing].
    fn next_random(&mut self) -> anyhow::Result<Share<R>> {
        // Used to distinguish calls to next random and next triple
        const RAND_FLAG: u64 = 0x818DECF7255EBCE6;
        // Construct a rng uniquely defined from the dummy seed and the ctr
        let mut rng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(self.seed ^ self.rnd_ctr ^ RAND_FLAG);
        self.rnd_ctr += 1;
        Ok(Share::new(self.session.my_role()?, R::sample(&mut rng)))
    }

    fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<R>>> {
        let mut res = Vec::with_capacity(amount);
        // Since there is no communication in the dummy implementation there is no need for optimizating
        // the construction of a vector of triples. Hence we just iteratively call `next_triple` `amount` times.
        for _i in 0..amount {
            res.push(self.next_triple()?);
        }
        Ok(res)
    }

    fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<R>>> {
        let mut res = Vec::with_capacity(amount);
        // Since there is no communication in the dummy implementation there is no need for optimizating
        // the construction of a vector of random shares. Hence we just iteratively call `next_random` `amount` times.
        for _i in 0..amount {
            res.push(self.next_random()?);
        }
        Ok(res)
    }
}

/// Helper method to reconstructs a shared ring element based on a vector of shares.
/// Returns an error if reconstruction fails, and otherwise the reconstructed ring value.
pub fn reconstruct<
    R: Ring + std::convert::From<value::Value> + Send + Sync,
    Rnd: RngCore,
    Ses: BaseSessionHandles<Rnd>,
>(
    session: &Ses,
    shares: Vec<Share<R>>,
) -> anyhow::Result<R>
where
    value::Value: std::convert::From<R>,
{
    let my_role = session.my_role()?;
    let expected_type = *shares
        .iter()
        .filter_map(|share| {
            if share.owner() == my_role {
                let share_value: Value = share.value().into();
                Some(share_value.ty())
            } else {
                None
            }
        })
        .try_collect::<_, Vec<RingType>, _>()?
        .iter()
        .all_equal_value()
        .map_err(|err| anyhow_error_and_log(format!("Error in opening types {:?}", err)))?;
    let index_shares = &shares
        .iter()
        .map(|cur_share| IndexedValue {
            party_id: cur_share.owner().one_based(),
            value: cur_share.value().into(),
        })
        .collect();
    if let Ok(Some(res)) = reconstruct_w_errors_sync(
        session.amount_of_parties(),
        session.threshold() as usize,
        session.threshold() as usize,
        index_shares,
        &expected_type,
    ) {
        return Ok(res.into());
    }
    Err(anyhow_error_and_log(
        "Could not reconstruct the sharing".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use crate::{
        execution::{
            online::{
                preprocessing::{
                    reconstruct, BasePreprocessing, DummyDebugPreprocessing, DummyPreprocessing,
                    Preprocessing, RANDOM_BATCH_SIZE, TRIPLE_BATCH_SIZE,
                },
                triple::Triple,
            },
            party::Role,
            session::{
                BaseSessionHandles, ParameterHandles, SessionParameters, SmallSession,
                SmallSessionStruct,
            },
        },
        residue_poly::ResiduePoly,
        tests::helper::tests::{get_small_session, get_small_session_for_parties},
        Zero, Z128, Z64,
    };
    use itertools::Itertools;
    use paste::paste;
    use rand_chacha::ChaCha20Rng;
    use std::num::Wrapping;

    use super::Share;

    #[test]
    fn test_debug_dummy_rand() {
        let session = get_small_session();
        let mut preprocessing = DummyDebugPreprocessing::new(42, session.clone());
        let rand = preprocessing.next_random_vec(2).unwrap();
        // Check that the values are different
        assert_ne!(rand[0], rand[1]);
        let recon_a = reconstruct::<
            ResiduePoly<Z128>,
            ChaCha20Rng,
            SmallSessionStruct<ChaCha20Rng, SessionParameters>,
        >(&session, vec![rand[0]])
        .unwrap();
        let recon_b = reconstruct::<
            ResiduePoly<Z128>,
            ChaCha20Rng,
            SmallSessionStruct<ChaCha20Rng, SessionParameters>,
        >(&session, vec![rand[1]])
        .unwrap();
        // Check that things are "shared" in plain, i.e. with threshold=0
        assert_eq!(rand[0].value(), recon_a);
        assert_eq!(rand[1].value(), recon_b);
    }

    #[test]
    fn test_debug_dummy_triple() {
        let session = get_small_session();
        let mut preprocessing = DummyDebugPreprocessing::new(42, session.clone());
        let trips: Vec<Triple<ResiduePoly<Z128>>> = preprocessing.next_triple_vec(2).unwrap();
        assert_ne!(trips[0], trips[1]);
        let recon_one_a = reconstruct(&session, vec![trips[0].a]).unwrap();
        let recon_two_a = reconstruct(&session, vec![trips[1].a]).unwrap();
        let recon_one_b = reconstruct(&session, vec![trips[0].b]).unwrap();
        let recon_two_b = reconstruct(&session, vec![trips[1].b]).unwrap();
        let recon_one_c = reconstruct(&session, vec![trips[0].c]).unwrap();
        let recon_two_c = reconstruct(&session, vec![trips[1].c]).unwrap();
        // Check that things are "shared" in plain, i.e. with threshold=0
        assert_eq!(recon_one_c, recon_one_a * recon_one_b);
        assert_eq!(recon_two_c, recon_two_a * recon_two_b);
    }

    #[test]
    fn test_debug_dummy_multiple_calls() {
        let session = get_small_session();
        let mut preprocessing = DummyDebugPreprocessing::new(42, session.clone());
        let rand_a: Share<ResiduePoly<Z128>> = preprocessing.next_random().unwrap();
        let trip_a: Triple<ResiduePoly<Z128>> = preprocessing.next_triple().unwrap();
        let rand_b: Share<ResiduePoly<Z128>> = preprocessing.next_random().unwrap();
        let trip_b: Triple<ResiduePoly<Z128>> = preprocessing.next_triple().unwrap();
        assert_ne!(trip_a, trip_b);
        assert_ne!(rand_a, rand_b);
        assert_ne!(trip_a.a, rand_a);
        assert_ne!(trip_a.b, rand_a);
        let recon_trip_a = reconstruct(&session, vec![trip_a.c]).unwrap();
        let recon_trip_b = reconstruct(&session, vec![trip_b.c]).unwrap();
        let recon_rand_a = reconstruct::<
            ResiduePoly<Z128>,
            ChaCha20Rng,
            SmallSessionStruct<ChaCha20Rng, SessionParameters>,
        >(&session, vec![rand_a])
        .unwrap();
        let recon_rand_b = reconstruct::<
            ResiduePoly<Z128>,
            ChaCha20Rng,
            SmallSessionStruct<ChaCha20Rng, SessionParameters>,
        >(&session, vec![rand_b])
        .unwrap();
        // Check that things are "shared" in plain, i.e. with threshold=0
        assert_eq!(recon_trip_a, trip_a.a.value() * trip_a.b.value());
        assert_eq!(recon_trip_b, trip_b.a.value() * trip_b.b.value());
        assert_eq!(rand_a.value(), recon_rand_a);
        assert_eq!(rand_b.value(), recon_rand_b);
    }

    #[test]
    fn test_no_more_elements() {}
    macro_rules! test_preprocessing {
        ($z:ty, $u:ty) => {
            paste! {
                // Test what happens when no more triples are preset
                #[test]
                fn [<test_no_more_elements_ $z:lower>]() {
                    let share = Share::new(Role::indexed_by_one(1), ResiduePoly::<Z128>::from_scalar(Wrapping(1)));
                    let triple = Triple::new(share.clone(), share.clone(), share.clone());
                    let mut preproc = BasePreprocessing::<ResiduePoly<Z128>> {
                        available_triples: (0..TRIPLE_BATCH_SIZE).map(|_i| triple.clone()).collect_vec(),
                        available_randoms: (0..TRIPLE_BATCH_SIZE).map(|_i| share.clone()).collect_vec(),
                    };
                    // Try to use both the method for getting a single triple and a vector
                    let mut triple_res = preproc
                        .next_triple_vec(TRIPLE_BATCH_SIZE - 1)
                        .unwrap();
                    triple_res.push(preproc.next_triple().unwrap());
                    // Similarely for random elements
                    let mut rand_res = preproc
                        .next_random_vec(RANDOM_BATCH_SIZE - 1)
                        .unwrap();
                    rand_res.push(preproc.next_random().unwrap());
                    // We have now used the entire batch of values and should thus fail
                    assert!(preproc
                        .next_triple()
                        .unwrap_err()
                        .to_string()
                        .contains("available_triple is empty"));
                    assert!(preproc
                        .next_random()
                        .unwrap_err()
                        .to_string()
                        .contains("available_random is empty"));
                }

                #[test]
                fn [<test_threshold_dummy_share $z:lower>]() {
                    let msg = ResiduePoly::<$z>::from_scalar(Wrapping(42));
                    let mut session = get_small_session_for_parties(10, 3, Role::indexed_by_one(1));
                    let shares = DummyPreprocessing::<$z, ChaCha20Rng, SmallSession>::share(
                        session.amount_of_parties(),
                        session.threshold(),
                        msg,
                        session.rng(),
                    )
                    .unwrap();
                    let recon = reconstruct(&session, shares).unwrap();
                    assert_eq!(msg, recon);
                }

                #[test]
                fn [<test_threshold_dummy_rand $z:lower>]() {
                    let parties = 10;
                    let threshold = 3;
                    let mut preps = Vec::new();
                    for i in 1..=parties {
                        let session = get_small_session_for_parties(parties, threshold, Role::indexed_by_one(i));
                        preps.push(DummyPreprocessing::<$z, ChaCha20Rng, SmallSession>::new(42, session));
                    }
                    let recon = [<get_rand_ $z:lower>](parties, threshold, 2, &mut preps);
                    // Check that the values are different
                    assert_ne!(recon[0], recon[1]);
                    // Sanity check the result (results are extremely unlikely to be zero)
                    assert_ne!(recon[0], ResiduePoly::<$z>::ZERO);
                    assert_ne!(recon[1], ResiduePoly::<$z>::ZERO);
                }
                fn [<get_rand_ $z:lower>](
                    parties: usize,
                    threshold: u8,
                    amount: usize,
                    preps: &mut [DummyPreprocessing::<$z, ChaCha20Rng, SmallSession>],
                ) -> Vec<ResiduePoly<$z>> {
                    let session = get_small_session_for_parties(parties, threshold, Role::indexed_by_one(1));
                    let mut res = Vec::new();
                    let mut temp: Vec<Vec<Share<ResiduePoly<Wrapping<$u>>>>> = Vec::new();
                    for i in 1..=parties {
                        let preprocessing = preps.get_mut(i - 1).unwrap();
                        let cur_rand = preprocessing.next_random_vec(amount).unwrap();
                        temp.push(cur_rand);
                    }
                    for j in 0..amount {
                        let mut to_recon = Vec::new();
                        #[allow(clippy::needless_range_loop)]
                        for i in 0..parties {
                            to_recon.push(temp[i][j]);
                        }
                        res.push(reconstruct(&session, to_recon).unwrap());
                    }
                    res
                }

                #[test]
                fn [<test_threshold_dummy_trip $z:lower>]() {
                    let parties = 10;
                    let threshold = 3;
                    let mut preps = Vec::new();
                    for i in 1..=parties {
                        let session = get_small_session_for_parties(parties, threshold, Role::indexed_by_one(i));
                        preps.push(DummyPreprocessing::<$z, ChaCha20Rng, SmallSession>::new(42, session));
                    }
                    let trips = [<get_trip_ $z:lower>](parties, threshold, 2, &mut preps);
                    assert_ne!(trips[0], trips[1]);
                }

                fn [<get_trip_ $z:lower>](
                    parties: usize,
                    threshold: u8,
                    amount: usize,
                    preps: &mut [DummyPreprocessing::<$z, ChaCha20Rng, SmallSession>],
                ) -> Vec<(ResiduePoly<$z>, ResiduePoly<$z>, ResiduePoly<$z>)> {
                    let session = get_small_session_for_parties(parties, threshold, Role::indexed_by_one(1));
                    let mut res = Vec::new();
                    let mut a_shares = Vec::new();
                    let mut b_shares = Vec::new();
                    let mut c_shares = Vec::new();
                    for i in 1..=parties {
                        let preprocessing = preps.get_mut(i - 1).unwrap();
                        let cur_trip: Vec<Triple<ResiduePoly<$z>>> =
                            preprocessing.next_triple_vec(amount,).unwrap();
                        a_shares.push(cur_trip.iter().map(|trip| trip.a).collect_vec());
                        b_shares.push(cur_trip.iter().map(|trip| trip.b).collect_vec());
                        c_shares.push(cur_trip.iter().map(|trip| trip.c).collect_vec());
                    }
                    for j in 0..amount {
                        let mut to_recon_a = Vec::new();
                        let mut to_recon_b = Vec::new();
                        let mut to_recon_c = Vec::new();
                        for i in 0..parties {
                            to_recon_a.push(a_shares[i][j]);
                            to_recon_b.push(b_shares[i][j]);
                            to_recon_c.push(c_shares[i][j]);
                        }
                        let recon_a = reconstruct(&session, to_recon_a).unwrap();
                        let recon_b = reconstruct(&session, to_recon_b).unwrap();
                        let recon_c = reconstruct(&session, to_recon_c).unwrap();
                        assert_eq!(recon_a * recon_b, recon_c);
                        res.push((recon_a, recon_b, recon_c));
                    }
                    res
                }

                #[test]
                fn [<test_threshold_dummy_combined $z:lower>]() {
                    let parties = 10;
                    let threshold = 3;
                    let mut preps = Vec::new();
                    for i in 1..=parties {
                        let session = get_small_session_for_parties(parties, threshold, Role::indexed_by_one(i));
                        preps.push(DummyPreprocessing::<$z, ChaCha20Rng, SmallSession>::new(42, session));
                    }
                    let rand_a = [<get_rand_ $z:lower>](parties, threshold, 1, &mut preps)[0];
                    let trip_a = [<get_trip_ $z:lower>](parties, threshold, 1, &mut preps)[0];
                    let rand_b = [<get_rand_ $z:lower>](parties, threshold, 1, &mut preps)[0];
                    let trip_b = [<get_trip_ $z:lower>](parties, threshold, 1, &mut preps)[0];
                    assert_ne!(trip_a, trip_b);
                    assert_ne!(rand_a, rand_b);
                    assert_ne!(trip_a.0, rand_a);
                    assert_ne!(trip_a.1, rand_a);
                    assert_ne!(trip_a.0, rand_b);
                    assert_ne!(trip_a.1, rand_b);
                }
            }
        };
    }
    test_preprocessing![Z64, u64];
    test_preprocessing![Z128, u128];
}
