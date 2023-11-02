use std::num::Wrapping;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::{
        distributed::reconstruct_w_errors,
        party::Role,
        session::{BaseSessionHandles, ParameterHandles, SessionParameters},
    },
    poly::{Poly, Ring},
    residue_poly::ResiduePoly,
    value::{self, IndexedValue},
    Sample, Z128,
};

use super::{share::Share, triple::Triple};

/// Trait for implementing preprocessing values
pub trait Preprocessing<
    Rnd: RngCore + Send + Sync + Clone,
    R: Ring + std::convert::From<value::Value> + Send + Sync,
    Ses: BaseSessionHandles<Rnd>,
> where
    value::Value: std::convert::From<R>,
{
    /// Constructs a random triple
    fn next_triple(&mut self, session: &mut Ses) -> anyhow::Result<Triple<R>>;

    /// Constructs a random sharing
    fn next_random(&mut self, session: &mut Ses) -> anyhow::Result<Share<R>>;
}

/// Struct for dummy preprocessing for use in interactive tests although it is constructed non-interactively.
/// The struct reflects dummy shares that are technically correct Shamir shares of a polynomial
/// with `threshold` degree.
/// Its implementation is deterministic but pseudorandomly and fully derived using the `seed`.
#[derive(Clone)]
pub struct DummyPreprocessing {
    seed: u64,
    rnd_ctr: u64,
    trip_ctr: u64,
}
impl DummyPreprocessing {
    /// Dummy preprocessing which generates shares deterministically from `seed`
    pub fn new(seed: u64) -> Self {
        DummyPreprocessing {
            seed,
            rnd_ctr: 0,
            trip_ctr: 0,
        }
    }

    /// Helper method for computing the Shamir shares of a `secret`.
    /// Returns a vector of the shares 0-indexed based on [Role]
    pub fn share(
        parties: usize,
        threshold: u8,
        secret: ResiduePoly<Z128>,
        rng: &mut impl RngCore,
    ) -> anyhow::Result<Vec<Share<ResiduePoly<Z128>>>> {
        let poly = Poly::sample_random(rng, secret, threshold as usize);
        (1..=parties)
            .map(|xi| {
                let embedded_xi = ResiduePoly::embed(xi)?;
                Ok(Share::new(Role(xi as u64), poly.eval(&embedded_xi)))
            })
            .collect::<anyhow::Result<Vec<_>>>()
    }
}
impl<Rnd: RngCore + Send + Sync + Clone, Ses: BaseSessionHandles<Rnd>>
    Preprocessing<Rnd, ResiduePoly<Z128>, Ses> for DummyPreprocessing
{
    /// Computes a dummy triple deterministically constructed from the seed in [DummyPreprocessing].
    fn next_triple(&mut self, session: &mut Ses) -> anyhow::Result<Triple<ResiduePoly<Z128>>> {
        // Used to distinguish calls to next random and next triple
        const TRIP_FLAG: u64 = 0x47873E027A425DDE;
        // Use a new RNG based on the seed and counter
        let mut rng: ChaCha20Rng =
            ChaCha20Rng::seed_from_u64(self.seed ^ self.trip_ctr ^ TRIP_FLAG);
        self.trip_ctr += 1;
        let a: ResiduePoly<Wrapping<u128>> = ResiduePoly::<Z128>::sample(&mut rng);
        let a_vec = DummyPreprocessing::share(
            session.amount_of_parties(),
            session.threshold(),
            a,
            &mut rng,
        )?;
        // Retrive the share of the calling party
        let a_share = a_vec
            .get(session.my_role()?.zero_index())
            .ok_or_else(|| anyhow_error_and_log("My role index does not exist".to_string()))?;
        let b = ResiduePoly::<Z128>::sample(&mut rng);
        let b_vec = DummyPreprocessing::share(
            session.amount_of_parties(),
            session.threshold(),
            b,
            &mut rng,
        )?;
        // Retrive the share of the calling party
        let b_share = b_vec
            .get(session.my_role()?.zero_index())
            .ok_or_else(|| anyhow_error_and_log("My role index does not exist".to_string()))?;
        // Compute the c shares based on the true values of a and b
        let c_vec = DummyPreprocessing::share(
            session.amount_of_parties(),
            session.threshold(),
            a * b,
            &mut rng,
        )?;
        // Retrive the share of the calling party
        let c_share = c_vec
            .get(session.my_role()?.zero_index())
            .ok_or_else(|| anyhow_error_and_log("My role index does not exist".to_string()))?;
        Ok(Triple::new(*a_share, *b_share, *c_share))
    }

    /// Computes a random element deterministically but pseudorandomly constructed from the seed in [DummyPreprocessing].
    fn next_random(&mut self, session: &mut Ses) -> anyhow::Result<Share<ResiduePoly<Z128>>> {
        // Used to distinguish calls to next random and next triple
        const RAND_FLAG: u64 = 0x818DECF7255EBCE6;
        // Use a new RNG based on the seed and counter
        let mut rng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(self.seed ^ self.rnd_ctr ^ RAND_FLAG);
        self.rnd_ctr += 1;
        let secret = ResiduePoly::sample(&mut rng);
        let all_parties_shares = DummyPreprocessing::share(
            session.amount_of_parties(),
            session.threshold(),
            secret,
            &mut rng,
        )?;
        let my_share = all_parties_shares
            .get(session.my_role()?.zero_index())
            .ok_or_else(|| anyhow_error_and_log("Party share does not exist".to_string()))?;
        Ok(*my_share)
    }
}

/// Dummy preprocessing struct constructed primarely for use for debugging
/// Concretely the struct can be used _non-interactively_ since shares will all be points,
/// i.e. sharing of threshold=0
pub struct DummyDebugPreprocessing {
    seed: u64,
    rnd_ctr: u64,
    trip_ctr: u64,
}
impl DummyDebugPreprocessing {
    // Dummy preprocessing which generates shares deterministically from `seed`
    pub fn new(seed: u64) -> Self {
        DummyDebugPreprocessing {
            seed,
            rnd_ctr: 0,
            trip_ctr: 0,
        }
    }
}
impl<
        Rnd: RngCore + Send + Sync + Clone,
        R: Ring + std::convert::From<value::Value> + Send + Sync,
        Ses: BaseSessionHandles<Rnd>,
    > Preprocessing<Rnd, R, Ses> for DummyDebugPreprocessing
where
    value::Value: std::convert::From<R>,
{
    /// Computes a dummy triple deterministically constructed from the seed in [DummyPreprocessing].
    fn next_triple(&mut self, session: &mut Ses) -> anyhow::Result<Triple<R>> {
        // Used to distinguish calls to next random and next triple
        const TRIP_FLAG: u64 = 0x47873E027A425DDE;
        let mut rng: ChaCha20Rng =
            ChaCha20Rng::seed_from_u64(self.seed ^ self.trip_ctr ^ TRIP_FLAG);
        self.trip_ctr += 1;
        let a = Share::new(session.my_role()?, R::sample(&mut rng));
        let b = Share::new(session.my_role()?, R::sample(&mut rng));
        let c = Share::new(session.my_role()?, a.value() * b.value());
        Ok(Triple::new(a, b, c))
    }

    /// Computes a random element deterministically but pseudorandomly constructed from the seed in [DummyPreprocessing].
    fn next_random(&mut self, session: &mut Ses) -> anyhow::Result<Share<R>> {
        // Used to distinguish calls to next random and next triple
        const RAND_FLAG: u64 = 0x818DECF7255EBCE6;
        // Construct a rng uniquely defined from the dummy seed and the ctr
        let mut rng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(self.seed ^ self.rnd_ctr ^ RAND_FLAG);
        self.rnd_ctr += 1;
        Ok(Share::new(session.my_role()?, R::sample(&mut rng)))
    }
}

/// Helper method to reconstructs a shared ring element based on a vector of shares.
/// Returns an error if reconstruction fails, and otherwise the reconstructed ring value.
pub fn reconstruct<R: Ring + std::convert::From<value::Value> + Send + Sync>(
    param: &SessionParameters,
    shares: Vec<Share<R>>,
) -> anyhow::Result<R>
where
    value::Value: std::convert::From<R>,
{
    let index_shares = &shares
        .iter()
        .map(|cur_share| IndexedValue {
            party_id: cur_share.owner().0 as usize,
            value: cur_share.value().into(),
        })
        .collect();
    if let Ok(Some(res)) = reconstruct_w_errors(
        param.amount_of_parties(),
        param.threshold() as usize,
        index_shares,
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
                    reconstruct, DummyDebugPreprocessing, DummyPreprocessing, Preprocessing,
                },
                triple::Triple,
            },
            party::Role,
            session::{BaseSessionHandles, ParameterHandles},
        },
        residue_poly::ResiduePoly,
        tests::helper::tests::{
            get_dummy_parameters_for_parties, get_small_session, get_small_session_for_parties,
        },
        Zero, Z128,
    };
    use std::num::Wrapping;

    use super::Share;

    #[test]
    fn test_debug_dummy_rand() {
        let mut preprocessing = DummyDebugPreprocessing::new(42);
        let mut session = get_small_session();
        let rand_a = preprocessing.next_random(&mut session).unwrap();
        let rand_b = preprocessing.next_random(&mut session).unwrap();
        // Check that the values are different
        assert_ne!(rand_a, rand_b);
        let recon_a = reconstruct::<ResiduePoly<Z128>>(&session.parameters, vec![rand_a]).unwrap();
        let recon_b = reconstruct::<ResiduePoly<Z128>>(&session.parameters, vec![rand_b]).unwrap();
        // Check that things are "shared" in plain, i.e. with threshold=0
        assert_eq!(rand_a.value(), recon_a);
        assert_eq!(rand_b.value(), recon_b);
    }

    #[test]
    fn test_debug_dummy_triple() {
        let mut preprocessing = DummyDebugPreprocessing::new(42);
        let mut session = get_small_session();
        let trip_one: Triple<ResiduePoly<Z128>> = preprocessing.next_triple(&mut session).unwrap();
        let trip_two: Triple<ResiduePoly<Z128>> = preprocessing.next_triple(&mut session).unwrap();
        assert_ne!(trip_one, trip_two);
        let recon_one_a = reconstruct(&session.parameters, vec![trip_one.a]).unwrap();
        let recon_two_a = reconstruct(&session.parameters, vec![trip_two.a]).unwrap();
        let recon_one_b = reconstruct(&session.parameters, vec![trip_one.b]).unwrap();
        let recon_two_b = reconstruct(&session.parameters, vec![trip_two.b]).unwrap();
        let recon_one_c = reconstruct(&session.parameters, vec![trip_one.c]).unwrap();
        let recon_two_c = reconstruct(&session.parameters, vec![trip_two.c]).unwrap();
        // Check that things are "shared" in plain, i.e. with threshold=0
        assert_eq!(recon_one_c, recon_one_a * recon_one_b);
        assert_eq!(recon_two_c, recon_two_a * recon_two_b);
    }

    #[test]
    fn test_debug_dummy_multiple_calls() {
        let mut preprocessing = DummyDebugPreprocessing::new(42);
        let mut session = get_small_session();
        let rand_a: Share<ResiduePoly<Z128>> = preprocessing.next_random(&mut session).unwrap();
        let trip_a: Triple<ResiduePoly<Z128>> = preprocessing.next_triple(&mut session).unwrap();
        let rand_b: Share<ResiduePoly<Z128>> = preprocessing.next_random(&mut session).unwrap();
        let trip_b: Triple<ResiduePoly<Z128>> = preprocessing.next_triple(&mut session).unwrap();
        assert_ne!(trip_a, trip_b);
        assert_ne!(rand_a, rand_b);
        assert_ne!(trip_a.a, rand_a);
        assert_ne!(trip_a.b, rand_a);
        let recon_trip_a = reconstruct(&session.parameters, vec![trip_a.c]).unwrap();
        let recon_trip_b = reconstruct(&session.parameters, vec![trip_b.c]).unwrap();
        let recon_rand_a =
            reconstruct::<ResiduePoly<Z128>>(&session.parameters, vec![rand_a]).unwrap();
        let recon_rand_b =
            reconstruct::<ResiduePoly<Z128>>(&session.parameters, vec![rand_b]).unwrap();
        // Check that things are "shared" in plain, i.e. with threshold=0
        assert_eq!(recon_trip_a, trip_a.a.value() * trip_a.b.value());
        assert_eq!(recon_trip_b, trip_b.a.value() * trip_b.b.value());
        assert_eq!(rand_a.value(), recon_rand_a);
        assert_eq!(rand_b.value(), recon_rand_b);
    }

    #[test]
    fn test_threshold_dummy_share() {
        let msg = ResiduePoly::<Z128>::from_scalar(Wrapping(42));
        let mut session = get_small_session_for_parties(10, 3, Role(1));
        let shares = DummyPreprocessing::share(
            session.amount_of_parties(),
            session.threshold(),
            msg,
            session.rng(),
        )
        .unwrap();
        let recon = reconstruct(&session.parameters, shares).unwrap();
        assert_eq!(msg, recon);
    }

    #[test]
    fn test_threshold_dummy_rand() {
        let parties = 10;
        let threshold = 3;
        let mut preps = Vec::new();
        for _i in 1..=parties {
            preps.push(DummyPreprocessing::new(42));
        }
        let recon_a = get_rand(parties, threshold, &mut preps);
        let recon_b = get_rand(parties, threshold, &mut preps);
        // Check that the values are different
        assert_ne!(recon_a, recon_b);
        // Assert equality with a reference value for exactly the seed: 42
        assert_eq!(
            Wrapping(107023415132726423068115182735781144892),
            recon_a.coefs[0]
        );
        assert_eq!(
            Wrapping(273726053182077268016548212164197421531),
            recon_b.coefs[0]
        );
        // We just sanity check the rest of the coefficients
        for i in 1..recon_a.coefs.len() {
            assert_ne!(Wrapping::ZERO, recon_a.coefs[i]);
            assert_ne!(Wrapping::ZERO, recon_b.coefs[i]);
        }
    }
    fn get_rand(
        parties: usize,
        threshold: u8,
        preps: &mut [DummyPreprocessing],
    ) -> ResiduePoly<Z128> {
        let mut recon: Vec<Share<ResiduePoly<Wrapping<u128>>>> = Vec::new();
        for i in 1..=parties {
            let preprocessing = preps.get_mut(i - 1).unwrap();
            let mut session = get_small_session_for_parties(parties, threshold, Role(i as u64));
            let cur_rand = preprocessing.next_random(&mut session).unwrap();
            recon.push(cur_rand);
        }
        let params = get_dummy_parameters_for_parties(parties, threshold, Role(1));
        reconstruct(&params, recon).unwrap()
    }

    #[test]
    fn test_threshold_dummy_trip() {
        let parties = 10;
        let threshold = 3;
        let mut preps = Vec::new();
        for _i in 1..=parties {
            preps.push(DummyPreprocessing::new(42));
        }
        let trip_a = get_trip(parties, threshold, &mut preps);
        let trip_b = get_trip(parties, threshold, &mut preps);
        assert_ne!(trip_a, trip_b);
    }
    fn get_trip(
        parties: usize,
        threshold: u8,
        preps: &mut [DummyPreprocessing],
    ) -> (ResiduePoly<Z128>, ResiduePoly<Z128>, ResiduePoly<Z128>) {
        let mut a_shares = Vec::new();
        let mut b_shares = Vec::new();
        let mut c_shares = Vec::new();
        for i in 1..=parties {
            let preprocessing = preps.get_mut(i - 1).unwrap();
            let mut session = get_small_session_for_parties(parties, threshold, Role(i as u64));
            let cur_trip: Triple<ResiduePoly<Z128>> =
                preprocessing.next_triple(&mut session).unwrap();
            a_shares.push(cur_trip.a);
            b_shares.push(cur_trip.b);
            c_shares.push(cur_trip.c);
        }
        let session = get_small_session_for_parties(parties, threshold, Role(1));
        let recon_a = reconstruct(&session.parameters, a_shares).unwrap();
        let recon_b = reconstruct(&session.parameters, b_shares).unwrap();
        let recon_c = reconstruct(&session.parameters, c_shares).unwrap();
        assert_eq!(recon_a * recon_b, recon_c);
        (recon_a, recon_b, recon_c)
    }

    #[test]
    fn test_threshold_dummy_combined() {
        let parties = 10;
        let threshold = 3;
        let mut preps = Vec::new();
        for _i in 1..=parties {
            preps.push(DummyPreprocessing::new(42));
        }
        let rand_a = get_rand(parties, threshold, &mut preps);
        let trip_a = get_trip(parties, threshold, &mut preps);
        let rand_b = get_rand(parties, threshold, &mut preps);
        let trip_b = get_trip(parties, threshold, &mut preps);
        assert_ne!(trip_a, trip_b);
        assert_ne!(rand_a, rand_b);
        assert_ne!(trip_a.0, rand_a);
        assert_ne!(trip_a.1, rand_a);
        assert_ne!(trip_a.0, rand_b);
        assert_ne!(trip_a.1, rand_b);
    }
}
