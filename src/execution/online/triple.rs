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
    value::{IndexedValue, Value},
    Sample, Z128,
};

/// Generic structure for shares
#[derive(Clone, Debug, Hash, PartialEq, Eq, Copy)]
pub struct Share<R>
where
    R: Ring,
{
    value: R,
    owner: Role,
}

impl<R: Ring> Share<R> {
    pub fn new(owner: Role, value: R) -> Self {
        Self { value, owner }
    }

    pub fn value(&self) -> R {
        self.value
    }

    pub fn owner(&self) -> Role {
        self.owner
    }
}
/// Implementable trait to realize reconstruction for a specific types of shares
pub trait Reconstruct<R>
where
    R: Ring,
{
    /// Reconstructs a shared ring element based on a vector of shares.
    /// Returns an error if reconstruction fails, and otherwise the reconstructed ring value.
    fn reconstruct(params: &SessionParameters, shares: Vec<Share<R>>) -> anyhow::Result<R>;
}
impl Reconstruct<ResiduePoly<Z128>> for Share<ResiduePoly<Z128>> {
    fn reconstruct(
        param: &SessionParameters,
        shares: Vec<Share<ResiduePoly<Z128>>>,
    ) -> anyhow::Result<ResiduePoly<Z128>> {
        let index_shares = &shares
            .iter()
            .map(|cur_share| IndexedValue {
                party_id: cur_share.owner().0 as usize,
                value: Value::Poly128(cur_share.value()),
            })
            .collect();
        if let Ok(Some(Value::Poly128(res))) = reconstruct_w_errors(
            param.amount_of_parties(),
            param.threshold() as usize,
            index_shares,
        ) {
            return Ok(res);
        }
        Err(anyhow_error_and_log(
            "Could not reconstruct the sharing".to_string(),
        ))
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Copy)]
pub struct Triple<R>
where
    R: Ring,
{
    a: Share<R>,
    b: Share<R>,
    c: Share<R>,
}
impl<R: Ring> Triple<R> {
    pub fn new(a: Share<R>, b: Share<R>, c: Share<R>) -> Self {
        Self { a, b, c }
    }
}

// ID to define subsession IDs for preprocessing. Stored using an alias to allow easy future refactoring
pub type OfflineId = u64;

/// Trait for implementing preprocessing values
pub trait Preprocessing<Rnd: RngCore + Send + Sync + Clone, R: Ring, Ses: BaseSessionHandles<Rnd>> {
    /// Constructs a random triple
    fn next_triple(&self, session: &mut Ses, id: OfflineId) -> anyhow::Result<Triple<R>>;

    /// Constructs a random sharing
    fn next_random(&self, session: &mut Ses, id: OfflineId) -> anyhow::Result<Share<R>>;
}

/// Struct for dummy preprocessing for use in interactive tests although it is constructed non-interactively.
/// The struct reflects dummy shares that are technically correct Shamir shares of a polynomial
/// with `threshold` degree.
/// Its implementation is deterministic but pseudorandomly and fully derived using the `seed`.
#[derive(Clone)]
pub struct DummyPreprocessing {
    seed: u64,
}
impl DummyPreprocessing {
    /// Dummy preprocessing which generates shares deterministically from `seed`
    pub fn new(seed: u64) -> Self {
        DummyPreprocessing { seed }
    }

    /// Helper method for computes the Shamir shares of a `secret`.
    /// Returns a vector of the shares 0-indexed based on [Role]
    fn share(
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
    /// Computes a dummy triple deterministically constructed from the seed in [DummyPreprocessing] and the [OfflineId] `id`.
    fn next_triple(
        &self,
        session: &mut Ses,
        id: OfflineId,
    ) -> anyhow::Result<Triple<ResiduePoly<Z128>>> {
        // Derive distinct ids for generating the parts of a
        let mut rng_a: ChaCha20Rng = ChaCha20Rng::seed_from_u64(self.seed ^ id ^ 1);
        let a: ResiduePoly<Wrapping<u128>> = ResiduePoly::<Z128>::sample(&mut rng_a);
        let a_vec = DummyPreprocessing::share(
            session.amount_of_parties(),
            session.threshold(),
            a,
            &mut rng_a,
        )?;
        // Retrive the share of the calling party
        let a_share = a_vec
            .get(session.my_role()?.zero_index())
            .ok_or_else(|| anyhow_error_and_log("My role index does not exist".to_string()))?;
        // Derive distinct ids for generating the parts of b
        let mut rng_b: ChaCha20Rng = ChaCha20Rng::seed_from_u64(self.seed ^ id ^ 2);
        let b = ResiduePoly::<Z128>::sample(&mut rng_b);
        let b_vec = DummyPreprocessing::share(
            session.amount_of_parties(),
            session.threshold(),
            b,
            &mut rng_b,
        )?;
        // Retrive the share of the calling party
        let b_share = b_vec
            .get(session.my_role()?.zero_index())
            .ok_or_else(|| anyhow_error_and_log("My role index does not exist".to_string()))?;
        // Derive distinct ids for generating the parts of c
        let mut rng_c: ChaCha20Rng = ChaCha20Rng::seed_from_u64(self.seed ^ id ^ 2);
        // Compute the c shares based on the true values of a and b
        let c_vec = DummyPreprocessing::share(
            session.amount_of_parties(),
            session.threshold(),
            a * b,
            &mut rng_c,
        )?;
        // Retrive the share of the calling party
        let c_share = c_vec
            .get(session.my_role()?.zero_index())
            .ok_or_else(|| anyhow_error_and_log("My role index does not exist".to_string()))?;
        Ok(Triple::new(*a_share, *b_share, *c_share))
    }

    /// Computes a random element deterministically but pseudorandomly constructed from the seed in [DummyPreprocessing] and the [OfflineId] `id`.
    fn next_random(
        &self,
        session: &mut Ses,
        id: OfflineId,
    ) -> anyhow::Result<Share<ResiduePoly<Z128>>> {
        // Construct a rng uniquely defined from the dummy seed and the id
        let mut rng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(self.seed ^ id);
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
}
impl DummyDebugPreprocessing {
    // Dummy preprocessing which generates shares deterministically from `seed`
    pub fn new(seed: u64) -> Self {
        DummyDebugPreprocessing { seed }
    }

    /// Samples a triple in plain from the full domain of the underlying ring
    pub fn sample<R: Ring>(owner: Role, rng: &mut impl RngCore) -> Triple<R> {
        let plain_a: Share<R> = Share::new(owner, R::sample(rng));
        let plain_b: Share<R> = Share::new(owner, R::sample(rng));
        let plain_c: Share<R> = Share::new(owner, plain_a.value() * plain_b.value());
        Triple::new(plain_a, plain_b, plain_c)
    }
}
impl<Rnd: RngCore + Send + Sync + Clone, R: Ring, Ses: BaseSessionHandles<Rnd>>
    Preprocessing<Rnd, R, Ses> for DummyDebugPreprocessing
{
    /// Computes a dummy triple deterministically constructed from the seed in [DummyPreprocessing] and the [OfflineId] `id`.
    fn next_triple(&self, session: &mut Ses, id: OfflineId) -> anyhow::Result<Triple<R>> {
        let plain_a = self.next_random(session, id ^ 1)?;
        let plain_b = self.next_random(session, id ^ 2)?;
        Ok(Triple::new(
            plain_a,
            plain_b,
            Share::new(session.my_role()?, plain_a.value() * plain_b.value()),
        ))
    }

    /// Computes a random element deterministically but pseudorandomly constructed from the seed in [DummyPreprocessing] and the [OfflineId] `id`.
    fn next_random(&self, session: &mut Ses, id: OfflineId) -> anyhow::Result<Share<R>> {
        // Construct a rng uniquely defined from the dummy seed and the id
        let mut rng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(self.seed ^ id);
        Ok(Share::new(session.my_role()?, R::sample(&mut rng)))
    }
}

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use crate::{
        execution::{
            online::triple::{
                DummyDebugPreprocessing, DummyPreprocessing, Preprocessing, Reconstruct, Triple,
            },
            party::Role,
            session::{BaseSessionHandles, ParameterHandles},
        },
        residue_poly::ResiduePoly,
        tests::helper::tests::{get_small_session, get_small_session_for_parties},
        Zero, Z128,
    };
    use std::num::Wrapping;

    use super::Share;

    #[test]
    fn test_debug_dummy_rand() {
        let preprocessing = DummyDebugPreprocessing::new(42);
        let mut session = get_small_session();
        let rand = preprocessing.next_random(&mut session, 1337).unwrap();
        let recon_rand =
            Share::<ResiduePoly<Z128>>::reconstruct(&session.parameters, vec![rand]).unwrap();
        // Check that things are "shared" in plain, i.e. with threshold=0
        assert_eq!(rand.value, recon_rand);
    }

    #[test]
    fn test_debug_dummy_triple() {
        let preprocessing = DummyDebugPreprocessing::new(42);
        let mut session = get_small_session();
        let trip: Triple<ResiduePoly<Z128>> =
            preprocessing.next_triple(&mut session, 1337).unwrap();
        let recon_c =
            Share::<ResiduePoly<Z128>>::reconstruct(&session.parameters, vec![trip.c]).unwrap();
        // Check that things are "shared" in plain, i.e. with threshold=0
        assert_eq!(recon_c, trip.a.value * trip.b.value);
    }

    #[test]
    fn test_threshold_dummy_share() {
        let msg = Wrapping(42);
        let mut session = get_small_session_for_parties(10, 3, Role(1));
        let shares = DummyPreprocessing::share(
            session.amount_of_parties(),
            session.threshold(),
            ResiduePoly::from_scalar(msg),
            session.rng(),
        )
        .unwrap();
        let recon = Share::<ResiduePoly<Z128>>::reconstruct(&session.parameters, shares).unwrap();
        assert_eq!(msg, recon.coefs[0]);
        // The functionality is currently only used to share a scalar so the rest of the coefficients should be 0
        for i in 1..recon.coefs.len() {
            assert_eq!(Wrapping::ZERO, recon.coefs[i]);
        }
    }

    #[test]
    fn test_threshold_dummy_rand() {
        let parties = 10;
        let threshold = 3;
        let mut rand_recon = Vec::new();
        let preprocessing = DummyPreprocessing::new(42);
        for i in 1..=parties {
            let mut session = get_small_session_for_parties(parties, threshold, Role(i as u64));
            let cur_rand = preprocessing.next_random(&mut session, 1337).unwrap();
            rand_recon.push(cur_rand);
        }
        let session = get_small_session_for_parties(parties, threshold, Role(1));
        let recon =
            Share::<ResiduePoly<Z128>>::reconstruct(&session.parameters, rand_recon).unwrap();
        // Assert equality with a reference value for exactly the seed: 42
        assert_eq!(
            Wrapping(202747963817102809561422760277939422522),
            recon.coefs[0]
        );
        // We just sanity check the rest of the coefficients
        for i in 1..recon.coefs.len() {
            assert_ne!(Wrapping::ZERO, recon.coefs[i]);
        }
    }

    #[traced_test]
    #[test]
    fn test_threshold_dummy_trip() {
        let parties = 10;
        let threshold = 3;
        let mut a_shares = Vec::new();
        let mut b_shares = Vec::new();
        let mut c_shares = Vec::new();
        let preprocessing = DummyPreprocessing::new(42);
        for i in 1..=parties {
            let mut session = get_small_session_for_parties(parties, threshold, Role(i as u64));
            let cur_trip: Triple<ResiduePoly<Z128>> =
                preprocessing.next_triple(&mut session, 1337).unwrap();
            a_shares.push(cur_trip.a);
            b_shares.push(cur_trip.b);
            c_shares.push(cur_trip.c);
        }
        let session = get_small_session_for_parties(parties, threshold, Role(1));
        let recon_a =
            Share::<ResiduePoly<Z128>>::reconstruct(&session.parameters, a_shares).unwrap();
        let recon_b =
            Share::<ResiduePoly<Z128>>::reconstruct(&session.parameters, b_shares).unwrap();
        let recon_c =
            Share::<ResiduePoly<Z128>>::reconstruct(&session.parameters, c_shares).unwrap();
        assert_eq!(recon_a * recon_b, recon_c);
    }
}
