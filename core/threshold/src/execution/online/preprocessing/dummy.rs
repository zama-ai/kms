use super::BitDecPreprocessing;
use super::BitPreprocessing;
use super::DKGPreprocessing;
use super::InMemoryBitDecPreprocessing;
use super::NoiseBounds;
use super::NoiseFloodPreprocessing;
use crate::algebra::base_ring::Z128;
use crate::algebra::base_ring::Z64;
use crate::algebra::galois_rings::common::ResiduePoly;
use crate::algebra::structure_traits::ErrorCorrect;
use crate::algebra::structure_traits::Invert;
use crate::algebra::structure_traits::RingWithExceptionalSequence;
use crate::algebra::structure_traits::Solve;
use crate::execution::constants::LOG_B_SWITCH_SQUASH;
use crate::execution::constants::STATSEC;
use crate::execution::keyset_config::KeySetConfig;
use crate::execution::online::preprocessing::BasePreprocessing;
use crate::execution::online::preprocessing::RandomPreprocessing;
use crate::execution::online::preprocessing::TriplePreprocessing;
use crate::execution::online::secret_distributions::RealSecretDistributions;
use crate::execution::online::secret_distributions::SecretDistributions;
use crate::execution::online::triple::Triple;
use crate::execution::runtime::session::BaseSession;
use crate::execution::runtime::session::SessionParameters;
use crate::execution::runtime::session::SmallSession;
use crate::execution::sharing::shamir::RevealOp;
use crate::execution::sharing::shamir::ShamirSharings;
use crate::execution::tfhe_internals::parameters::DKGParams;
use crate::execution::tfhe_internals::parameters::TUniformBound;
use crate::{
    algebra::poly::Poly,
    algebra::structure_traits::Ring,
    error::error_handler::anyhow_error_and_log,
    execution::{runtime::party::Role, runtime::session::ParameterHandles, sharing::share::Share},
};
use aes_prng::AesRng;
use itertools::Itertools;
use rand::{CryptoRng, Rng, SeedableRng};
use tonic::async_trait;

/// Struct for dummy preprocessing for use in interactive tests although it is constructed non-interactively.
/// The struct reflects dummy shares that are technically correct Shamir shares of a polynomial
/// with `threshold` degree.
/// Its implementation is deterministic but pseudorandomly and fully derived using the `seed`.
#[derive(Clone)]
pub struct DummyPreprocessing<Z> {
    seed: u64,
    parameters: SessionParameters,
    pub rnd_ctr: u64,
    pub trip_ctr: u64,
    _phantom: std::marker::PhantomData<Z>,
}

impl<Z> DummyPreprocessing<Z>
where
    Z: RingWithExceptionalSequence,
{
    /// Dummy preprocessing which generates shares deterministically from `seed`
    pub fn new<Ses: ParameterHandles>(seed: u64, session: &Ses) -> Self {
        DummyPreprocessing::<Z> {
            seed,
            parameters: session.to_parameters(),
            rnd_ctr: 0,
            trip_ctr: 0,
            _phantom: Default::default(),
        }
    }

    /// Helper method for computing the Shamir shares of a `secret`.
    /// Returns a vector of the shares 0-indexed based on [Role]
    pub fn share(
        parties: usize,
        threshold: u8,
        secret: Z,
        rng: &mut (impl Rng + CryptoRng),
    ) -> anyhow::Result<Vec<Share<Z>>> {
        let role_with_embeddings = (1..=parties)
            .map(|party_id| {
                let party_role = Role::indexed_from_one(party_id);
                let embedding = Z::embed_role_to_exceptional_sequence(&party_role)?;
                Ok((party_role, embedding))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let poly = Poly::sample_random_with_fixed_constant(rng, secret, threshold as usize);

        Ok(role_with_embeddings
            .into_iter()
            .map(|(role, embedded_role)| Share::new(role, poly.eval(&embedded_role)))
            .collect())
    }
}

impl<Z> TriplePreprocessing<Z> for DummyPreprocessing<Z>
where
    Z: RingWithExceptionalSequence,
{
    /// Computes a dummy triple deterministically constructed from the seed in [DummyPreprocessing].
    fn next_triple(&mut self) -> anyhow::Result<Triple<Z>> {
        // Used to distinguish calls to next random and next triple
        const TRIP_FLAG: u64 = 0x47873E027A425DDE;
        // Use a new RNG based on the seed and counter
        let mut rng: AesRng = AesRng::seed_from_u64(self.seed ^ self.trip_ctr ^ TRIP_FLAG);
        let a = Z::sample(&mut rng);
        let a_vec = DummyPreprocessing::<Z>::share(
            self.parameters.num_parties(),
            self.parameters.threshold(),
            a,
            &mut rng,
        )?;
        let my_role = self.parameters.my_role();
        // Retrive the share of the calling party
        let a_share = my_role
            .get_from(&a_vec)
            .ok_or_else(|| anyhow_error_and_log("My role index does not exist".to_string()))?;
        let b = Z::sample(&mut rng);
        let b_vec = DummyPreprocessing::<Z>::share(
            self.parameters.num_parties(),
            self.parameters.threshold(),
            b,
            &mut rng,
        )?;
        // Retrive the share of the calling party
        let b_share = my_role
            .get_from(&b_vec)
            .ok_or_else(|| anyhow_error_and_log("My role index does not exist".to_string()))?;
        // Compute the c shares based on the true values of a and b
        let c_vec = DummyPreprocessing::<Z>::share(
            self.parameters.num_parties(),
            self.parameters.threshold(),
            a * b,
            &mut rng,
        )?;
        // Retrive the share of the calling party
        let c_share = my_role
            .get_from(&c_vec)
            .ok_or_else(|| anyhow_error_and_log("My role index does not exist".to_string()))?;
        self.trip_ctr += 1;
        Ok(Triple::new(*a_share, *b_share, *c_share))
    }

    fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<Z>>> {
        let mut res = Vec::with_capacity(amount);
        // Since there is no communication in the dummy implementation there is no need for optimizating the list call
        for _i in 0..amount {
            res.push(self.next_triple()?);
        }
        Ok(res)
    }

    fn append_triples(&mut self, _triples: Vec<Triple<Z>>) {
        unimplemented!()
    }

    fn triples_len(&self) -> usize {
        self.trip_ctr as usize
    }
}

impl<Z> RandomPreprocessing<Z> for DummyPreprocessing<Z>
where
    Z: RingWithExceptionalSequence,
{
    /// Computes a random element deterministically but pseudorandomly constructed from the seed in [DummyPreprocessing].
    fn next_random(&mut self) -> anyhow::Result<Share<Z>> {
        // Used to distinguish calls to next random and next triple
        const RAND_FLAG: u64 = 0x818DECF7255EBCE6;
        // Use a new RNG based on the seed and counter
        let mut rng: AesRng = AesRng::seed_from_u64(self.seed ^ self.rnd_ctr ^ RAND_FLAG);
        let secret = Z::sample(&mut rng);
        let all_parties_shares = Self::share(
            self.parameters.num_parties(),
            self.parameters.threshold(),
            secret,
            &mut rng,
        )?;
        let my_share = self
            .parameters
            .my_role()
            .get_from(&all_parties_shares)
            .ok_or_else(|| anyhow_error_and_log("Party share does not exist".to_string()))?;
        self.rnd_ctr += 1;
        Ok(*my_share)
    }

    fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>> {
        let mut res = Vec::with_capacity(amount);
        // Since there is no communication in the dummy implementation there is no need for optimizating the list call
        for _i in 0..amount {
            res.push(self.next_random()?);
        }
        Ok(res)
    }

    fn append_randoms(&mut self, _randoms: Vec<Share<Z>>) {
        unimplemented!()
    }

    fn randoms_len(&self) -> usize {
        self.rnd_ctr as usize
    }
}

impl<Z> BasePreprocessing<Z> for DummyPreprocessing<Z> where Z: RingWithExceptionalSequence {}

impl<Z> BitPreprocessing<Z> for DummyPreprocessing<Z>
where
    Z: RingWithExceptionalSequence,
{
    ///__NOTE__ : It is useless to append bits to a [`DummyPreprocessing`]
    /// we generate them on the fly with no interaction
    fn append_bits(&mut self, _bits: Vec<Share<Z>>) {}

    fn next_bit(&mut self) -> anyhow::Result<Share<Z>> {
        Ok(self.next_bit_vec(1)?[0])
    }

    fn next_bit_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>> {
        const BIT_FLAG: u64 = 0xB542074E84A9D88E;
        let mut rng = AesRng::seed_from_u64(BIT_FLAG ^ self.seed);
        let mut res = Vec::with_capacity(amount);
        let my_role = self.parameters.my_role();
        let my_share_zero = DummyPreprocessing::<Z>::share(
            self.parameters.num_parties(),
            self.parameters.threshold(),
            Z::ZERO,
            &mut rng,
        )?[&my_role];
        let my_share_one = DummyPreprocessing::<Z>::share(
            self.parameters.num_parties(),
            self.parameters.threshold(),
            Z::ONE,
            &mut rng,
        )?[&my_role];
        for _ in 0..amount {
            let bit = rng.get_bit() == 1;
            let secret = if bit { my_share_one } else { my_share_zero };
            res.push(secret);
        }
        Ok(res)
    }

    fn bits_len(&self) -> usize {
        unimplemented!("We do not store anything in dummy preprocessing");
    }
}

#[async_trait]
impl<const EXTENSION_DEGREE: usize> BitDecPreprocessing<EXTENSION_DEGREE>
    for DummyPreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
{
    async fn fill_from_base_preproc(
        &mut self,
        _preprocessing: &mut dyn BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>,
        _session: &mut BaseSession,
        _num_ctxts: usize,
    ) -> anyhow::Result<()> {
        unimplemented!("We do not implement filling for DummyPreprocessing")
    }

    fn cast_to_in_memory_impl(
        &mut self,
        num_ctxts: usize,
    ) -> anyhow::Result<InMemoryBitDecPreprocessing<EXTENSION_DEGREE>> {
        let num_bits = self.num_required_bits(num_ctxts);
        let num_triples = self.num_required_triples(num_ctxts);

        // Safe to use unwraps here because dummy never runs out of correlated randomness
        let bits = self.next_bit_vec(num_bits).unwrap();
        let triples = self.next_triple_vec(num_triples).unwrap();

        Ok(InMemoryBitDecPreprocessing::<EXTENSION_DEGREE> {
            available_triples: triples,
            available_bits: bits,
        })
    }
}

#[async_trait]
impl<const EXTENSION_DEGREE: usize> NoiseFloodPreprocessing<EXTENSION_DEGREE>
    for DummyPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    fn append_masks(&mut self, _masks: Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>) {
        unimplemented!("We do not implement filling for DummyPreprocessing")
    }

    fn next_mask(&mut self) -> anyhow::Result<ResiduePoly<Z128, EXTENSION_DEGREE>> {
        Ok(self.next_mask_vec(1)?.pop().unwrap())
    }

    fn next_mask_vec(
        &mut self,
        amount: usize,
    ) -> anyhow::Result<Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>> {
        let bound_d = (STATSEC + LOG_B_SWITCH_SQUASH) as usize;
        Ok(
            RealSecretDistributions::t_uniform(2 * amount, TUniformBound(bound_d), self)?
                .into_iter()
                .tuples()
                .map(|(a, b)| a.value() + b.value())
                .collect(),
        )
    }

    /// Fill the masks directly from the [`crate::execution::small_execution::prss::PRSSState`] available from [`SmallSession`]
    fn fill_from_small_session(
        &mut self,
        _session: &mut SmallSession<ResiduePoly<Z128, EXTENSION_DEGREE>>,
        _amount: usize,
    ) -> anyhow::Result<()> {
        unimplemented!("We do not implement filling for DummyPreprocessing")
    }

    /// Fill the masks by first generating bits via triples and randomness provided by [`BasePreprocessing`]
    async fn fill_from_base_preproc(
        &mut self,
        _preprocessing: &mut dyn BasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>,
        _session: &mut BaseSession,
        _num_ctxts: usize,
    ) -> anyhow::Result<()> {
        unimplemented!("We do not implement filling for DummyPreprocessing")
    }

    /// Fill the masks directly from available bits provided by [`BitPreprocessing`],
    /// using [`crate::execution::online::secret_distributions::SecretDistributions`]
    fn fill_from_bits_preproc(
        &mut self,
        _bit_preproc: &mut dyn BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>,
        _num_ctxts: usize,
    ) -> anyhow::Result<()> {
        unimplemented!("We do not implement filling for DummyPreprocessing")
    }
}

#[async_trait]
impl<Z> DKGPreprocessing<Z> for DummyPreprocessing<Z>
where
    Z: RingWithExceptionalSequence,
{
    fn next_noise_vec(
        &mut self,
        amount: usize,
        bound: NoiseBounds,
    ) -> anyhow::Result<Vec<Share<Z>>> {
        RealSecretDistributions::t_uniform(amount, bound.get_bound(), self)
    }

    ///__NOTE__ : It is useless to append noises to a [`DummyPreprocessing`]
    /// we generate them on the fly with no interaction
    fn append_noises(&mut self, _noises: Vec<Share<Z>>, _bound: NoiseBounds) {}

    async fn fill_from_base_preproc(
        &mut self,
        _params: DKGParams,
        _keyset_config: KeySetConfig,
        _session: &mut BaseSession,
        _preprocessing: &mut dyn BasePreprocessing<Z>,
    ) -> anyhow::Result<()> {
        unimplemented!("We do not implement filling for DummyPreprocessing")
    }

    fn fill_from_triples_and_bit_preproc(
        &mut self,
        _params: DKGParams,
        _keyset_config: KeySetConfig,
        _session: &mut BaseSession,
        _preprocessing_triples: &mut dyn BasePreprocessing<Z>,
        _preprocessing_bits: &mut dyn BitPreprocessing<Z>,
    ) -> anyhow::Result<()> {
        unimplemented!("We do not implement filling for DummyPreprocessing")
    }

    ///__NOTE__ : Since we only generate noise on the fly,
    /// this call will always return 0;
    fn noise_len(&self, _bound: NoiseBounds) -> usize {
        0
    }
}

/// Dummy preprocessing struct constructed primarely for use for debugging
/// Concretely the struct can be used _non-interactively_ since shares will all be points,
/// i.e. sharing of threshold=0
pub struct DummyDebugPreprocessing<Z> {
    seed: u64,
    session: SessionParameters,
    rnd_ctr: u64,
    trip_ctr: u64,
    _phantom_z: std::marker::PhantomData<Z>,
}
impl<Z> DummyDebugPreprocessing<Z> {
    // Dummy preprocessing which generates shares deterministically from `seed`
    pub fn new<Ses: ParameterHandles>(seed: u64, session: &Ses) -> Self {
        DummyDebugPreprocessing::<Z> {
            seed,
            session: session.to_parameters(),
            rnd_ctr: 0,
            trip_ctr: 0,
            _phantom_z: Default::default(),
        }
    }
}
impl<Z: Ring> TriplePreprocessing<Z> for DummyDebugPreprocessing<Z> {
    /// Computes a dummy triple deterministically constructed from the seed in [DummyPreprocessing].
    fn next_triple(&mut self) -> anyhow::Result<Triple<Z>> {
        // Used to distinguish calls to next random and next triple
        const TRIP_FLAG: u64 = 0x47873E027A425DDE;
        let mut rng: AesRng = AesRng::seed_from_u64(self.seed ^ self.trip_ctr ^ TRIP_FLAG);
        self.trip_ctr += 1;
        let a = Share::new(self.session.my_role(), Z::sample(&mut rng));
        let b = Share::new(self.session.my_role(), Z::sample(&mut rng));
        let c = Share::new(self.session.my_role(), a.value() * b.value());
        Ok(Triple::new(a, b, c))
    }

    fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<Z>>> {
        let mut res = Vec::with_capacity(amount);
        // Since there is no communication in the dummy implementation there is no need for optimizating
        // the construction of a vector of triples. Hence we just iteratively call `next_triple` `amount` times.
        for _i in 0..amount {
            res.push(self.next_triple()?);
        }
        Ok(res)
    }

    fn append_triples(&mut self, _triples: Vec<Triple<Z>>) {
        unimplemented!()
    }

    fn triples_len(&self) -> usize {
        self.trip_ctr as usize
    }
}

impl<Z: Ring> RandomPreprocessing<Z> for DummyDebugPreprocessing<Z> {
    /// Computes a random element deterministically but pseudorandomly constructed from the seed in [DummyPreprocessing].
    fn next_random(&mut self) -> anyhow::Result<Share<Z>> {
        // Used to distinguish calls to next random and next triple
        const RAND_FLAG: u64 = 0x818DECF7255EBCE6;
        // Construct a rng uniquely defined from the dummy seed and the ctr
        let mut rng: AesRng = AesRng::seed_from_u64(self.seed ^ self.rnd_ctr ^ RAND_FLAG);
        self.rnd_ctr += 1;
        Ok(Share::new(self.session.my_role(), Z::sample(&mut rng)))
    }

    fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>> {
        let mut res = Vec::with_capacity(amount);
        // Since there is no communication in the dummy implementation there is no need for optimizating
        // the construction of a vector of random shares. Hence we just iteratively call `next_random` `amount` times.
        for _i in 0..amount {
            res.push(self.next_random()?);
        }
        Ok(res)
    }

    fn append_randoms(&mut self, _randoms: Vec<Share<Z>>) {
        unimplemented!()
    }

    fn randoms_len(&self) -> usize {
        self.rnd_ctr as usize
    }
}

impl<Z: Ring> BasePreprocessing<Z> for DummyDebugPreprocessing<Z> {}

/// Helper method to reconstructs a shared ring element based on a vector of shares.
/// Returns an error if reconstruction fails, and otherwise the reconstructed ring value.
pub fn reconstruct<Z: Ring + ErrorCorrect, Ses: ParameterHandles>(
    session: &Ses,
    shares: Vec<Share<Z>>,
) -> anyhow::Result<Z> {
    ShamirSharings::create(shares).reconstruct(session.threshold() as usize)
}

#[cfg(test)]
mod tests {
    use crate::{
        algebra::{
            base_ring::{Z128, Z64},
            galois_rings::degree_4::{ResiduePolyF4, ResiduePolyF4Z128},
            structure_traits::Zero,
        },
        networking::NetworkMode,
        tests::helper::testing::get_networkless_base_session_for_parties,
        tests::helper::tests::get_base_session,
    };
    use paste::paste;
    use std::num::Wrapping;

    use super::Share;
    use crate::execution::online::preprocessing::dummy::reconstruct;
    use crate::execution::online::preprocessing::dummy::DummyDebugPreprocessing;
    use crate::execution::online::preprocessing::dummy::DummyPreprocessing;
    use crate::execution::online::preprocessing::dummy::Role;
    use crate::execution::online::preprocessing::RandomPreprocessing;
    use crate::execution::online::preprocessing::TriplePreprocessing;
    use crate::execution::online::triple::Triple;
    use crate::execution::runtime::session::{BaseSessionHandles, ParameterHandles};
    use itertools::Itertools;

    #[test]
    fn test_debug_dummy_rand() {
        //Dummy do not care about network assumption, default to Sync
        let session = get_base_session(NetworkMode::Sync);
        let mut preprocessing = DummyDebugPreprocessing::<ResiduePolyF4Z128>::new(42, &session);
        let rand = preprocessing.next_random_vec(2).unwrap();
        // Check that the values are different
        assert_ne!(rand[0], rand[1]);
        let recon_a = reconstruct(&session, vec![rand[0]]).unwrap();
        let recon_b = reconstruct(&session, vec![rand[1]]).unwrap();
        // Check that things are "shared" in plain, i.e. with threshold=0
        assert_eq!(rand[0].value(), recon_a);
        assert_eq!(rand[1].value(), recon_b);
    }

    #[test]
    fn test_debug_dummy_triple() {
        //Dummy do not care about network assumption, default to Sync
        let session = get_base_session(NetworkMode::Sync);
        let mut preprocessing = DummyDebugPreprocessing::<ResiduePolyF4Z128>::new(42, &session);
        let trips: Vec<Triple<ResiduePolyF4Z128>> = preprocessing.next_triple_vec(2).unwrap();
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
        //Dummy do not care about network assumption, default to Sync
        let session = get_base_session(NetworkMode::Sync);
        let mut preprocessing = DummyDebugPreprocessing::<ResiduePolyF4Z128>::new(42, &session);
        let rand_a: Share<ResiduePolyF4Z128> = preprocessing.next_random().unwrap();
        let trip_a: Triple<ResiduePolyF4Z128> = preprocessing.next_triple().unwrap();
        let rand_b: Share<ResiduePolyF4Z128> = preprocessing.next_random().unwrap();
        let trip_b: Triple<ResiduePolyF4Z128> = preprocessing.next_triple().unwrap();
        assert_ne!(trip_a, trip_b);
        assert_ne!(rand_a, rand_b);
        assert_ne!(trip_a.a, rand_a);
        assert_ne!(trip_a.b, rand_a);
        let recon_trip_a = reconstruct(&session, vec![trip_a.c]).unwrap();
        let recon_trip_b = reconstruct(&session, vec![trip_b.c]).unwrap();
        let recon_rand_a = reconstruct(&session, vec![rand_a]).unwrap();
        let recon_rand_b = reconstruct(&session, vec![rand_b]).unwrap();
        // Check that things are "shared" in plain, i.e. with threshold=0
        assert_eq!(recon_trip_a, trip_a.a.value() * trip_a.b.value());
        assert_eq!(recon_trip_b, trip_b.a.value() * trip_b.b.value());
        assert_eq!(rand_a.value(), recon_rand_a);
        assert_eq!(rand_b.value(), recon_rand_b);
    }

    macro_rules! test_preprocessing {
        ($z:ty, $u:ty) => {
            paste! {

                #[test]
                fn [<test_threshold_dummy_share $z:lower>]() {
                    let msg = ResiduePolyF4::<$z>::from_scalar(Wrapping(42));
                    let mut session = get_networkless_base_session_for_parties(10, 3, Role::indexed_from_one(1));
                    let shares = DummyPreprocessing::<ResiduePolyF4<$z>>::share(
                        session.num_parties(),
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
                        let session = get_networkless_base_session_for_parties(parties, threshold, Role::indexed_from_one(i));
                        preps.push(DummyPreprocessing::<ResiduePolyF4<$z>>::new(42, &session));
                    }
                    let recon = [<get_rand_ $z:lower>](parties, threshold, 2, &mut preps);
                    // Check that the values are different
                    assert_ne!(recon[0], recon[1]);
                    // Sanity check the result (results are extremely unlikely to be zero)
                    assert_ne!(recon[0], ResiduePolyF4::<$z>::ZERO);
                    assert_ne!(recon[1], ResiduePolyF4::<$z>::ZERO);
                }
                fn [<get_rand_ $z:lower>](
                    parties: usize,
                    threshold: u8,
                    amount: usize,
                    preps: &mut [DummyPreprocessing::<ResiduePolyF4<$z>>],
                ) -> Vec<ResiduePolyF4<$z>> {
                    let session = get_networkless_base_session_for_parties(parties, threshold, Role::indexed_from_one(1));
                    let mut res = Vec::new();
                    let mut temp: Vec<Vec<Share<ResiduePolyF4<$z>>>> = Vec::new();
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
                        let session = get_networkless_base_session_for_parties(parties, threshold, Role::indexed_from_one(i));
                        preps.push(DummyPreprocessing::<ResiduePolyF4<$z>>::new(42, &session));
                    }
                    let trips = [<get_trip_ $z:lower>](parties, threshold, 2, &mut preps);
                    assert_ne!(trips[0], trips[1]);
                }

                fn [<get_trip_ $z:lower>](
                    parties: usize,
                    threshold: u8,
                    amount: usize,
                    preps: &mut [DummyPreprocessing::<ResiduePolyF4<$z>>],
                ) -> Vec<(ResiduePolyF4<$z>, ResiduePolyF4<$z>, ResiduePolyF4<$z>)> {
                    let session = get_networkless_base_session_for_parties(parties, threshold, Role::indexed_from_one(1));
                    let mut res = Vec::new();
                    let mut a_shares = Vec::new();
                    let mut b_shares = Vec::new();
                    let mut c_shares = Vec::new();
                    for i in 1..=parties {
                        let preprocessing = preps.get_mut(i - 1).unwrap();
                        let cur_trip: Vec<Triple<ResiduePolyF4<$z>>> =
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
                        let session = get_networkless_base_session_for_parties(parties, threshold, Role::indexed_from_one(i));
                        preps.push(DummyPreprocessing::<ResiduePolyF4<$z>>::new(42, &session));
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
