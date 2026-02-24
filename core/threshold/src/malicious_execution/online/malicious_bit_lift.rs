use tonic::async_trait;

use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        galois_rings::common::{Monomials, ResiduePoly},
        structure_traits::{ErrorCorrect, Sample},
    },
    execution::{
        online::{
            bit_lift::{BitLift, SecureBitLift},
            preprocessing::{BasePreprocessing, BitPreprocessing},
        },
        runtime::sessions::base_session::BaseSessionHandles,
        sharing::share::Share,
    },
    ProtocolDescription,
};

/// A malicious implementation of the bit lift protocol that drops all the input bits and returns an empty vector
#[derive(Default, Clone)]
pub struct BitLiftDrop;

impl ProtocolDescription for BitLiftDrop {
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!("{indent}-BitLiftDrop")
    }
}

#[async_trait]
impl BitLift for BitLiftDrop {
    async fn execute<
        const EXTENSION_DEGREE: usize,
        Ses: BaseSessionHandles,
        P: BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>
            + BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
            + Send
            + ?Sized,
    >(
        _secret_bit_vector: Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
        _preproc: &mut P,
        _session: &mut Ses,
    ) -> anyhow::Result<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Monomials,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        Ok(vec![])
    }
}

/// A malicious implementation of the bit lift protocol that adds a random value to each input bit
#[derive(Default, Clone)]
pub struct BitLiftAddError;

impl ProtocolDescription for BitLiftAddError {
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!("{indent}-BitLiftAddError")
    }
}

#[async_trait]
impl BitLift for BitLiftAddError {
    async fn execute<
        const EXTENSION_DEGREE: usize,
        Ses: BaseSessionHandles,
        P: BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>
            + BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
            + Send
            + ?Sized,
    >(
        mut secret_bit_vector: Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Monomials,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        secret_bit_vector
            .iter_mut()
            .map(|share| {
                *share += ResiduePoly::<Z64, EXTENSION_DEGREE>::sample(session.rng());
            })
            .for_each(drop);

        SecureBitLift::execute(secret_bit_vector, preproc, session).await
    }
}

/// A malicious implementation of the bit lift protocol that acts as if there was one more bit
/// to lift
#[derive(Default, Clone)]
pub struct BitLiftWrongAmountTooMany;

impl ProtocolDescription for BitLiftWrongAmountTooMany {
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!("{indent}-BitLiftWrongAmountTooMany")
    }
}

#[async_trait]
impl BitLift for BitLiftWrongAmountTooMany {
    async fn execute<
        const EXTENSION_DEGREE: usize,
        Ses: BaseSessionHandles,
        P: BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>
            + BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
            + Send
            + ?Sized,
    >(
        mut secret_bit_vector: Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Monomials,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        secret_bit_vector.push(Share::new(
            secret_bit_vector[0].owner(),
            ResiduePoly::<Z64, EXTENSION_DEGREE>::sample(session.rng()),
        ));

        SecureBitLift::execute(secret_bit_vector, preproc, session).await
    }
}

/// A malicious implementation of the bit lift protocol that acts as if there was one less bit
/// to lift
#[derive(Default, Clone)]
pub struct BitLiftWrongAmountTooFew;

impl ProtocolDescription for BitLiftWrongAmountTooFew {
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!("{indent}-BitLiftWrongAmountTooFew")
    }
}

#[async_trait]
impl BitLift for BitLiftWrongAmountTooFew {
    async fn execute<
        const EXTENSION_DEGREE: usize,
        Ses: BaseSessionHandles,
        P: BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>
            + BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
            + Send
            + ?Sized,
    >(
        mut secret_bit_vector: Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Monomials,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        secret_bit_vector.pop();

        SecureBitLift::execute(secret_bit_vector, preproc, session).await
    }
}
