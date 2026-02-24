use std::sync::Arc;

use tonic::async_trait;

use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        galois_rings::common::{Monomials, ResiduePoly},
        structure_traits::{ErrorCorrect, FromU128},
    },
    execution::{
        online::{
            bit_manipulation::{BatchedBits, Bits},
            preprocessing::{BasePreprocessing, BitPreprocessing},
            triple::open_list,
        },
        runtime::sessions::base_session::BaseSessionHandles,
        sharing::share::Share,
    },
    ProtocolDescription,
};

#[async_trait]
pub trait BitLift: Send + Sync + Clone + ProtocolDescription {
    /// Lifts a vector of bits shared over a galois extension of Z64 into a vector of bits shared over a galois estension of Z128
    /// # Arguments
    /// * `secret_bit_vector` - Vector of bits shared over a galois extension of Z64
    /// * `preproc` - Randoms bits over the extension of Z128
    /// * `session` - Session handles to use for the execution
    /// # Returns
    /// Vector of bits shared over a galois extension of Z128
    ///
    /// __NOTE: If the input bits are not actually bits (i.e., not in {0,1}), this is very much wrong and insecure !__
    async fn execute<
        const EXTENSION_DEGREE: usize,
        Ses: BaseSessionHandles,
        P: BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>
            + BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
            + Send
            + ?Sized,
    >(
        secret_bit_vector: Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Monomials,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect;
}

#[derive(Default, Clone)]
pub struct SecureBitLift;

impl ProtocolDescription for SecureBitLift {
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!("{indent}-SecureBitLift")
    }
}

#[async_trait]
impl BitLift for SecureBitLift {
    async fn execute<
        const EXTENSION_DEGREE: usize,
        Ses: BaseSessionHandles,
        P: BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>
            + BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
            + Send
            + ?Sized,
    >(
        secret_bit_vector: Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Monomials,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let amount = secret_bit_vector.len();

        let random_bits_z128 = preproc.next_bit_vec(amount)?;

        // Copy of the randoms bits, except modswitched to Z64 (reminiscent of "dabits")
        // note that they are still the same bits as in Z128
        let random_bits_z64 = Arc::new(
            random_bits_z128
                .iter()
                .map(|b| Share::new(b.owner(), b.value().to_residuepoly64()))
                .collect::<Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>>(),
        );

        let secret_bit_vector = Arc::new(secret_bit_vector);

        // Masking the secret bit vector with random bits in MPC
        let masked_secret_bits = Bits::xor_list_secret_secret(
            Arc::clone(&secret_bit_vector),
            Arc::clone(&random_bits_z64),
            preproc,
            session,
        )
        .await?;

        let opened_masked_bits_z64 = open_list(&masked_secret_bits, session).await?;

        let opened_masked_bits_z128 = opened_masked_bits_z64
            .into_iter()
            .map(
                |s| ResiduePoly::<Z128, EXTENSION_DEGREE> {
                    coefs: s.coefs.map(|c| Z128::from_u128(c.0 as u128)),
                }, // Lift to Z128
            )
            .collect::<Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>>();

        // Remove the mask by xoring, xor secret clear is only available for vec of vec
        // so wrap and unwrap to/from vec of vec
        let unmasked_lifted_bits =
            BatchedBits::xor_list_secret_clear(&[random_bits_z128], &[opened_masked_bits_z128])?
                .remove(0);

        Ok(unmasked_lifted_bits)
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use crate::{
        algebra::{
            base_ring::{Z128, Z64},
            galois_rings::common::{Monomials, ResiduePoly},
            structure_traits::ErrorCorrect,
        },
        execution::{
            online::{
                bit_lift::{BitLift, SecureBitLift},
                preprocessing::{dummy::DummyPreprocessing, BitPreprocessing},
                triple::open_list,
            },
            runtime::sessions::large_session::LargeSession,
            sharing::share::Share,
        },
        malicious_execution::online::malicious_bit_lift::{
            BitLiftAddError, BitLiftDrop, BitLiftWrongAmountTooFew, BitLiftWrongAmountTooMany,
        },
        networking::NetworkMode,
        tests::helper::tests::{
            execute_protocol_large_w_disputes_and_malicious, TestingParameters,
        },
    };

    async fn test_bit_lift<const EXTENSION_DEGREE: usize, MaliciousBitLift: BitLift>(
        params: TestingParameters,
        num_bits: usize,
        malicious_bit_lift: MaliciousBitLift,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Monomials,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let mut task_honest = |mut session: LargeSession| async move {
            let mut prep = DummyPreprocessing::new(42, &session);

            // Pull out some random bits mod Z64 that we will lift
            let bits_to_lift: Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>> =
                prep.next_bit_vec(num_bits).unwrap();

            assert_eq!(bits_to_lift.len(), num_bits);

            let opened_bits_z64 = open_list(&bits_to_lift, &session).await.unwrap();

            let lifted_bits = SecureBitLift::execute(bits_to_lift, &mut prep, &mut session)
                .await
                .unwrap();

            let opened_bits_z128 = open_list(&lifted_bits, &session).await.unwrap();

            assert_eq!(
                opened_bits_z64.len(),
                opened_bits_z128.len(),
                "Number of opened bits should be the same before and after lifting"
            );

            for (b64, (idx, b128)) in opened_bits_z64
                .iter()
                .zip_eq(opened_bits_z128.iter().enumerate())
            {
                let b64_scalar = b64.to_scalar().unwrap().0;
                // Sanity check we indeed started with bits
                assert!(
                    b64_scalar == 0 || b64_scalar == 1,
                    "Input {idx} was not actually a bit, got {}",
                    b64_scalar
                );

                assert_eq!(
                    b64_scalar,
                    b128.to_scalar().unwrap().0 as u64,
                    "Lifted bit {idx} is not the same as original bit, expected {}, got {}",
                    b64_scalar,
                    b128.to_scalar().unwrap().0
                );
            }
            Ok::<(), ()>(())
        };

        let mut task_malicious =
            |mut session: LargeSession, _malicious_bitlift: MaliciousBitLift| async move {
                let mut prep = DummyPreprocessing::new(42, &session);

                // Pull out some random bits mod Z64 that we will lift
                let bits_to_lift: Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>> =
                    prep.next_bit_vec(num_bits).unwrap();

                assert_eq!(bits_to_lift.len(), num_bits);

                let _opened_bits_z64 = open_list(&bits_to_lift, &session).await;

                let lifted_bits = MaliciousBitLift::execute(bits_to_lift, &mut prep, &mut session)
                    .await
                    .unwrap();

                let _opened_bits_z128 = open_list(&lifted_bits, &session).await;

                Ok::<(), ()>(())
            };

        let (results_honest, _results_malicious) =
            execute_protocol_large_w_disputes_and_malicious::<
                _,
                _,
                _,
                _,
                _,
                ResiduePoly<Z64, EXTENSION_DEGREE>,
                EXTENSION_DEGREE,
            >(
                &params,
                &params.dispute_pairs,
                &params.malicious_roles,
                malicious_bit_lift,
                NetworkMode::Async,
                None,
                &mut task_honest,
                &mut task_malicious,
            )
            .await;
        assert_eq!(
            results_honest.len(),
            params.num_parties - params.malicious_roles.len()
        );
        assert!(results_honest.iter().all(|res| res.1.is_ok()));
    }

    #[tokio::test]
    async fn sunshine() {
        let params = TestingParameters::init(4, 1, &[], &[], &[], false, None);
        test_bit_lift::<4, _>(params, 10, SecureBitLift).await;
    }

    #[rstest::rstest]
    async fn malicious_lift<B: BitLift + 'static>(
        #[values(
            BitLiftDrop,
            BitLiftWrongAmountTooMany,
            BitLiftWrongAmountTooFew,
            BitLiftAddError
        )]
        malicious_bit_lift: B,
    ) {
        // Note: Malicious strategies above to do not depend on a "role to lie to"
        let params = TestingParameters::init(4, 1, &[2], &[], &[], false, None);
        test_bit_lift::<4, _>(params, 10, malicious_bit_lift).await;
    }
}
