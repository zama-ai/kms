use aes_prng::AesRng;
use async_trait::async_trait;
use rand::SeedableRng;
use rand::{CryptoRng, Rng};
use tracing::instrument;

use super::vss::{SecureVss, Vss};
use crate::algebra::structure_traits::{ErrorCorrect, Ring, RingEmbed};
use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::{runtime::session::LargeSessionHandles, sharing::open::robust_open_to_all},
};

/// Secure implementation of Coinflip as defined in NIST document
///
/// In particular, relies on the secure version of
/// the VSS protocol defined in [`SecureVss`]
pub type SecureCoinflip = RealCoinflip<SecureVss>;

#[async_trait]
pub trait Coinflip: Send + Sync + Clone + Default {
    async fn execute<Z, R: Rng + CryptoRng, L: LargeSessionHandles<R>>(
        &self,
        session: &mut L,
    ) -> anyhow::Result<Z>
    where
        Z: ErrorCorrect,
        Z: Ring,
        Z: RingEmbed;
}

#[derive(Default, Clone)]
pub struct DummyCoinflip {}

#[async_trait]
impl Coinflip for DummyCoinflip {
    async fn execute<Z: Ring, R: Rng + CryptoRng, L: LargeSessionHandles<R>>(
        &self,
        _session: &mut L,
    ) -> anyhow::Result<Z> {
        //Everyone just generate the same randomness by calling a new rng with a fixed seed
        let mut rng = AesRng::seed_from_u64(0);
        Ok(Z::sample(&mut rng))
    }
}

#[derive(Default, Clone)]
pub struct RealCoinflip<V: Vss> {
    vss: V,
}

impl<V: Vss> RealCoinflip<V> {
    pub fn init(vss: V) -> Self {
        Self { vss }
    }
}

#[async_trait]
impl<V: Vss> Coinflip for RealCoinflip<V> {
    #[instrument(name="CoinFlip",skip(self,session),fields(sid = ?session.session_id(), own_identity=?session.own_identity()))]
    async fn execute<Z, R: Rng + CryptoRng, L: LargeSessionHandles<R>>(
        &self,
        session: &mut L,
    ) -> anyhow::Result<Z>
    where
        Z: ErrorCorrect,
        Z: Ring,
        Z: RingEmbed,
    {
        //NOTE: I don't care if I am in Corrupt
        let my_secret = Z::sample(session.rng());

        let shares_of_contributions = self.vss.execute(session, &my_secret).await?;

        //Note that we don't care about summing only non-corrupt contributions as
        //output of VSS from corrupted parties is the trivial 0 sharing
        let share_of_coin = shares_of_contributions.into_iter().sum::<Z>();

        let opening =
            robust_open_to_all(session, share_of_coin, session.threshold() as usize).await?;

        match opening {
            Some(v) => Ok(v),
            _ => Err(anyhow_error_and_log(
                "No Value reconstructed in coinflip".to_string(),
            )),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use super::{Coinflip, DummyCoinflip, RealCoinflip, SecureCoinflip};
    #[cfg(feature = "slow_tests")]
    use crate::execution::large_execution::vss::tests::{
        DroppingVssAfterR1, DroppingVssAfterR2, DroppingVssFromStart, MaliciousVssR1,
    };
    use crate::{
        algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
        execution::{
            communication::broadcast::SyncReliableBroadcast,
            large_execution::vss::{SecureVss, Vss},
            runtime::{
                party::{Identity, Role},
                session::{
                    BaseSessionHandles, LargeSession, LargeSessionHandles, ParameterHandles,
                },
                test_runtime::DistributedTestRuntime,
            },
            sharing::open::robust_open_to_all,
        },
        tests::helper::tests::{
            execute_protocol_large_w_disputes_and_malicious,
            get_networkless_large_session_for_parties, TestingParameters,
        },
    };
    use crate::{
        algebra::structure_traits::{ErrorCorrect, Ring, RingEmbed},
        networking::NetworkMode,
    };
    use aes_prng::AesRng;
    use anyhow::anyhow;
    use async_trait::async_trait;
    use rand::SeedableRng;
    use rand::{CryptoRng, Rng};
    use rstest::rstest;
    use tokio::task::JoinSet;

    #[test]
    fn test_dummy_coinflip() {
        let identities = vec![
            Identity("localhost:5000".to_string()),
            Identity("localhost:5001".to_string()),
            Identity("localhost:5002".to_string()),
            Identity("localhost:5003".to_string()),
            Identity("localhost:5004".to_string()),
        ];
        let threshold = 1;
        //Coinflip assumes Sync network
        let runtime = DistributedTestRuntime::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >::new(identities.clone(), threshold, NetworkMode::Sync, None);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        for (party_nb, _) in runtime.identities.iter().enumerate() {
            let mut session = get_networkless_large_session_for_parties(
                identities.len(),
                threshold,
                Role::indexed_by_zero(party_nb),
            );
            set.spawn(async move {
                let dummy_coinflip = DummyCoinflip::default();
                (
                    party_nb,
                    dummy_coinflip
                        .execute::<ResiduePolyF4Z128, _, _>(&mut session)
                        .await
                        .unwrap(),
                )
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

        //make sure result for p0 is correct and all parties have the same result
        let p0_result = results[0].1;
        for (_, r) in results {
            assert_eq!(r, p0_result);
        }
    }

    ///Performs the VSS and does nothing after that (returns its secret)
    #[derive(Default, Clone)]
    pub(crate) struct DroppingCoinflipAfterVss<V: Vss> {
        vss: V,
    }

    impl<V: Vss> DroppingCoinflipAfterVss<V> {
        pub fn init(vss_strategy: V) -> Self {
            Self { vss: vss_strategy }
        }
    }

    ///Performs the coinflip, but does not send the correct shares for reconstruction
    #[derive(Default, Clone)]
    pub(crate) struct MaliciousCoinflipRecons<V: Vss> {
        vss: V,
    }

    impl<V: Vss> MaliciousCoinflipRecons<V> {
        pub fn init(vss_strategy: V) -> Self {
            Self { vss: vss_strategy }
        }
    }

    #[async_trait]
    impl<V: Vss> Coinflip for DroppingCoinflipAfterVss<V> {
        async fn execute<
            Z: Ring + RingEmbed + ErrorCorrect,
            R: Rng + CryptoRng,
            L: LargeSessionHandles<R>,
        >(
            &self,
            session: &mut L,
        ) -> anyhow::Result<Z> {
            let my_secret = Z::sample(session.rng());

            let _ = self.vss.execute::<Z, R, L>(session, &my_secret).await?;

            Ok(my_secret)
        }
    }

    #[async_trait]
    impl<V: Vss> Coinflip for MaliciousCoinflipRecons<V> {
        async fn execute<
            Z: Ring + RingEmbed + ErrorCorrect,
            R: Rng + CryptoRng,
            L: LargeSessionHandles<R>,
        >(
            &self,
            session: &mut L,
        ) -> anyhow::Result<Z> {
            let my_secret = Z::sample(session.rng());

            let shares_of_contributions = self.vss.execute::<Z, R, L>(session, &my_secret).await?;

            //Add an error to share_of_coins
            let mut share_of_coins = shares_of_contributions.into_iter().sum();
            share_of_coins += Z::sample(session.rng());

            let opening =
                robust_open_to_all(session, share_of_coins, session.threshold() as usize).await?;

            match opening {
                Some(v) => Ok(v),
                _ => Err(anyhow!("Malicious error")),
            }
        }
    }

    //Helper function to plug malicious coinflip strategies
    fn test_coinflip_strategies<
        Z: Ring + RingEmbed + ErrorCorrect,
        const EXTENSION_DEGREE: usize,
        C: Coinflip + 'static,
    >(
        params: TestingParameters,
        malicious_coinflip: C,
    ) {
        let mut task_honest = |mut session: LargeSession| async move {
            let real_coinflip = SecureCoinflip::default();
            (
                session.my_role().unwrap().zero_based(),
                real_coinflip
                    .execute::<Z, _, _>(&mut session)
                    .await
                    .unwrap(),
                session.corrupt_roles().clone(),
            )
        };

        let mut task_malicious = |mut session: LargeSession, malicious_coinflip: C| async move {
            (
                session.my_role().unwrap().zero_based(),
                malicious_coinflip
                    .execute::<Z, _, _>(&mut session)
                    .await
                    .unwrap(),
                session.corrupt_roles().clone(),
            )
        };

        //Coinflip assumes Sync network
        let (results_honest, _) =
            execute_protocol_large_w_disputes_and_malicious::<_, _, _, _, _, Z, EXTENSION_DEGREE>(
                &params,
                &[],
                &params.malicious_roles,
                malicious_coinflip,
                NetworkMode::Sync,
                None,
                &mut task_honest,
                &mut task_malicious,
            );

        //make sure the  malicious set of all honest parties is in sync
        let ref_malicious_set = results_honest[0].2.clone();
        for (_, _, malicious_set) in results_honest.iter() {
            assert_eq!(malicious_set, &ref_malicious_set);
        }

        //If it applies
        //Make sure malicious parties are detected as such
        if params.should_be_detected {
            for role in params.malicious_roles.iter() {
                assert!(ref_malicious_set.contains(role));
            }
        } else {
            assert!(ref_malicious_set.is_empty());
        }

        //Compute expected results
        let mut expected_res = Z::ZERO;
        for party_nb in 0..params.num_parties {
            if !(params
                .malicious_roles
                .contains(&Role::indexed_by_zero(party_nb))
                && params.should_be_detected)
            {
                let mut tmp_rng = AesRng::seed_from_u64(party_nb as u64);
                expected_res += Z::sample(&mut tmp_rng);
            }
        }

        //make sure result for p1 is correct and all parties have the same result
        for (_, r, corrupt_roles) in results_honest {
            if params.should_be_detected {
                for role in params.malicious_roles.iter() {
                    assert!(corrupt_roles.contains(role));
                }
            }
            assert_eq!(r, expected_res);
        }
    }

    // Rounds: We expect 3+1+t+1 rounds on the happy path
    #[rstest]
    #[case(TestingParameters::init_honest(4, 1, Some(6)))]
    #[case(TestingParameters::init_honest(7, 2, Some(7)))]
    #[case(TestingParameters::init_honest(10, 3, Some(8)))]
    fn test_coinflip_honest_z128(#[case] params: TestingParameters) {
        let malicious_coinflip = SecureCoinflip::default();
        test_coinflip_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_coinflip.clone(),
        );
        test_coinflip_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_coinflip.clone(),
        );
    }

    //Test when coinflip aborts after the VSS for all kinds of VSS
    //No matter the strategy we expect all honest parties to output the same thing
    //We also specify whether we expect the cheating strategy to be detected, if so we check we do detect the cheaters
    #[rstest]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], false, None), SecureVss::default())]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], true, None), DroppingVssAfterR1::default())]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], false, None), DroppingVssAfterR2::init(&SyncReliableBroadcast::default()))]
    #[case(TestingParameters::init(4, 1, &[1], &[2], &[], false, None), MaliciousVssR1::init(&SyncReliableBroadcast::default(),&params.roles_to_lie_to))]
    #[case(TestingParameters::init(4, 1, &[1], &[0,2], &[], true, None), MaliciousVssR1::init(&SyncReliableBroadcast::default(),&params.roles_to_lie_to))]
    #[case(TestingParameters::init(7, 2, &[1,3], &[0,2], &[], false, None), MaliciousVssR1::init(&SyncReliableBroadcast::default(),&params.roles_to_lie_to))]
    #[case(TestingParameters::init(7, 2, &[1,3], &[0,2,4,6], &[], true, None), MaliciousVssR1::init(&SyncReliableBroadcast::default(),&params.roles_to_lie_to))]
    #[cfg(feature = "slow_tests")]
    fn test_coinflip_dropout<V: Vss + 'static>(
        #[case] params: TestingParameters,
        #[case] malicious_vss: V,
    ) {
        let dropping_coinflip = DroppingCoinflipAfterVss {
            vss: malicious_vss.clone(),
        };
        test_coinflip_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            dropping_coinflip.clone(),
        );
        test_coinflip_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            dropping_coinflip.clone(),
        );
    }

    //Test honest coinflip with all kinds of malicious strategies for VSS
    //No matter the strategy, we expect all honest parties to end up with the same output
    //We also specify whether we expect the cheating strategy to be detected, if so we check we do detect the cheaters
    #[rstest]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], true, None), DroppingVssFromStart::default())]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], true, None), DroppingVssAfterR1::default())]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], false, None), DroppingVssAfterR2::init(&SyncReliableBroadcast::default()))]
    #[case(TestingParameters::init(4, 1, &[1], &[2], &[], false, None), MaliciousVssR1::init(&SyncReliableBroadcast::default(),&params.roles_to_lie_to))]
    #[case(TestingParameters::init(4, 1, &[1], &[0,2], &[], true, None), MaliciousVssR1::init(&SyncReliableBroadcast::default(),&params.roles_to_lie_to))]
    #[case(TestingParameters::init(7, 2, &[1,3], &[0,2], &[], false, None), MaliciousVssR1::init(&SyncReliableBroadcast::default(),&params.roles_to_lie_to))]
    #[case(TestingParameters::init(7, 2, &[1,3], &[0,2,4,6], &[], true, None), MaliciousVssR1::init(&SyncReliableBroadcast::default(),&params.roles_to_lie_to))]
    #[cfg(feature = "slow_tests")]
    fn test_coinflip_malicious_vss<V: Vss + 'static>(
        #[case] params: TestingParameters,
        #[case] malicious_vss: V,
    ) {
        let real_coinflip_with_malicious_vss = RealCoinflip {
            vss: malicious_vss.clone(),
        };

        test_coinflip_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            real_coinflip_with_malicious_vss.clone(),
        );
        test_coinflip_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            real_coinflip_with_malicious_vss.clone(),
        );
    }

    //Test malicious coinflip with all kinds of strategies for VSS (honest and malicious)
    //Again, we always expect the honest parties to agree on the output
    #[rstest]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], false, None), SecureVss::default())]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], true, None), DroppingVssAfterR1::default())]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], false, None), DroppingVssAfterR2::init(&SyncReliableBroadcast::default()))]
    #[case(TestingParameters::init(4, 1, &[1], &[2], &[], false, None), MaliciousVssR1::init(&SyncReliableBroadcast::default(),&params.roles_to_lie_to))]
    #[case(TestingParameters::init(4, 1, &[1], &[0,2], &[], true, None), MaliciousVssR1::init(&SyncReliableBroadcast::default(),&params.roles_to_lie_to))]
    #[case(TestingParameters::init(7, 2, &[1,3], &[0,2], &[], false, None), MaliciousVssR1::init(&SyncReliableBroadcast::default(),&params.roles_to_lie_to))]
    #[case(TestingParameters::init(7, 2, &[1,3], &[0,2,4,6], &[], true, None), MaliciousVssR1::init(&SyncReliableBroadcast::default(),&params.roles_to_lie_to))]
    #[cfg(feature = "slow_tests")]
    fn test_malicious_coinflip_malicious_vss<V: Vss + 'static>(
        #[case] params: TestingParameters,
        #[case] malicious_vss: V,
    ) {
        let malicious_coinflip_recons = MaliciousCoinflipRecons {
            vss: malicious_vss.clone(),
        };

        test_coinflip_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_coinflip_recons.clone(),
        );
        test_coinflip_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_coinflip_recons.clone(),
        );
    }
}
