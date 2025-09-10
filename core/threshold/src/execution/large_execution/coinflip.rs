use aes_prng::AesRng;
use async_trait::async_trait;
use rand::SeedableRng;
use tracing::instrument;

use super::vss::{SecureVss, Vss};
use crate::algebra::structure_traits::{ErrorCorrect, Ring};
use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::{
        runtime::session::LargeSessionHandles,
        sharing::open::{RobustOpen, SecureRobustOpen},
    },
    ProtocolDescription,
};

/// Secure implementation of Coinflip as defined in NIST document
///
/// In particular, relies on the secure version of
/// the VSS protocol defined in [`SecureVss`]
pub type SecureCoinflip = RealCoinflip<SecureVss, SecureRobustOpen>;

#[async_trait]
pub trait Coinflip: ProtocolDescription + Send + Sync + Clone {
    async fn execute<Z: ErrorCorrect, L: LargeSessionHandles>(
        &self,
        session: &mut L,
    ) -> anyhow::Result<Z>;
}

#[derive(Default, Clone)]
pub struct DummyCoinflip {}

impl ProtocolDescription for DummyCoinflip {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!("{indent}-DummyCoinflip")
    }
}

#[async_trait]
impl Coinflip for DummyCoinflip {
    async fn execute<Z: Ring, L: LargeSessionHandles>(
        &self,
        _session: &mut L,
    ) -> anyhow::Result<Z> {
        //Everyone just generate the same randomness by calling a new rng with a fixed seed
        let mut rng = AesRng::seed_from_u64(0);
        Ok(Z::sample(&mut rng))
    }
}

#[derive(Default, Clone)]
pub struct RealCoinflip<V: Vss, RO: RobustOpen> {
    vss: V,
    robust_open: RO,
}

impl<V: Vss, RO: RobustOpen> ProtocolDescription for RealCoinflip<V, RO> {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!(
            "{}-RealCoinflip:\n{}\n{}",
            indent,
            V::protocol_desc(depth + 1),
            RO::protocol_desc(depth + 1)
        )
    }
}

impl<V: Vss, RO: RobustOpen> RealCoinflip<V, RO> {
    pub fn new(vss: V, robust_open: RO) -> Self {
        Self { vss, robust_open }
    }
}

#[async_trait]
impl<V: Vss, RO: RobustOpen> Coinflip for RealCoinflip<V, RO> {
    #[instrument(name="CoinFlip",skip(self,session),fields(sid = ?session.session_id(), my_role=?session.my_role()))]
    async fn execute<Z, L: LargeSessionHandles>(&self, session: &mut L) -> anyhow::Result<Z>
    where
        Z: ErrorCorrect,
    {
        //NOTE: I don't care if I am in Corrupt
        let my_secret = Z::sample(session.rng());

        let shares_of_contributions = self.vss.execute(session, &my_secret).await?;

        //Note that we don't care about summing only non-corrupt contributions as
        //output of VSS from corrupted parties is the trivial 0 sharing
        let share_of_coin = shares_of_contributions.into_iter().sum::<Z>();

        let opening = self
            .robust_open
            .robust_open_to_all(session, share_of_coin, session.threshold() as usize)
            .await?;

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
    use super::{Coinflip, DummyCoinflip, SecureCoinflip};
    #[cfg(feature = "slow_tests")]
    use crate::execution::communication::broadcast::SyncReliableBroadcast;
    #[cfg(feature = "slow_tests")]
    use crate::execution::large_execution::{coinflip::RealCoinflip, vss::SecureVss, vss::Vss};
    #[cfg(feature = "slow_tests")]
    use crate::execution::sharing::open::{RobustOpen, SecureRobustOpen};
    #[cfg(feature = "slow_tests")]
    use crate::malicious_execution::large_execution::malicious_vss::{
        DroppingVssAfterR1, DroppingVssAfterR2, DroppingVssFromStart, MaliciousVssR1,
    };

    use crate::{
        algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
        execution::runtime::{
            party::Role,
            session::{BaseSessionHandles, LargeSession},
            test_runtime::generate_fixed_roles,
        },
        tests::helper::tests::{
            execute_protocol_large_w_disputes_and_malicious,
            get_networkless_large_session_for_parties, TestingParameters,
        },
    };
    use crate::{
        algebra::structure_traits::{ErrorCorrect, Ring},
        networking::NetworkMode,
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use rstest::rstest;
    use tokio::task::JoinSet;

    #[test]
    fn test_dummy_coinflip() {
        let roles = generate_fixed_roles(5);
        let threshold = 1;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        let party_amount = roles.len();
        for party in roles {
            let mut session =
                get_networkless_large_session_for_parties(party_amount, threshold, party);
            set.spawn(async move {
                let dummy_coinflip = DummyCoinflip::default();
                (
                    party,
                    dummy_coinflip
                        .execute::<ResiduePolyF4Z128, _>(&mut session)
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

    //Helper function to plug malicious coinflip strategies
    async fn test_coinflip_strategies<
        Z: ErrorCorrect,
        const EXTENSION_DEGREE: usize,
        C: Coinflip + 'static,
    >(
        params: TestingParameters,
        malicious_coinflip: C,
    ) {
        let mut task_honest = |mut session: LargeSession| async move {
            let real_coinflip = SecureCoinflip::default();
            (
                real_coinflip.execute::<Z, _>(&mut session).await.unwrap(),
                session.corrupt_roles().clone(),
            )
        };

        let mut task_malicious = |mut session: LargeSession, malicious_coinflip: C| async move {
            let res = malicious_coinflip.execute::<Z, _>(&mut session).await;
            let cur_roles = session.corrupt_roles().clone();
            res.map(|inner| (inner, cur_roles))
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
            )
            .await;

        //make sure the  malicious set of all honest parties is in sync
        let ref_malicious_set = results_honest[&Role::indexed_from_one(1)].1.clone();
        for (_, malicious_set) in results_honest.values() {
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
        for party_nb in 1..=params.num_parties {
            if !(params
                .malicious_roles
                .contains(&Role::indexed_from_one(party_nb))
                && params.should_be_detected)
            {
                let mut tmp_rng = AesRng::seed_from_u64(party_nb as u64);
                expected_res += Z::sample(&mut tmp_rng);
            }
        }

        //make sure result for p1 is correct and all parties have the same result
        for (r, corrupt_roles) in results_honest.values() {
            if params.should_be_detected {
                for role in params.malicious_roles.iter() {
                    assert!(corrupt_roles.contains(role));
                }
            }
            assert_eq!(*r, expected_res);
        }
    }

    // Rounds: We expect 3+1+t+1 rounds on the happy path
    #[rstest]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[case(TestingParameters::init_honest(4, 1, Some(6)))]
    #[case(TestingParameters::init_honest(7, 2, Some(7)))]
    #[case(TestingParameters::init_honest(10, 3, Some(8)))]
    async fn test_coinflip_honest_z128(#[case] params: TestingParameters) {
        let malicious_coinflip = SecureCoinflip::default();
        test_coinflip_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_coinflip.clone(),
        )
        .await;
        test_coinflip_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_coinflip.clone(),
        )
        .await;
    }

    //Test when coinflip aborts after the VSS for all kinds of VSS
    //No matter the strategy we expect all honest parties to output the same thing
    //We also specify whether we expect the cheating strategy to be detected, if so we check we do detect the cheaters
    #[rstest]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], false, None), SecureVss::default())]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], true, None), DroppingVssAfterR1::default())]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], false, None), DroppingVssAfterR2::new(&SyncReliableBroadcast::default()))]
    #[case(TestingParameters::init(4, 1, &[1], &[2], &[], false, None), MaliciousVssR1::new(&SyncReliableBroadcast::default(),&params.roles_to_lie_to))]
    #[case(TestingParameters::init(4, 1, &[1], &[0,2], &[], true, None), MaliciousVssR1::new(&SyncReliableBroadcast::default(),&params.roles_to_lie_to))]
    #[case(TestingParameters::init(7, 2, &[1,3], &[0,2], &[], false, None), MaliciousVssR1::new(&SyncReliableBroadcast::default(),&params.roles_to_lie_to))]
    #[case(TestingParameters::init(7, 2, &[1,3], &[0,2,4,6], &[], true, None), MaliciousVssR1::new(&SyncReliableBroadcast::default(),&params.roles_to_lie_to))]
    #[cfg(feature = "slow_tests")]
    async fn test_coinflip_dropout<V: Vss + 'static>(
        #[case] params: TestingParameters,
        #[case] malicious_vss: V,
    ) {
        use crate::malicious_execution::large_execution::malicious_coinflip::DroppingCoinflipAfterVss;

        let dropping_coinflip = DroppingCoinflipAfterVss::new(malicious_vss.clone());
        test_coinflip_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            dropping_coinflip.clone(),
        )
        .await;
        test_coinflip_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            dropping_coinflip.clone(),
        )
        .await;
    }

    //Test honest coinflip with all kinds of malicious strategies for VSS
    //No matter the strategy, we expect all honest parties to end up with the same output
    //We also specify whether we expect the cheating strategy to be detected, if so we check we do detect the cheaters
    #[rstest]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], true, None), DroppingVssFromStart::default(),SecureRobustOpen::default())]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], true, None), DroppingVssAfterR1::default(),SecureRobustOpen::default())]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], false, None), DroppingVssAfterR2::new(&SyncReliableBroadcast::default()),SecureRobustOpen::default())]
    #[case(TestingParameters::init(4, 1, &[1], &[2], &[], false, None), MaliciousVssR1::new(&SyncReliableBroadcast::default(),&params.roles_to_lie_to),SecureRobustOpen::default())]
    #[case(TestingParameters::init(4, 1, &[1], &[0,2], &[], true, None), MaliciousVssR1::new(&SyncReliableBroadcast::default(),&params.roles_to_lie_to),SecureRobustOpen::default())]
    #[case(TestingParameters::init(7, 2, &[1,3], &[0,2], &[], false, None), MaliciousVssR1::new(&SyncReliableBroadcast::default(),&params.roles_to_lie_to),SecureRobustOpen::default())]
    #[case(TestingParameters::init(7, 2, &[1,3], &[0,2,4,6], &[], true, None), MaliciousVssR1::new(&SyncReliableBroadcast::default(),&params.roles_to_lie_to),SecureRobustOpen::default())]
    #[cfg(feature = "slow_tests")]
    async fn test_coinflip_malicious_vss<V: Vss + 'static, RO: RobustOpen + 'static>(
        #[case] params: TestingParameters,
        #[case] malicious_vss: V,
        #[case] malicious_robust_open: RO,
    ) {
        let real_coinflip_with_malicious_sub_protocols = RealCoinflip {
            vss: malicious_vss.clone(),
            robust_open: malicious_robust_open.clone(),
        };

        test_coinflip_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            real_coinflip_with_malicious_sub_protocols.clone(),
        )
        .await;
        test_coinflip_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            real_coinflip_with_malicious_sub_protocols.clone(),
        )
        .await;
    }

    //Test malicious coinflip with all kinds of strategies for VSS (honest and malicious)
    //Again, we always expect the honest parties to agree on the output
    #[rstest]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], false, None), SecureVss::default(),SecureRobustOpen::default())]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], true, None), DroppingVssAfterR1::default(),SecureRobustOpen::default())]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], false, None), DroppingVssAfterR2::new(&SyncReliableBroadcast::default()),SecureRobustOpen::default())]
    #[case(TestingParameters::init(4, 1, &[1], &[2], &[], false, None), MaliciousVssR1::new(&SyncReliableBroadcast::default(),&params.roles_to_lie_to),SecureRobustOpen::default())]
    #[case(TestingParameters::init(4, 1, &[1], &[0,2], &[], true, None), MaliciousVssR1::new(&SyncReliableBroadcast::default(),&params.roles_to_lie_to),SecureRobustOpen::default())]
    #[case(TestingParameters::init(7, 2, &[1,3], &[0,2], &[], false, None), MaliciousVssR1::new(&SyncReliableBroadcast::default(),&params.roles_to_lie_to),SecureRobustOpen::default())]
    #[case(TestingParameters::init(7, 2, &[1,3], &[0,2,4,6], &[], true, None), MaliciousVssR1::new(&SyncReliableBroadcast::default(),&params.roles_to_lie_to),SecureRobustOpen::default())]
    #[cfg(feature = "slow_tests")]
    async fn test_malicious_coinflip_malicious_vss<V: Vss + 'static, RO: RobustOpen + 'static>(
        #[case] params: TestingParameters,
        #[case] malicious_vss: V,
        #[case] malicious_robust_open: RO,
    ) {
        use crate::malicious_execution::large_execution::malicious_coinflip::MaliciousCoinflipRecons;
        let malicious_coinflip_recons =
            MaliciousCoinflipRecons::new(malicious_vss.clone(), malicious_robust_open.clone());

        test_coinflip_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_coinflip_recons.clone(),
        )
        .await;
        test_coinflip_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            malicious_coinflip_recons.clone(),
        )
        .await;
    }
}
