use async_trait::async_trait;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;

use crate::{
    error::error_handler::anyhow_error_and_log,
    residue_poly::ResiduePoly,
    sharing::vss::Vss,
    value::{self, Value},
    Sample, Z128,
};

use super::{distributed::robust_open_to_all, session::LargeSessionHandles};

#[async_trait]
pub trait Coinflip: Send + Sync + Clone + Default {
    async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
        &self,
        session: &mut L,
    ) -> anyhow::Result<ResiduePoly<Z128>>;
}

#[derive(Default, Clone)]
pub struct DummyCoinflip {}

#[async_trait]
impl Coinflip for DummyCoinflip {
    async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
        &self,
        _session: &mut L,
    ) -> anyhow::Result<ResiduePoly<Z128>> {
        //Everyone just generate the same randomness by calling a new rng with a fixed seed
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        Ok(ResiduePoly::<Z128>::sample(&mut rng))
    }
}

#[derive(Default, Clone)]
pub struct RealCoinflip<V: Vss> {
    vss: V,
}

#[async_trait]
impl<V: Vss> Coinflip for RealCoinflip<V> {
    async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
        &self,
        session: &mut L,
    ) -> anyhow::Result<ResiduePoly<Z128>> {
        //NOTE: I don't care if I am in Corrupt
        let my_secret = ResiduePoly::<Z128>::sample(session.rng());

        let shares_of_contributions = self.vss.execute::<R, L>(session, &my_secret).await?;

        let share_of_coin: ResiduePoly<Z128> = shares_of_contributions.into_iter().sum();

        let opening = robust_open_to_all(
            session,
            value::Value::Poly128(share_of_coin),
            session.threshold() as usize,
        )
        .await?;

        match opening {
            Some(Value::Poly128(v)) => Ok(v),
            _ => Err(anyhow_error_and_log(
                "No Value reconstructed in coinflip".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {

    use std::collections::HashSet;

    use anyhow::anyhow;
    use async_trait::async_trait;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rstest::rstest;
    use tokio::task::JoinSet;

    use crate::{
        execution::{
            distributed::{robust_open_to_all, DistributedTestRuntime},
            party::{Identity, Role},
            session::{BaseSessionHandles, LargeSession, LargeSessionHandles, ParameterHandles},
        },
        residue_poly::ResiduePoly,
        sharing::vss::{
            tests::{DroppingVssAfterR1, DroppingVssAfterR2, DroppingVssFromStart, MaliciousVssR1},
            RealVss, Vss,
        },
        tests::helper::tests::{
            execute_protocol_w_disputes_and_malicious, get_large_session_for_parties,
            roles_from_idxs,
        },
        value::{self, Value},
        Sample, Zero, Z128,
    };

    use super::{Coinflip, DummyCoinflip, RealCoinflip};

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
        let runtime = DistributedTestRuntime::new(identities.clone(), threshold);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        for (party_nb, _) in runtime.identities.iter().enumerate() {
            let mut session = get_large_session_for_parties(
                identities.len(),
                threshold,
                Role::indexed_by_zero(party_nb),
            );
            set.spawn(async move {
                let dummy_coinflip = DummyCoinflip::default();
                (
                    party_nb,
                    dummy_coinflip.execute(&mut session).await.unwrap(),
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

    //Performs the VSS and does nothing after that (returns its secret)
    #[derive(Default, Clone)]
    pub struct DroppingCoinflipAfterVss<V: Vss> {
        vss: V,
    }

    ///Performs the coinflip, but does not send the correct shares for reconstruction
    #[derive(Default, Clone)]
    pub struct MaliciousCoinflipRecons<V: Vss> {
        vss: V,
    }

    #[async_trait]
    impl<V: Vss> Coinflip for DroppingCoinflipAfterVss<V> {
        async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
            &self,
            session: &mut L,
        ) -> anyhow::Result<ResiduePoly<Z128>> {
            let my_secret = ResiduePoly::<Z128>::sample(session.rng());

            let _ = self.vss.execute::<R, L>(session, &my_secret).await?;

            Ok(my_secret)
        }
    }

    #[async_trait]
    impl<V: Vss> Coinflip for MaliciousCoinflipRecons<V> {
        async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
            &self,
            session: &mut L,
        ) -> anyhow::Result<ResiduePoly<Z128>> {
            let my_secret = ResiduePoly::<Z128>::sample(session.rng());

            let shares_of_contributions = self.vss.execute::<R, L>(session, &my_secret).await?;

            //Add an error to share_of_coins
            let mut share_of_coins: ResiduePoly<Z128> = shares_of_contributions.into_iter().sum();
            share_of_coins += ResiduePoly::<Z128>::sample(session.rng());

            let opening = robust_open_to_all(
                session,
                value::Value::Poly128(share_of_coins),
                session.threshold() as usize,
            )
            .await?;

            match opening {
                Some(Value::Poly128(v)) => Ok(v),
                _ => Err(anyhow!("Malicious error")),
            }
        }
    }

    //Helper function to plug malicious coinflip strategies
    fn test_coinflip_strategies<C: Coinflip + 'static>(
        num_parties: usize,
        threshold: usize,
        malicious_coinflip: C,
        malicious_roles: &[Role],
        should_be_detected: bool,
    ) {
        async fn task_honest(
            mut session: LargeSession,
        ) -> (usize, ResiduePoly<Z128>, HashSet<Role>) {
            let real_coinflip = RealCoinflip::<RealVss>::default();
            (
                session.my_role().unwrap().zero_based(),
                real_coinflip.execute(&mut session).await.unwrap(),
                session.corrupt_roles().clone(),
            )
        }

        async fn task_malicious<C: Coinflip>(
            mut session: LargeSession,
            malicious_coinflip: C,
        ) -> (usize, ResiduePoly<Z128>, HashSet<Role>) {
            (
                session.my_role().unwrap().zero_based(),
                malicious_coinflip.execute(&mut session).await.unwrap(),
                session.corrupt_roles().clone(),
            )
        }

        let (results_honest, _) = execute_protocol_w_disputes_and_malicious(
            num_parties,
            threshold as u8,
            &[],
            malicious_roles,
            malicious_coinflip,
            &mut task_honest,
            &mut task_malicious,
        );

        //Compute expected results
        let mut expected_res: ResiduePoly<Z128> = ResiduePoly::<Z128>::ZERO;
        for party_nb in 0..num_parties {
            if !(malicious_roles.contains(&Role::indexed_by_zero(party_nb)) && should_be_detected) {
                let mut tmp_rng = ChaCha20Rng::seed_from_u64(party_nb as u64);
                expected_res += ResiduePoly::<Z128>::sample(&mut tmp_rng);
            }
        }

        //make sure result for p1 is correct and all parties have the same result
        for (_, r, corrupt_roles) in results_honest {
            if should_be_detected {
                for role in malicious_roles {
                    assert!(corrupt_roles.contains(role));
                }
            }
            assert_eq!(r, expected_res);
        }
    }

    #[rstest]
    #[case(4, 1)]
    #[case(7, 2)]
    #[case(10, 3)]
    fn test_coinflip_honest(#[case] num_parties: usize, #[case] threshold: usize) {
        let malicious_coinflip = RealCoinflip::<RealVss>::default();
        let malicious_roles = &[];
        let should_be_detected = false;

        test_coinflip_strategies(
            num_parties,
            threshold,
            malicious_coinflip,
            malicious_roles,
            should_be_detected,
        );
    }

    //Test when coinflip aborts after the VSS for all kinds of VSS
    //No matter the strategy we expect all honest parties to output the same thing
    //We also specify whether we expect the cheating strategy to be detected, if so we check we do detect the cheaters
    #[rstest]
    #[case(4, 1, RealVss::default(), &roles_from_idxs(&[1]), false)]
    #[case(4, 1, DroppingVssAfterR1::default(), &roles_from_idxs(&[1]), true)]
    #[case(4, 1, DroppingVssAfterR2::default(), &roles_from_idxs(&[1]), false)]
    #[case(4, 1, MaliciousVssR1::init(&[2]), &roles_from_idxs(&[1]), false)]
    #[case(4, 1, MaliciousVssR1::init(&[0,2]), &roles_from_idxs(&[1]), true)]
    #[case(7, 2, MaliciousVssR1::init(&[0,2]), &roles_from_idxs(&[1,3]),false)]
    #[case(7, 2, MaliciousVssR1::init(&[0,2,4,6]), &roles_from_idxs(&[1,3]),true)]
    fn test_coinflip_dropout<V: Vss + 'static>(
        #[case] num_parties: usize,
        #[case] threshold: usize,
        #[case] malicious_vss: V,
        #[case] malicious_roles: &[Role],
        #[case] should_be_detected: bool,
    ) {
        let dropping_coinflip = DroppingCoinflipAfterVss {
            vss: malicious_vss.clone(),
        };
        test_coinflip_strategies(
            num_parties,
            threshold,
            dropping_coinflip,
            malicious_roles,
            should_be_detected,
        )
    }

    //Test honest coinflip with all kinds of malicious strategies for VSS
    //No matter the strategy, we expect all honest parties to end up with the same output
    //We also specify whether we expect the cheating strategy to be detected, if so we check we do detect the cheaters
    #[rstest]
    #[case(4, 1, DroppingVssFromStart::default(), &roles_from_idxs(&[1]), true)]
    #[case(4, 1, DroppingVssAfterR1::default(), &roles_from_idxs(&[1]), true)]
    #[case(4, 1, DroppingVssAfterR2::default(), &roles_from_idxs(&[1]), false)]
    #[case(4, 1, MaliciousVssR1::init(&[2]), &roles_from_idxs(&[1]), false)]
    #[case(4, 1, MaliciousVssR1::init(&[0,2]), &roles_from_idxs(&[1]), true)]
    #[case(7, 2, MaliciousVssR1::init(&[0,2]), &roles_from_idxs(&[1,3]),false)]
    #[case(7, 2, MaliciousVssR1::init(&[0,2,4,6]), &roles_from_idxs(&[1,3]),true)]
    fn test_coinflip_malicious_vss<V: Vss + 'static>(
        #[case] num_parties: usize,
        #[case] threshold: usize,
        #[case] malicious_vss: V,
        #[case] malicious_roles: &[Role],
        #[case] should_be_detected: bool,
    ) {
        let real_coinflip_with_malicious_vss = RealCoinflip {
            vss: malicious_vss.clone(),
        };

        test_coinflip_strategies(
            num_parties,
            threshold,
            real_coinflip_with_malicious_vss,
            malicious_roles,
            should_be_detected,
        );
    }

    //Test malicious coinflip with all kinds of strategies for VSS (honest and malicious)
    //Again, we always expect the honest parties to agree on the output
    #[rstest]
    #[case(4, 1, RealVss::default(), &roles_from_idxs(&[1]), false)]
    #[case(4, 1, DroppingVssFromStart::default(), &roles_from_idxs(&[1]), true)]
    #[case(4, 1, DroppingVssAfterR1::default(), &roles_from_idxs(&[1]), true)]
    #[case(4, 1, DroppingVssAfterR2::default(), &roles_from_idxs(&[1]), false)]
    #[case(4, 1, MaliciousVssR1::init(&[2]), &roles_from_idxs(&[1]), false)]
    #[case(4, 1, MaliciousVssR1::init(&[0,2]), &roles_from_idxs(&[1]), true)]
    #[case(7, 2, MaliciousVssR1::init(&[0,2]), &roles_from_idxs(&[1,3]),false)]
    #[case(7, 2, MaliciousVssR1::init(&[0,2,4,6]), &roles_from_idxs(&[1,3]),true)]
    fn test_malicious_coinflip_malicious_vss<V: Vss + 'static>(
        #[case] num_parties: usize,
        #[case] threshold: usize,
        #[case] malicious_vss: V,
        #[case] malicious_roles: &[Role],
        #[case] should_be_detected: bool,
    ) {
        let malicious_coinflip_recons = MaliciousCoinflipRecons {
            vss: malicious_vss.clone(),
        };

        test_coinflip_strategies(
            num_parties,
            threshold,
            malicious_coinflip_recons,
            malicious_roles,
            should_be_detected,
        );
    }
}
