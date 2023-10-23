use async_trait::async_trait;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;

use crate::{
    error::error_handler::anyhow_error_and_log, residue_poly::ResiduePoly, sharing::vss::Vss,
    value, Sample, Z128,
};

use super::{distributed::robust_open_to_all, session::LargeSessionHandles};

#[async_trait]
pub trait Coinflip {
    async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
        session: &mut L,
    ) -> anyhow::Result<ResiduePoly<Z128>>;
}

#[derive(Default)]
pub struct DummyCoinflip {}

#[async_trait]
impl Coinflip for DummyCoinflip {
    async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
        _session: &mut L,
    ) -> anyhow::Result<ResiduePoly<Z128>> {
        //Everyone just generate the same randomness by calling a new rng with a fixed seed
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        Ok(ResiduePoly::<Z128>::sample(&mut rng))
    }
}

#[derive(Default)]
pub struct RealCoinflip<V: Vss> {
    _marker: std::marker::PhantomData<V>,
}

#[async_trait]
impl<V: Vss> Coinflip for RealCoinflip<V> {
    async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
        session: &mut L,
    ) -> anyhow::Result<ResiduePoly<Z128>> {
        //NOTE: I don't care if I am in Corrupt
        let my_secret = ResiduePoly::<Z128>::sample(session.rng());

        let shares_of_contributions = V::execute::<R, L>(session, &my_secret).await?;

        let share_of_coin: ResiduePoly<Z128> = shares_of_contributions.into_iter().sum();

        let opening = robust_open_to_all(session, &value::Value::Poly128(share_of_coin)).await?;

        match opening {
            Some(value::Value::Poly128(v)) => Ok(v),
            _ => Err(anyhow_error_and_log(
                "Value reconstructed in coinflip not of the right type".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use tokio::task::JoinSet;

    use crate::{
        computation::SessionId,
        execution::{
            distributed::DistributedTestRuntime,
            party::{Identity, Role},
            session::BaseSessionHandles,
        },
        residue_poly::ResiduePoly,
        sharing::vss::RealVss,
        tests::helper::tests::{generate_identities, get_large_session_for_parties},
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
                Role::from_zero(party_nb),
            );
            set.spawn(async move {
                (
                    party_nb,
                    DummyCoinflip::execute(&mut session).await.unwrap(),
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

    #[test]
    fn test_coinflip() {
        let identities = generate_identities(5);

        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();

        let mut seeds = Vec::new();
        for (party_nb, _) in runtime.identities.iter().enumerate() {
            let mut session = runtime
                .large_session_for_player(session_id, party_nb)
                .unwrap();
            seeds.push(session.rng.get_seed());
            set.spawn(async move {
                (
                    party_nb,
                    RealCoinflip::<RealVss>::execute(&mut session)
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

        //Compute expected results
        let mut expected_res: ResiduePoly<Z128> = ResiduePoly::<Z128>::ZERO;
        for (party_nb, _) in runtime.identities.iter().enumerate() {
            let mut tmp_rng = ChaCha20Rng::from_seed(seeds[party_nb]);
            expected_res += ResiduePoly::<Z128>::sample(&mut tmp_rng);
        }

        //make sure result for p0 is correct and all parties have the same result
        let p0_result = results[0].1;
        assert_eq!(p0_result, expected_res);
        for (_, r) in results {
            assert_eq!(r, p0_result);
        }
    }

    //We test the behaviour for when P1 is in the corrupt set
    //We expecte everything to happen fine
    #[test]
    fn test_coinflip_one_corrupt() {
        let identities = generate_identities(5);

        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        let mut malicious_set = JoinSet::new();

        let mut seeds = Vec::new();
        for (party_nb, _) in runtime.identities.iter().enumerate() {
            let mut session = runtime
                .large_session_for_player(session_id, party_nb)
                .unwrap();
            seeds.push(session.rng.get_seed());
            if party_nb != 0 {
                session.add_corrupt(Role::from_zero(0));
                set.spawn(async move {
                    (
                        party_nb,
                        RealCoinflip::<RealVss>::execute(&mut session)
                            .await
                            .unwrap(),
                    )
                });
            } else {
                malicious_set.spawn(async move {
                    (
                        party_nb,
                        RealCoinflip::<RealVss>::execute(&mut session).await,
                    )
                });
            }
        }

        let results = rt.block_on(async {
            let mut results = Vec::new();
            while let Some(v) = set.join_next().await {
                let data = v.unwrap();
                results.push(data);
            }
            results
        });

        //Compute expected results
        let mut expected_res: ResiduePoly<Z128> = ResiduePoly::<Z128>::ZERO;
        for (party_nb, _) in runtime.identities.iter().enumerate() {
            if party_nb != 0 {
                let mut tmp_rng = ChaCha20Rng::from_seed(seeds[party_nb]);
                expected_res += ResiduePoly::<Z128>::sample(&mut tmp_rng);
            }
        }

        //make sure result for p1 is correct and all parties have the same result
        let p1_result = results[1].1;
        assert_eq!(p1_result, expected_res);
        for (_, r) in results {
            assert_eq!(r, p1_result);
        }
    }

    //We test the behaviour for when P1 doesnt communicate
    //We expect everything to happen fine
    #[test]
    fn test_coinflip_one_dropout() {
        let identities = generate_identities(5);

        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();

        let mut seeds = Vec::new();
        for (party_nb, _) in runtime.identities.iter().enumerate() {
            let mut session = runtime
                .large_session_for_player(session_id, party_nb)
                .unwrap();
            seeds.push(session.rng.get_seed());
            if party_nb != 0 {
                set.spawn(async move {
                    let res = (
                        party_nb,
                        RealCoinflip::<RealVss>::execute(&mut session)
                            .await
                            .unwrap(),
                    );
                    assert!(session.corrupt_roles().contains(&Role::from_zero(0)));
                    res
                });
            }
        }

        let results = rt.block_on(async {
            let mut results = Vec::new();
            while let Some(v) = set.join_next().await {
                let data = v.unwrap();
                results.push(data);
            }
            results
        });

        //Compute expected results
        let mut expected_res: ResiduePoly<Z128> = ResiduePoly::<Z128>::ZERO;
        for (party_nb, _) in runtime.identities.iter().enumerate() {
            if party_nb != 0 {
                let mut tmp_rng = ChaCha20Rng::from_seed(seeds[party_nb]);
                expected_res += ResiduePoly::<Z128>::sample(&mut tmp_rng);
            }
        }

        //make sure result for p1 is correct and all parties have the same result
        let p1_result = results[1].1;
        assert_eq!(p1_result, expected_res);
        for (_, r) in results {
            assert_eq!(r, p1_result);
        }
    }
}
