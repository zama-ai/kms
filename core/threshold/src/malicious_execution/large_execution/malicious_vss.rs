use aes_prng::AesRng;
use itertools::Itertools;
use rand::{CryptoRng, Rng, SeedableRng};
use tonic::async_trait;

use crate::{
    algebra::{
        bivariate::{BivariateEval, BivariatePoly},
        poly::Poly,
        structure_traits::{Ring, RingEmbed},
    },
    execution::{
        communication::broadcast::Broadcast,
        large_execution::vss::{
            round_1, round_2, round_3, round_4, sample_secret_polys, DoublePoly, MapRoleDoublePoly,
            Round1VSSOutput, Vss,
        },
        runtime::{party::Role, session::BaseSessionHandles},
    },
    tests::helper::tests_and_benches::roles_from_idxs,
};

///Does nothing, and output an empty Vec
#[derive(Default, Clone)]
pub struct DroppingVssFromStart {}

#[async_trait]
impl Vss for DroppingVssFromStart {
    //Do nothing, and output an empty Vec
    async fn execute_many<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        _session: &mut S,
        _secrets: &[Z],
    ) -> anyhow::Result<Vec<Vec<Z>>> {
        Ok(Vec::new())
    }

    async fn execute<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        _session: &mut S,
        _secret: &Z,
    ) -> anyhow::Result<Vec<Z>> {
        Ok(Vec::new())
    }
}

///Does round 1 and then drops
#[derive(Default, Clone)]
pub struct DroppingVssAfterR1 {}

#[async_trait]
impl Vss for DroppingVssAfterR1 {
    //Do round1, and output an empty Vec
    async fn execute_many<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
        secrets: &[Z],
    ) -> anyhow::Result<Vec<Vec<Z>>> {
        let (bivariate_poly, map_double_shares) = sample_secret_polys(session, secrets)?;
        let _ = round_1(session, secrets.len(), bivariate_poly, map_double_shares).await?;
        Ok(Vec::new())
    }

    async fn execute<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
        secret: &Z,
    ) -> anyhow::Result<Vec<Z>> {
        let _ = self.execute_many(session, &[*secret]).await?;
        Ok(Vec::new())
    }
}

///Does round 1 and 2 and then drops
#[derive(Default, Clone)]
pub struct DroppingVssAfterR2<BCast: Broadcast> {
    broadcast: BCast,
}

impl<BCast: Broadcast> DroppingVssAfterR2<BCast> {
    pub fn new(broadcast_strategy: &BCast) -> Self {
        Self {
            broadcast: broadcast_strategy.clone(),
        }
    }
}

#[async_trait]
impl<BCast: Broadcast> Vss for DroppingVssAfterR2<BCast> {
    //Do round1 and round2, and output an empty Vec
    async fn execute_many<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
        secrets: &[Z],
    ) -> anyhow::Result<Vec<Vec<Z>>> {
        let (bivariate_poly, map_double_shares) = sample_secret_polys(session, secrets)?;
        let num_secrets = secrets.len();
        let vss = round_1(session, num_secrets, bivariate_poly, map_double_shares).await?;
        let _ = round_2(session, num_secrets, &vss, &self.broadcast).await?;
        Ok(Vec::new())
    }

    async fn execute<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
        secret: &Z,
    ) -> anyhow::Result<Vec<Z>> {
        let _ = self.execute_many(session, &[*secret]).await?;
        Ok(Vec::new())
    }
}

///Participate in the protocol, but lies to some parties in the first round
#[derive(Default, Clone)]
pub struct MaliciousVssR1<BCast: Broadcast> {
    broadcast: BCast,
    roles_to_lie_to: Vec<Role>,
}

impl<BCast: Broadcast> MaliciousVssR1<BCast> {
    pub fn new(broadcast_strategy: &BCast, roles_from_zero: &[usize]) -> Self {
        Self {
            broadcast: broadcast_strategy.clone(),
            roles_to_lie_to: roles_from_idxs(roles_from_zero),
        }
    }
}

#[async_trait]
impl<BCast: Broadcast> Vss for MaliciousVssR1<BCast> {
    async fn execute_many<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
        secrets: &[Z],
    ) -> anyhow::Result<Vec<Vec<Z>>> {
        //Execute a malicious round 1
        let num_secrets = secrets.len();
        let vss = malicious_round_1(session, secrets, &self.roles_to_lie_to).await?;
        let verification_map = round_2(session, num_secrets, &vss, &self.broadcast).await?;
        let unhappy_vec = round_3(
            session,
            num_secrets,
            &vss,
            &verification_map,
            &self.broadcast,
        )
        .await?;
        Ok(round_4(session, num_secrets, &vss, unhappy_vec, &self.broadcast).await?)
    }
}

//This code executes a round1 where the party sends malformed double shares for its VSS to parties in roles_to_lie_to
async fn malicious_round_1<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
    session: &mut S,
    secrets: &[Z],
    roles_to_lie_to: &[Role],
) -> anyhow::Result<Round1VSSOutput<Z>> {
    let num_secrets = secrets.len();
    let mut rng = AesRng::seed_from_u64(0);
    let bivariate_poly = secrets
        .iter()
        .map(|secret| {
            BivariatePoly::from_secret(&mut rng, *secret, session.threshold() as usize).unwrap()
        })
        .collect_vec();
    let map_double_shares: MapRoleDoublePoly<Z> = session
        .role_assignments()
        .keys()
        .map(|r| {
            let embedded_role = Z::embed_exceptional_set(r.one_based()).unwrap();
            let correct_bpolys = (0..num_secrets)
                .map(|i| DoublePoly {
                    share_in_x: bivariate_poly[i]
                        .partial_y_evaluation(embedded_role)
                        .unwrap(),
                    share_in_y: bivariate_poly[i]
                        .partial_x_evaluation(embedded_role)
                        .unwrap(),
                })
                .collect_vec();
            if roles_to_lie_to.contains(r) {
                // we only lie for one of the polynomials, the first one
                let mut wrong_bpolys = correct_bpolys.clone();
                wrong_bpolys[0] = DoublePoly {
                    share_in_x: Poly::<Z>::sample_random_with_fixed_constant(
                        &mut rng,
                        Z::ONE,
                        session.threshold().into(),
                    ),
                    share_in_y: Poly::<Z>::sample_random_with_fixed_constant(
                        &mut rng,
                        Z::ZERO,
                        session.threshold().into(),
                    ),
                };
                (*r, wrong_bpolys)
            } else {
                (*r, correct_bpolys)
            }
        })
        .collect();
    round_1(session, num_secrets, bivariate_poly, map_double_shares).await
}

#[derive(Default, Clone)]
pub struct WrongSecretLenVss<BCast: Broadcast> {
    broadcast: BCast,
}

impl<BCast: Broadcast> WrongSecretLenVss<BCast> {
    pub fn new(broadcast_strategy: &BCast) -> Self {
        Self {
            broadcast: broadcast_strategy.clone(),
        }
    }
}

#[async_trait]
impl<BCast: Broadcast> Vss for WrongSecretLenVss<BCast> {
    // The adversary will halve the number of secrets
    async fn execute_many<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
        secrets: &[Z],
    ) -> anyhow::Result<Vec<Vec<Z>>> {
        assert!(secrets.len() > 1);
        let num_secrets = secrets.len() / 2;
        let (bivariate_poly, map_double_shares) =
            sample_secret_polys(session, &secrets[..num_secrets])?;
        let vss = round_1(session, num_secrets, bivariate_poly, map_double_shares).await?;
        let verification_map = round_2(session, num_secrets, &vss, &self.broadcast).await?;
        let unhappy_vec = round_3(
            session,
            num_secrets,
            &vss,
            &verification_map,
            &self.broadcast,
        )
        .await?;
        Ok(round_4(session, num_secrets, &vss, unhappy_vec, &self.broadcast).await?)
    }
}

#[derive(Default, Clone)]
/// Participae in the protocol honestly except it sends
/// a polynomial of degree t+1 in the first round
pub struct WrongDegreeSharingVss<BCast: Broadcast> {
    broadcast: BCast,
}

impl<BCast: Broadcast> WrongDegreeSharingVss<BCast> {
    pub fn new(broadcast_strategy: &BCast) -> Self {
        Self {
            broadcast: broadcast_strategy.clone(),
        }
    }
}

impl<BCast: Broadcast> WrongDegreeSharingVss<BCast> {
    fn sample_secret_polys<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        session: &mut S,
        secrets: &[Z],
    ) -> anyhow::Result<(Vec<BivariatePoly<Z>>, MapRoleDoublePoly<Z>)> {
        // We intentionally sent the degree to be too high (off by one) compared
        // to an honest behaviour.
        let degree = session.threshold() as usize + 1;
        //Sample the bivariate polynomials Vec<F(X,Y)>
        let bivariate_poly = secrets
            .iter()
            .map(|s| BivariatePoly::from_secret(session.rng(), *s, degree))
            .collect::<Result<Vec<_>, _>>()?;
        //Evaluate the bivariate poly in its first and second variables
        //to create a mapping role -> Vec<(F(X,alpha_role), F(alpha_role,Y))>
        let map_double_shares: MapRoleDoublePoly<Z> = session
            .role_assignments()
            .keys()
            .map(|r| {
                let embedded_role = Z::embed_exceptional_set(r.one_based())?;
                let mut vec_map = Vec::with_capacity(bivariate_poly.len());
                for p in &bivariate_poly {
                    let share_in_x = p.partial_y_evaluation(embedded_role)?;
                    let share_in_y = p.partial_x_evaluation(embedded_role)?;
                    vec_map.push(DoublePoly {
                        share_in_x,
                        share_in_y,
                    });
                }
                Ok::<(Role, Vec<DoublePoly<Z>>), anyhow::Error>((*r, vec_map))
            })
            .try_collect()?;
        Ok((bivariate_poly, map_double_shares))
    }
}

#[async_trait]
impl<BCast: Broadcast> Vss for WrongDegreeSharingVss<BCast> {
    async fn execute_many<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
        secrets: &[Z],
    ) -> anyhow::Result<Vec<Vec<Z>>> {
        let num_secrets = secrets.len();
        let (bivariate_poly, map_double_shares) = Self::sample_secret_polys(session, secrets)?;
        let vss = round_1(session, num_secrets, bivariate_poly, map_double_shares).await?;
        let verification_map = round_2(session, num_secrets, &vss, &self.broadcast).await?;
        let unhappy_vec = round_3(
            session,
            num_secrets,
            &vss,
            &verification_map,
            &self.broadcast,
        )
        .await?;
        Ok(round_4(session, num_secrets, &vss, unhappy_vec, &self.broadcast).await?)
    }
}
