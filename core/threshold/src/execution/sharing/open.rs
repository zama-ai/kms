use itertools::Itertools;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::collections::HashMap;
use tokio::{task::JoinSet, time::error::Elapsed};
use tonic::async_trait;
use tracing::instrument;

use crate::{
    algebra::structure_traits::ErrorCorrect,
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::p2p::{generic_receive_from_all, send_to_all},
        online::preprocessing::constants::BATCH_SIZE_BITS,
        runtime::{party::Role, session::BaseSessionHandles},
    },
    networking::value::NetworkValue,
    ProtocolDescription,
};

use super::{
    shamir::{
        fill_indexed_shares, reconstruct_w_errors_async, reconstruct_w_errors_sync, ShamirSharings,
    },
    share::Share,
};

/// Enum to state whether we want to open
/// only to some designated parties or
/// to all parties at once.
pub enum OpeningKind<Z> {
    ToSome(HashMap<Role, Vec<Z>>),
    ToAll(Vec<Z>),
}

#[async_trait]
pub trait RobustOpen: ProtocolDescription + Send + Sync + Clone {
    /// Inputs:
    /// - session
    /// - shares (wrapped inside [`OpeningKind`] to know who to open to) of the secrets to open
    /// - degree of the sharing
    ///
    /// Output:
    /// - The reconstructed secrets if reconstruction for all was possible
    async fn execute<Z: ErrorCorrect, B: BaseSessionHandles>(
        &self,
        session: &B,
        shares: OpeningKind<Z>,
        degree: usize,
    ) -> anyhow::Result<Option<Vec<Z>>>;

    /// Blanket implementation that relies on [`Self::execute`]
    ///
    /// Opens a batch of secrets to designated parties
    #[instrument(name="RobustOpenTo",skip(self,session,shares),fields(sid= ?session.session_id(), own_identity = ?session.own_identity(),num_receivers = ?shares.len()))]
    async fn multi_robust_open_list_to<Z: ErrorCorrect, B: BaseSessionHandles>(
        &self,
        session: &B,
        shares: HashMap<Role, Vec<Z>>,
        degree: usize,
    ) -> anyhow::Result<Option<Vec<Z>>> {
        self.execute(session, OpeningKind::ToSome(shares), degree)
            .await
    }

    /// Blanket implementation that relies on [`Self::execute`]
    ///
    /// Opens a batch of secrets to a designated party
    async fn robust_open_list_to<Z: ErrorCorrect, B: BaseSessionHandles>(
        &self,
        session: &B,
        shares: Vec<Z>,
        degree: usize,
        output_party: &Role,
    ) -> anyhow::Result<Option<Vec<Z>>> {
        let shares = HashMap::from([(*output_party, shares)]);
        self.multi_robust_open_list_to(session, shares, degree)
            .await
    }

    /// Blanket implementation that relies on [`Self::execute`]
    ///
    /// Opens a single secret to a designated party
    async fn robust_open_to<Z: ErrorCorrect, B: BaseSessionHandles>(
        &self,
        session: &B,
        share: Z,
        degree: usize,
        output_party: &Role,
    ) -> anyhow::Result<Option<Z>> {
        let res = self
            .robust_open_list_to(session, vec![share], degree, output_party)
            .await?;
        match res {
            Some(mut r) => Ok(r.pop()),
            _ => Ok(None),
        }
    }

    /// Blanket implementation that relies on [`Self::execute`]
    ///
    /// Try to reconstruct to all the secret which corresponds to the provided share.
    /// Considering I as a player already hold my own share of the secret
    ///
    /// Inputs:
    /// - session
    /// - shares of the secrets to open
    /// - degree of the sharing
    ///
    /// Output:
    /// - The reconstructed secrets if reconstruction for all was possible
    #[instrument(name="RobustOpen",skip(self,session,shares),fields(sid= ?session.session_id(), own_identity = ?session.own_identity(),batch_size = ?shares.len()))]
    async fn robust_open_list_to_all<Z: ErrorCorrect, B: BaseSessionHandles>(
        &self,
        session: &B,
        shares: Vec<Z>,
        degree: usize,
    ) -> anyhow::Result<Option<Vec<Z>>> {
        //Might need to chunk the opening into multiple ones due to network limits
        let chunk_size: usize = super::constants::MAX_MESSAGE_BYTE_SIZE / (Z::BIT_LENGTH >> 3);
        let chunks: Vec<Vec<_>> = shares
            .into_iter()
            .chunks(chunk_size)
            .into_iter()
            .map(|chunk| chunk.collect())
            .collect_vec();
        let mut result = Vec::new();
        for chunked_shares in chunks {
            match self
                .execute(session, OpeningKind::ToAll(chunked_shares), degree)
                .await?
            {
                Some(res) => result.extend(res),
                None => return Ok(None),
            }
        }
        Ok(Some(result))
    }

    /// Blanket implementation that relies on [`Self::execute`]
    ///
    /// Opens a single secret to all the parties
    async fn robust_open_to_all<Z: ErrorCorrect, B: BaseSessionHandles>(
        &self,
        session: &B,
        share: Z,
        degree: usize,
    ) -> anyhow::Result<Option<Z>> {
        let res = self
            .robust_open_list_to_all(session, vec![share], degree)
            .await?;
        match res {
            Some(mut r) => Ok(r.pop()),
            _ => Ok(None),
        }
    }
}

#[derive(Default, Clone)]
pub struct SecureRobustOpen {}

impl ProtocolDescription for SecureRobustOpen {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!("{}-SecureRobustOpen", indent)
    }
}

#[async_trait]
impl RobustOpen for SecureRobustOpen {
    async fn execute<Z: ErrorCorrect, B: BaseSessionHandles>(
        &self,
        session: &B,
        shares: OpeningKind<Z>,
        degree: usize,
    ) -> anyhow::Result<Option<Vec<Z>>> {
        //Might need to chunk the opening into multiple ones due to network limits
        let own_role = session.my_role();

        let shares_for_reconstruction = match shares {
            OpeningKind::ToSome(shares_map) => {
                // We need to explicitly increase the round counter here
                // because network().send() does not do it
                session.network().increase_round_counter()?;
                let mut shares_for_reconstruction = None;
                for (receiver_role, values) in shares_map.into_iter() {
                    if receiver_role == own_role {
                        shares_for_reconstruction = Some(values);
                    } else {
                        let receiver = session.identity_from(&receiver_role)?;

                        session
                            .network()
                            .send(NetworkValue::VecRingValue(values).to_network(), &receiver)
                            .await?;
                    }
                }
                shares_for_reconstruction
            }
            OpeningKind::ToAll(shares) => {
                // We do not need to explicitly increase the round counter here
                // because send_to_all does it
                let shares = NetworkValue::VecRingValue(shares);
                send_to_all(session, &own_role, &shares).await?;

                // Small hack to avoid cloning ,
                // we just wrap and unwrap the shares into a NetworkValue
                // for sending over the network
                match shares {
                    NetworkValue::VecRingValue(shares) => Some(shares),
                    _ => None,
                }
            }
        };

        let result = if let Some(shares) = shares_for_reconstruction {
            let mut jobs = JoinSet::<Result<(Role, anyhow::Result<Vec<Z>>), Elapsed>>::new();
            //Note: we give the set of corrupt parties as the non_answering_parties argument
            //Thus generic_receive_from_all will not receive from corrupt parties.
            generic_receive_from_all(
                &mut jobs,
                session,
                &own_role,
                Some(session.corrupt_roles()),
                |msg, _id| match msg {
                    NetworkValue::VecRingValue(v) => Ok(v),
                    _ => Err(anyhow_error_and_log(
                        "Received something else than a Ring value in robust open to all"
                            .to_string(),
                    )),
                },
            )?;

            //Start filling sharings with my own shares
            let mut sharings = shares
                .into_iter()
                .map(|share| ShamirSharings::create(vec![Share::new(own_role, share)]))
                .collect_vec();

            let reconstruct_fn = match session.network().get_network_mode() {
                crate::networking::NetworkMode::Sync => reconstruct_w_errors_sync,
                crate::networking::NetworkMode::Async => reconstruct_w_errors_async,
            };

            try_reconstruct_from_shares(session, &mut sharings, degree, jobs, reconstruct_fn)
                .await?
        } else {
            None
        };
        Ok(result)
    }
}

type JobResultType<Z> = (Role, anyhow::Result<Vec<Z>>);
type ReconsFunc<Z> = fn(
    num_parties: usize,
    degree: usize,
    threshold: usize,
    num_bots: usize,
    sharing: &ShamirSharings<Z>,
) -> anyhow::Result<Option<Z>>;
/// Helper function of robust reconstructions which collect the shares and tries to reconstruct
///
/// Takes as input:
///
/// - the session_parameters
/// - indexed_share as the indexed share of the local party
/// - degree as the degree of the secret sharing
/// - max_num_errors as the max. number of errors we allow (this is session.threshold)
/// - a set of jobs to receive the shares from the other parties
async fn try_reconstruct_from_shares<Z: ErrorCorrect, B: BaseSessionHandles>(
    session: &B,
    sharings: &mut [ShamirSharings<Z>],
    degree: usize,
    mut jobs: JoinSet<Result<JobResultType<Z>, Elapsed>>,
    reconstruct_fn: ReconsFunc<Z>,
) -> anyhow::Result<Option<Vec<Z>>> {
    let num_parties = session.num_parties();
    let threshold = session.threshold();
    let mut num_bots = session.corrupt_roles().len();
    let num_secrets = sharings.len();

    //Start awaiting on receive jobs to retrieve the shares
    while let Some(v) = jobs.join_next().await {
        let joined_result = v?;
        match joined_result {
            Ok((party_id, data)) => {
                if let Ok(values) = data {
                    fill_indexed_shares(sharings, values, num_secrets, party_id)?;
                } else if let Err(e) = data {
                    tracing::warn!(
                        "(Share reconstruction) Received malformed data from {party_id}:  {:?}",
                        e
                    );
                    num_bots += 1;
                }
            }
            Err(e) => {
                // TODO can we see the party_id that correspond to the job?
                tracing::warn!("(Share reconstruction) Some party has timed out:  {:?}", e);
                num_bots += 1;
            }
        }
        //Note: here we keep waiting on new shares until we have all of the values opened.
        let res: Option<Vec<_>> = sharings
            .par_iter()
            // Here we want to use par_iter for opening the huge batches
            // present in DKG, but we want to avoid using it for
            // DKG preproc where we have lots of sessions in parallel
            // dealing with small batches.
            // Because for the case with lots of sessions and small batches,
            // we don't want say P1 to highly parallelize session 1 first
            // and P2 highly parallelize session 2 first.
            // For DKG preproc, the prallelization happens through spawning lots of sessions,
            // which are more likely to distribute workload similarly across the parties
            // as network call acts as a sync points across parties
            .with_min_len(2 * BATCH_SIZE_BITS)
            .map(|sharing| {
                reconstruct_fn(num_parties, degree, threshold as usize, num_bots, sharing)
                    .unwrap_or_default()
            })
            .collect();

        //Only prematurely shutdown the jobs if we have managed to reconstruct everything
        if res.is_some() {
            jobs.shutdown().await;
            return Ok(res);
        }
    }

    //If we've reached this point without being able to reconstruct, we fail
    Err(anyhow_error_and_log(
        "Could not reconstruct the sharing".to_string(),
    ))
}

#[cfg(test)]
pub(crate) mod test {

    use aes_prng::AesRng;
    use itertools::Itertools;
    use rand::SeedableRng;

    use crate::algebra::structure_traits::{ErrorCorrect, Invert, Ring, RingEmbed};
    use crate::execution::runtime::party::Role;
    use crate::execution::runtime::session::SmallSession;
    use crate::execution::sharing::shamir::InputOp;
    use crate::execution::small_execution::prf::PRSSConversions;
    use crate::malicious_execution::open::malicious_open::{
        MaliciousRobustOpenDrop, MaliciousRobustOpenLie,
    };
    use crate::networking::NetworkMode;
    use crate::tests::helper::tests::{execute_protocol_small_w_malicious, TestingParameters};
    use crate::{
        algebra::galois_rings::degree_4::ResiduePolyF4Z128,
        execution::{runtime::session::ParameterHandles, sharing::shamir::ShamirSharings},
    };

    use super::{RobustOpen, SecureRobustOpen};

    /// Samples a list of secrets using the provided seed
    /// and computes the shares the correspond to `my_role`.
    /// If all parties call this function with the same seed,
    /// they end up with a well-formed sharing of the same secrets
    ///
    /// Returns both the secrets and the shares
    pub(crate) fn deterministically_compute_my_shares<Z: Ring + RingEmbed>(
        num_secrets: usize,
        my_role: Role,
        num_parties: usize,
        threshold: usize,
        seed: u64,
    ) -> (Vec<Z>, Vec<Z>) {
        let mut rng = AesRng::seed_from_u64(seed);
        let secrets: Vec<_> = (0..num_secrets).map(|_| Z::sample(&mut rng)).collect();
        let shares = secrets
            .iter()
            .map(|secret| {
                let shamir_shares =
                    ShamirSharings::share(&mut rng, *secret, num_parties, threshold)
                        .unwrap()
                        .shares;
                my_role.get_from(&shamir_shares).unwrap().value()
            })
            .collect_vec();
        (secrets, shares)
    }

    /// Generic function to test the different strategies for robust open.
    /// We use [`TestingParameters::should_be_detected`] field to
    /// tell the test whether we expect the malicious parties
    /// to output the correct result.
    /// (RobustOpen does not mutate the corruption set)
    fn test_robust_open_strategies<
        Z: ErrorCorrect + Invert + PRSSConversions,
        const EXTENSION_DEGREE: usize,
        RO: RobustOpen + 'static,
    >(
        params: TestingParameters,
        malicious_robust_open: RO,
        num_secrets: usize,
        network_mode: NetworkMode,
    ) {
        let mut task_honest = |session: SmallSession<Z>| async move {
            let secure_robust_open = SecureRobustOpen::default();
            let (secrets, shares) = deterministically_compute_my_shares::<Z>(
                num_secrets,
                session.my_role(),
                session.num_parties(),
                session.threshold() as usize,
                42,
            );
            let result = secure_robust_open
                .robust_open_list_to_all(&session, shares, session.threshold() as usize)
                .await
                .unwrap();
            (session.my_role(), secrets, result)
        };

        let mut task_malicious = |session: SmallSession<Z>, malicious_robust_open: RO| async move {
            let (secrets, shares) = deterministically_compute_my_shares::<Z>(
                num_secrets,
                session.my_role(),
                session.num_parties(),
                session.threshold() as usize,
                42,
            );
            let result = malicious_robust_open
                .robust_open_list_to_all(&session, shares, session.threshold() as usize)
                .await
                .unwrap();
            (session.my_role(), secrets, result)
        };

        let (results_honest, results_malicious) =
            execute_protocol_small_w_malicious::<_, _, _, _, _, Z, EXTENSION_DEGREE>(
                &params,
                &params.malicious_roles,
                malicious_robust_open,
                network_mode,
                None,
                &mut task_honest,
                &mut task_malicious,
            );

        let num_honest = params.num_parties - params.malicious_roles.len();
        assert_eq!(results_honest.len(), num_honest);

        let pivot = results_honest.first().cloned().unwrap();

        for (role, secrets, openings) in results_honest.into_iter() {
            assert!(
                openings.is_some(),
                "Honest Party {} failed to open correctly, expected Some got None ",
                role
            );
            let openings = openings.unwrap();
            assert_eq!(secrets, pivot.1);
            assert_eq!(secrets, openings);
        }

        if !params.should_be_detected {
            for result_malicious in results_malicious.into_iter() {
                let (role, secrets, openings) = result_malicious.unwrap();
                assert!(
                    openings.is_some(),
                    "Malicious Party {} failed to open correctly, expected Some got None ",
                    role
                );
                let openings = openings.unwrap();
                assert_eq!(secrets, pivot.1);
                assert_eq!(secrets, openings);
            }
        }
    }

    #[test]
    fn test_robust_open_all_sync() {
        // expect a single round for opening
        let testing_parameters = TestingParameters::init(4, 1, &[], &[], &[], false, Some(1));

        let malicious_strategy = SecureRobustOpen::default();

        test_robust_open_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            testing_parameters,
            malicious_strategy,
            10,
            NetworkMode::Sync,
        );
    }

    #[test]
    fn test_robust_open_all_async() {
        // expect a single round for opening
        let testing_parameters = TestingParameters::init(4, 1, &[], &[], &[], false, Some(1));

        let malicious_strategy = SecureRobustOpen::default();

        test_robust_open_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            testing_parameters,
            malicious_strategy,
            10,
            NetworkMode::Async,
        );
    }

    #[test]
    fn test_dropout_robust_open_all_sync() {
        // Expect a single round for opening
        // Party that drops can not reconstruct
        let testing_parameters = TestingParameters::init(4, 1, &[2], &[], &[], true, Some(1));

        let malicious_strategy = MaliciousRobustOpenDrop::default();

        test_robust_open_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            testing_parameters,
            malicious_strategy,
            10,
            NetworkMode::Sync,
        );
    }

    #[test]
    fn test_dropout_robust_open_all_async() {
        // Expect a single round for opening
        // Party that drops can not reconstruct
        let testing_parameters = TestingParameters::init(4, 1, &[2], &[], &[], true, Some(1));

        let malicious_strategy = MaliciousRobustOpenDrop::default();

        test_robust_open_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            testing_parameters,
            malicious_strategy,
            10,
            NetworkMode::Async,
        );
    }

    #[test]
    fn test_malicious_robust_open_all_sync() {
        // Expect a single round for opening
        // Even the malicious party that sends random shares is able to reconstruct
        let testing_parameters = TestingParameters::init(4, 1, &[2], &[], &[], false, Some(1));

        let malicious_strategy = MaliciousRobustOpenLie::default();

        test_robust_open_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            testing_parameters,
            malicious_strategy,
            10,
            NetworkMode::Sync,
        );
    }

    #[test]
    fn test_malicious_robust_open_all_async() {
        // Expect a single round for opening
        // Even the malicious party that sends random shares is able to reconstruct
        let testing_parameters = TestingParameters::init(4, 1, &[2], &[], &[], false, Some(1));

        let malicious_strategy = MaliciousRobustOpenLie::default();

        test_robust_open_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            testing_parameters,
            malicious_strategy,
            10,
            NetworkMode::Async,
        );
    }
}
