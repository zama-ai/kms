use itertools::Itertools;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
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
    thread_handles::spawn_compute_bound,
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
    #[instrument(name="RobustOpenTo",skip(self,session,shares),fields(sid= ?session.session_id(), my_role = ?session.my_role(),num_receivers = ?shares.len()))]
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
    #[instrument(name="RobustOpen",skip(self,session,shares),fields(sid= ?session.session_id(), my_role = ?session.my_role(),batch_size = ?shares.len()))]
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
        format!("{indent}-SecureRobustOpen")
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
                session.network().increase_round_counter().await;
                let mut shares_for_reconstruction = None;
                for (receiver_role, values) in shares_map.into_iter() {
                    if receiver_role == own_role {
                        shares_for_reconstruction = Some(values);
                    } else {
                        session
                            .network()
                            .send(
                                Arc::new(NetworkValue::VecRingValue(values).to_network()),
                                &receiver_role,
                            )
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
                    _ => Err(anyhow_error_and_log(format!(
                        "Received {}, expected a Ring value in robust open to all",
                        msg.network_type_name()
                    ))),
                },
            )
            .await;

            //Start filling sharings with my own shares
            let sharings = shares
                .into_iter()
                .map(|share| ShamirSharings::create(vec![Share::new(own_role, share)]))
                .collect_vec();

            let reconstruct_fn = match session.network().get_network_mode() {
                crate::networking::NetworkMode::Sync => reconstruct_w_errors_sync,
                crate::networking::NetworkMode::Async => reconstruct_w_errors_async,
            };

            try_reconstruct_from_shares(session, sharings, degree, jobs, reconstruct_fn).await?
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
    sharings: Vec<ShamirSharings<Z>>,
    degree: usize,
    mut jobs: JoinSet<Result<JobResultType<Z>, Elapsed>>,
    reconstruct_fn: ReconsFunc<Z>,
) -> anyhow::Result<Option<Vec<Z>>> {
    let num_parties = session.num_parties();
    let threshold = session.threshold();
    let mut num_bots = session.corrupt_roles().len();
    let num_secrets = sharings.len();

    // OPTIMIZATION: Collect shares concurrently with batched reconstruction
    // Instead of processing one party at a time, collect multiple responses
    // and attempt reconstruction less frequently to reduce O(n×m) complexity

    let mut collected_shares = 0;
    let required_shares = threshold as usize + 1; // Minimum shares needed for reconstruction
    let mut last_reconstruction_attempt = 0;
    let sharings = Arc::new(Mutex::new(sharings));

    //Start awaiting on receive jobs to retrieve the shares
    while let Some(v) = jobs.join_next().await {
        let sharings = sharings.clone();
        let joined_result = v?;
        match joined_result {
            Ok((party_id, data)) => {
                if let Ok(values) = data {
                    fill_indexed_shares(
                        &mut sharings
                            .lock()
                            .map_err(|_| anyhow_error_and_log("Poisoned lock"))?,
                        values,
                        num_secrets,
                        party_id,
                    )?;
                    collected_shares += 1;
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

        // OPTIMIZATION: Attempt reconstruction strategically to reduce redundant attempts:
        // 1. First time we reach minimum required shares (threshold + 1)
        // 2. For each additional share to handle potential corrupt/invalid shares
        // 3. When no more jobs are pending (final attempt)
        let should_attempt_reconstruction = collected_shares >= required_shares
            && (last_reconstruction_attempt == 0  // First time we have enough shares
                || collected_shares > last_reconstruction_attempt  // Each additional share
                || jobs.is_empty()); // Final attempt when all responses collected

        if should_attempt_reconstruction {
            last_reconstruction_attempt = collected_shares;

            // Spawn a task on rayon.
            let res: Option<Vec<_>> = spawn_compute_bound(move || -> anyhow::Result<_> {
                //Note: here we keep waiting on new shares until we have all of the values opened.
                // Here we want to use par_iter for opening the huge batches
                // present in DKG, but we want to avoid using it for
                // other tasks.
                Ok(sharings
                    .lock()
                    .map_err(|_| anyhow_error_and_log("Poisoned lock"))?
                    .par_iter()
                    .with_min_len(2 * BATCH_SIZE_BITS)
                    .map(|sharing| {
                        reconstruct_fn(num_parties, degree, threshold as usize, num_bots, sharing)
                            .unwrap_or_default()
                    })
                    .collect())
            })
            .await??;

            //Only prematurely shutdown the jobs if we have managed to reconstruct everything
            // NOTE: This shutdown can cause a warn log from the spawn_compute_bound,
            // because the job may die whilst a rayon task was spawned for deserializing the
            // incoming message.
            if res.is_some() {
                jobs.shutdown().await;
                return Ok(res);
            }
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

    use crate::algebra::structure_traits::{
        ErrorCorrect, Invert, Ring, RingWithExceptionalSequence,
    };
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
    pub(crate) fn deterministically_compute_my_shares<Z: RingWithExceptionalSequence>(
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
    async fn test_robust_open_strategies<
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
            (secrets, result)
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
            (secrets, result)
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
            )
            .await;

        let num_honest = params.num_parties - params.malicious_roles.len();
        assert_eq!(results_honest.len(), num_honest);

        let pivot = results_honest.get(&Role::indexed_from_one(1)).unwrap();

        for (role, (secrets, openings)) in results_honest.iter() {
            assert!(
                openings.is_some(),
                "Honest Party {role} failed to open correctly, expected Some got None "
            );
            let openings = openings.as_ref().unwrap();
            assert_eq!(*secrets, pivot.0);
            assert_eq!(*secrets, *openings);
        }

        if !params.should_be_detected {
            for (role, result_malicious) in results_malicious.into_iter() {
                let (secrets, openings) = result_malicious.unwrap();
                assert!(
                    openings.is_some(),
                    "Malicious Party {role} failed to open correctly, expected Some got None "
                );
                assert_eq!(secrets, pivot.0);
                assert_eq!(secrets, openings.unwrap());
            }
        }
    }

    #[tokio::test]
    async fn test_robust_open_all_sync() {
        // expect a single round for opening
        let testing_parameters = TestingParameters::init(4, 1, &[], &[], &[], false, Some(1));

        let malicious_strategy = SecureRobustOpen::default();

        test_robust_open_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            testing_parameters,
            malicious_strategy,
            10,
            NetworkMode::Sync,
        ).await;
    }

    #[tokio::test]
    async fn test_robust_open_all_async() {
        // expect a single round for opening
        let testing_parameters = TestingParameters::init(4, 1, &[], &[], &[], false, Some(1));

        let malicious_strategy = SecureRobustOpen::default();

        test_robust_open_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            testing_parameters,
            malicious_strategy,
            10,
            NetworkMode::Async,
        ).await;
    }

    #[tokio::test]
    async fn test_dropout_robust_open_all_sync() {
        // Expect a single round for opening
        // Party that drops can not reconstruct
        let testing_parameters = TestingParameters::init(4, 1, &[2], &[], &[], true, Some(1));

        let malicious_strategy = MaliciousRobustOpenDrop::default();

        test_robust_open_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            testing_parameters,
            malicious_strategy,
            10,
            NetworkMode::Sync,
        ).await;
    }

    #[tokio::test]
    async fn test_dropout_robust_open_all_async() {
        // Expect a single round for opening
        // Party that drops can not reconstruct
        let testing_parameters = TestingParameters::init(4, 1, &[2], &[], &[], true, Some(1));

        let malicious_strategy = MaliciousRobustOpenDrop::default();

        test_robust_open_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            testing_parameters,
            malicious_strategy,
            10,
            NetworkMode::Async,
        ).await;
    }

    #[tokio::test]
    async fn test_malicious_robust_open_all_sync() {
        // Expect a single round for opening
        // Even the malicious party that sends random shares is able to reconstruct
        let testing_parameters = TestingParameters::init(4, 1, &[2], &[], &[], false, Some(1));

        let malicious_strategy = MaliciousRobustOpenLie::default();

        test_robust_open_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            testing_parameters,
            malicious_strategy,
            10,
            NetworkMode::Sync,
        ).await;
    }

    #[tokio::test]
    async fn test_malicious_robust_open_all_async() {
        // Expect a single round for opening
        // Even the malicious party that sends random shares is able to reconstruct
        let testing_parameters = TestingParameters::init(4, 1, &[2], &[], &[], false, Some(1));

        let malicious_strategy = MaliciousRobustOpenLie::default();

        test_robust_open_strategies::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            testing_parameters,
            malicious_strategy,
            10,
            NetworkMode::Async,
        ).await;
    }
}
