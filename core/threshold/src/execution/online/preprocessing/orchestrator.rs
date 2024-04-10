use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    thread,
};

use core::slice::Iter;
use futures::Future;
use itertools::{Itertools, PeekingNext};
use num_integer::div_ceil;
use rand::{CryptoRng, Rng};
use tokio::{runtime::Handle, task::JoinSet};
use tracing::{instrument, Instrument};

use crate::{
    algebra::{
        residue_poly::{ResiduePoly128, ResiduePoly64},
        structure_traits::{Derive, ErrorCorrect, Invert, RingEmbed, Solve},
    },
    computation::SessionId,
    error::error_handler::anyhow_error_and_log,
    execution::{
        config::BatchParams,
        large_execution::offline::{LargePreprocessing, TrueDoubleSharing, TrueSingleSharing},
        online::{
            gen_bits::{BitGenEven, RealBitGenEven},
            preprocessing::{
                BasePreprocessing, BitPreprocessing, DKGPreprocessing, PreprocessorFactory,
            },
            triple::Triple,
        },
        runtime::session::{
            BaseSessionHandles, LargeSession, ParameterHandles, SmallSession, ToBaseSession,
        },
        sharing::share::Share,
        small_execution::{
            agree_random::RealAgreeRandom, offline::SmallPreprocessing, prf::PRSSConversions,
        },
        tfhe_internals::parameters::DKGParams,
    },
};

#[derive(Clone)]
pub struct PreprocessingOrchestrator<Z> {
    params: DKGParams,
    base_preproc: Arc<RwLock<Box<dyn BasePreprocessing<Z>>>>,
    bit_preproc: Arc<RwLock<Box<dyn BitPreprocessing<Z>>>>,
    dkg_preproc: Arc<RwLock<Box<dyn DKGPreprocessing<Z>>>>,
}

#[derive(Clone, Copy, Debug)]
pub enum TypeOrchestration {
    Triples,
    Randoms,
    Bits,
}

const BATCH_SIZE_TRIPLES: usize = 10000;
const BATCH_SIZE_BITS: usize = 10000;

impl PreprocessingOrchestrator<ResiduePoly64> {
    ///Create a new [`PreprocessingOrchestrator`] to generate
    ///offline data required by [`crate::execution::endpoints::keygen::distributed_keygen`]
    ///for [`DKGParams::WithoutSnS`]
    ///
    ///Relies on the provided [`PreprocessorFactory`] to create:
    ///- [`BasePreprocessing`]
    ///- [`BitPreprocessing`]
    ///- [`DKGPreprocessing`]
    pub fn new<F: PreprocessorFactory + ?Sized>(
        factory: &mut F,
        params: DKGParams,
    ) -> anyhow::Result<Self> {
        if let DKGParams::WithSnS(_) = params {
            return Err(anyhow_error_and_log("Cant have SnS with ResiduePoly64"));
        }

        Ok(Self {
            params,
            base_preproc: Arc::new(RwLock::new(factory.create_base_preprocessing_residue_64())),
            bit_preproc: Arc::new(RwLock::new(factory.create_bit_preprocessing_residue_64())),
            dkg_preproc: Arc::new(RwLock::new(factory.create_dkg_preprocessing_no_sns())),
        })
    }
}

impl PreprocessingOrchestrator<ResiduePoly128> {
    ///Create a new [`PreprocessingOrchestrator`] to generate
    ///offline data required by [`crate::execution::endpoints::keygen::distributed_keygen`]
    ///for [`DKGParams::WithSnS`]
    ///
    ///Relies on the provided [`PreprocessorFactory`] to create:
    ///- [`BasePreprocessing`]
    ///- [`BitPreprocessing`]
    ///- [`DKGPreprocessing`]
    pub fn new<F: PreprocessorFactory + ?Sized>(
        factory: &mut F,
        params: DKGParams,
    ) -> anyhow::Result<Self> {
        if let DKGParams::WithoutSnS(_) = params {
            return Err(anyhow_error_and_log(
                "Should not have no SNS with ResiduePoly128",
            ));
        }

        Ok(Self {
            params,
            base_preproc: Arc::new(RwLock::new(factory.create_base_preprocessing_residue_128())),
            bit_preproc: Arc::new(RwLock::new(factory.create_bit_preprocessing_residue_128())),
            dkg_preproc: Arc::new(RwLock::new(factory.create_dkg_preprocessing_with_sns())),
        })
    }
}

type SmallSessionDkgResult<R> =
    anyhow::Result<(Vec<SmallSession<R>>, Box<dyn DKGPreprocessing<R>>)>;

impl<R> PreprocessingOrchestrator<R>
where
    R: PRSSConversions + ErrorCorrect + Invert + Derive + RingEmbed + Solve,
{
    ///Start the orchestration of the preprocessing, returning a filled [`DKGPreprocessing`].
    ///
    ///Expects a vector of [`SmallSession`] __(at least 2!)__, using each of them in parallel for the preprocessing.
    ///The [`PRSSSetup`] is done by the orchestrator.
    ///
    ///__NOTE__ For now we fix the batch_size to 1000 and dedicate 1 in 20 sessions
    /// to raw triple and randomness generation and the rest to bit generation
    #[instrument(skip(self, sessions), fields(own_identity = ?sessions[0].own_identity()))]
    pub fn orchestrate_small_session_dkg_processing(
        self,
        mut sessions: Vec<SmallSession<R>>,
    ) -> SmallSessionDkgResult<R> {
        let party_id = sessions[0].own_identity();
        for session in sessions.iter() {
            assert_eq!(party_id, session.own_identity());
        }

        let num_bits = self.params.get_params_basics_handle().total_bits_required();
        let num_triples = self
            .params
            .get_params_basics_handle()
            .total_triples_required()
            - num_bits;
        let nb_randomness = self
            .params
            .get_params_basics_handle()
            .total_randomness_required()
            - num_bits;

        //Ensures sessions are sorted by session id
        sessions.sort_by_key(|session| session.session_id());

        //Dedicate 1 in 20 sessions to raw triples, the rest to bits
        let num_basic_sessions = div_ceil(sessions.len(), 20);
        let mut basic_sessions = (0..num_basic_sessions)
            .map(|_| {
                sessions.pop().ok_or_else(|| {
                    anyhow_error_and_log("Fail to retrieve sessions for basic preprocessing")
                })
            })
            .try_collect()?;

        let runtime_handle = tokio::runtime::Handle::current();
        //We spawn a native thread for the basic orchestrator
        let basic_orchestrator = self.clone();
        let basic_orchestrator_thread = thread::spawn(move || {
            let _guard = runtime_handle.enter();
            basic_orchestrator.orchestrate_small_session_processing(
                BATCH_SIZE_TRIPLES,
                num_triples,
                TypeOrchestration::Triples,
                &mut basic_sessions,
                runtime_handle.clone(),
            )?;
            basic_orchestrator.orchestrate_small_session_processing(
                nb_randomness,
                nb_randomness,
                TypeOrchestration::Randoms,
                &mut basic_sessions,
                runtime_handle,
            )?;
            Ok::<_, anyhow::Error>(basic_sessions)
        });

        let runtime_handle = tokio::runtime::Handle::current();
        //We spawn a native thread for the bit orchestrator
        let bit_orchestrator = self.clone();
        let bit_orchestrator_thread = thread::spawn(move || {
            let _guard = runtime_handle.enter();
            bit_orchestrator.orchestrate_small_session_processing(
                BATCH_SIZE_BITS,
                num_bits,
                TypeOrchestration::Bits,
                &mut sessions,
                runtime_handle,
            )?;
            Ok::<_, anyhow::Error>(sessions)
        });

        let mut res_sessions = Vec::new();
        res_sessions.append(
            &mut basic_orchestrator_thread.join().map_err(|_| {
                anyhow_error_and_log("Error joining on basic orchestrator thread")
            })??,
        );
        res_sessions.append(
            &mut bit_orchestrator_thread
                .join()
                .map_err(|_| anyhow_error_and_log("Error joining on bit orchestrator thread"))??,
        );

        {
            let mut base_preproc = self.base_preproc.try_write().map_err(|_| {
                anyhow_error_and_log("Error locking the base preprocessing store for write")
            })?;
            let mut bit_preproc = self.bit_preproc.try_write().map_err(|_| {
                anyhow_error_and_log("Error locking the bit preprocessing store for write ")
            })?;
            let mut dkg_preproc = self.dkg_preproc.try_write().map_err(|_| {
                anyhow_error_and_log("Error locking the dkg preprocessing store for write ")
            })?;

            dkg_preproc.fill_from_triples_and_bit_preproc(
                self.params,
                &mut res_sessions
                    .first()
                    .ok_or_else(|| {
                        anyhow_error_and_log(
                            "Error retrieving the first session to fill dkg preprocessing",
                        )
                    })?
                    .to_base_session(),
                base_preproc.as_mut(),
                bit_preproc.as_mut(),
            )?;
        }

        let dkg_preproc_return = Arc::into_inner(self.dkg_preproc).ok_or_else(|| {
            anyhow_error_and_log("Error getting hold of dkg preprocessing store inside the Arc")
        })?;
        let dkg_preproc_return = dkg_preproc_return.into_inner().map_err(|_| {
            anyhow_error_and_log("Error consuming dkg preprocessing inside the Lock")
        })?;
        Ok((res_sessions, dkg_preproc_return))
    }

    ///Start the orchestration of the preprocessing, returning a filled [`DKGPreprocessing`].
    ///
    ///Expects a vector of [`LargeSession`] __(at least 2!)__, using each of them in parallel for the preprocessing.
    ///
    ///__NOTE__ For now we fix the batch_size to 1000 and dedicate 1 in 20 sessions
    /// to raw triple and randomness generation and the rest to bit generation
    #[instrument(skip(self, sessions), fields(own_identity = ?sessions[0].own_identity()))]
    pub fn orchestrate_large_session_dkg_processing(
        self,
        mut sessions: Vec<LargeSession>,
    ) -> anyhow::Result<(Vec<LargeSession>, Box<dyn DKGPreprocessing<R>>)> {
        let party_id = sessions[0].own_identity();
        for session in sessions.iter() {
            assert_eq!(party_id, session.own_identity());
        }
        let num_bits = self.params.get_params_basics_handle().total_bits_required();
        let num_triples = self
            .params
            .get_params_basics_handle()
            .total_triples_required()
            - num_bits;
        let nb_randomness = self
            .params
            .get_params_basics_handle()
            .total_randomness_required()
            - num_bits;

        //Ensures sessions are sorted by session id
        sessions.sort_by_key(|session| session.session_id());

        //Dedicate 1 in 20 sessions to raw triples, the rest to bits
        let num_basic_sessions = div_ceil(sessions.len(), 20);
        let mut basic_sessions = (0..num_basic_sessions)
            .map(|_| {
                sessions.pop().ok_or_else(|| {
                    anyhow_error_and_log("Fail to retrieve sessions for basic preprocessing")
                })
            })
            .try_collect()?;

        let runtime_handle = tokio::runtime::Handle::current();
        //We spawn a native thread for the basic orchestrator
        let basic_orchestrator = self.clone();
        let basic_orchestrator_thread = thread::spawn(move || {
            let _guard = runtime_handle.enter();
            basic_orchestrator.orchestrate_large_session_processing(
                BATCH_SIZE_TRIPLES,
                num_triples,
                TypeOrchestration::Triples,
                &mut basic_sessions,
                runtime_handle.clone(),
            )?;
            basic_orchestrator.orchestrate_large_session_processing(
                nb_randomness,
                nb_randomness,
                TypeOrchestration::Randoms,
                &mut basic_sessions,
                runtime_handle.clone(),
            )?;
            Ok::<_, anyhow::Error>(basic_sessions)
        });

        let runtime_handle = tokio::runtime::Handle::current();
        //We spawn a native thread for the bit orchestrator
        let bit_orchestrator = self.clone();
        let bit_orchestrator_thread = thread::spawn(move || {
            let _guard = runtime_handle.enter();
            bit_orchestrator.orchestrate_large_session_processing(
                BATCH_SIZE_BITS,
                num_bits,
                TypeOrchestration::Bits,
                &mut sessions,
                runtime_handle,
            )?;
            Ok::<_, anyhow::Error>(sessions)
        });

        let mut res_sessions = Vec::new();
        res_sessions.append(
            &mut basic_orchestrator_thread.join().map_err(|_| {
                anyhow_error_and_log("Error joining on basic orchestrator thread")
            })??,
        );
        res_sessions.append(
            &mut bit_orchestrator_thread
                .join()
                .map_err(|_| anyhow_error_and_log("Error joining on bit orchestrator thread"))??,
        );

        {
            let mut base_preproc = self.base_preproc.try_write().map_err(|_| {
                anyhow_error_and_log("Error locking the base preprocessing store for write")
            })?;
            let mut bit_preproc = self.bit_preproc.try_write().map_err(|_| {
                anyhow_error_and_log("Error locking the bit preprocessing store for write ")
            })?;
            let mut dkg_preproc = self.dkg_preproc.try_write().map_err(|_| {
                anyhow_error_and_log("Error locking the dkg preprocessing store for write ")
            })?;

            dkg_preproc.fill_from_triples_and_bit_preproc(
                self.params,
                &mut res_sessions
                    .first()
                    .ok_or_else(|| {
                        anyhow_error_and_log(
                            "Error retrieving the first session to fill dkg preprocessing",
                        )
                    })?
                    .to_base_session(),
                base_preproc.as_mut(),
                bit_preproc.as_mut(),
            )?;
        }

        let dkg_preproc_return = Arc::into_inner(self.dkg_preproc).ok_or_else(|| {
            anyhow_error_and_log("Error getting hold of dkg preprocessing store inside the Arc")
        })?;
        let dkg_preproc_return = dkg_preproc_return.into_inner().map_err(|_| {
            anyhow_error_and_log("Error consuming dkg preprocessing inside the Lock")
        })?;

        Ok((res_sessions, dkg_preproc_return))
    }

    ///Generic funciton to orchestrate all types of preprocessing for [`SmallSession`]
    ///
    ///Expects:
    ///- a batch size,
    ///- the total size we need to generate
    ///- the type of preprocessing as a [`TypeOrchestration`]
    ///- the set of [`SmallSession`] dedicated to this preprocessing
    ///- a [`Handle`] to the tokio runtime
    pub fn orchestrate_small_session_processing(
        &self,
        batch_size: usize,
        total_size: usize,
        type_orchestration: TypeOrchestration,
        sessions: &mut Vec<SmallSession<R>>,
        runtime_handle: Handle,
    ) -> anyhow::Result<()> {
        let party_id = sessions[0].own_identity();
        for session in sessions.iter() {
            assert_eq!(party_id, session.own_identity());
        }
        println!("Entering orchestrator for  {}", party_id);

        let task_basic_gen = |mut session: SmallSession<R>, span: tracing::Span| async move {
            let batch_size = match type_orchestration {
                TypeOrchestration::Triples => BatchParams {
                    triples: batch_size,
                    randoms: 0,
                },
                TypeOrchestration::Randoms => BatchParams {
                    triples: 0,
                    randoms: batch_size,
                },
                TypeOrchestration::Bits => BatchParams {
                    triples: batch_size,
                    randoms: batch_size,
                },
            };

            let preprocessing =
                SmallPreprocessing::<R, RealAgreeRandom>::init(&mut session, batch_size)
                    .instrument(span)
                    .await;
            (session, preprocessing)
        };

        self.execute_preprocessing(
            sessions,
            total_size,
            batch_size,
            type_orchestration,
            task_basic_gen,
            runtime_handle,
        )
    }

    ///Generic funciton to orchestrate all types of preprocessing for [`LargeSession`]
    ///
    ///Expects:
    ///- a batch size,
    ///- the total size we need to generate
    ///- the type of preprocessing as a [`TypeOrchestration`]
    ///- the set of [`LargeSession`] dedicated to this preprocessing
    ///- a [`Handle`] to the tokio runtime
    pub fn orchestrate_large_session_processing(
        &self,
        batch_size: usize,
        total_size: usize,
        type_orchestration: TypeOrchestration,
        sessions: &mut Vec<LargeSession>,
        runtime_handle: Handle,
    ) -> anyhow::Result<()> {
        let party_id = sessions[0].own_identity();
        for session in sessions.iter() {
            assert_eq!(party_id, session.own_identity());
        }
        println!("Entering orchestrator for  {}", party_id);

        let task_basic_gen = |mut session: LargeSession, span: tracing::Span| async move {
            let batch_size = match type_orchestration {
                TypeOrchestration::Triples => BatchParams {
                    triples: batch_size,
                    randoms: 0,
                },
                TypeOrchestration::Randoms => BatchParams {
                    triples: 0,
                    randoms: batch_size,
                },
                TypeOrchestration::Bits => BatchParams {
                    triples: batch_size,
                    randoms: batch_size,
                },
            };
            let preprocessing = LargePreprocessing::<R, _, _>::init(
                &mut session,
                batch_size,
                TrueSingleSharing::default(),
                TrueDoubleSharing::default(),
            )
            .instrument(span)
            .await;
            (session, preprocessing)
        };

        self.execute_preprocessing(
            sessions,
            total_size,
            batch_size,
            type_orchestration,
            task_basic_gen,
            runtime_handle,
        )
    }

    ///Processes the triples in a deterministic order (dictated by [`SessionId`]) into the [`BasePreprocessing`].
    fn process_triples(
        &self,
        data: Vec<Triple<R>>,
        sid: SessionId,
        next_sid_to_push: &mut Iter<SessionId>,
        results: &mut BTreeMap<SessionId, Vec<Triple<R>>>,
    ) -> anyhow::Result<()> {
        match next_sid_to_push.peeking_next(|next_sid| **next_sid == sid) {
            Some(_) => {
                //push, and try pushing whats in map
                (*self.base_preproc.try_write().map_err(|_| {
                    anyhow_error_and_log("Error locking the base preprocessing store for write ")
                })?)
                .append_triples(data);
                let results_keys = results.keys().cloned().collect_vec();
                for sid in results_keys {
                    match next_sid_to_push.peeking_next(|next_sid| **next_sid == sid) {
                        Some(_) => {
                            (*self.base_preproc.try_write().map_err(|_| {
                                anyhow_error_and_log(
                                    "Error locking the base preprocessing store for write ",
                                )
                            })?)
                            .append_triples(
                                results
                                    .remove_entry(&sid)
                                    .ok_or_else(|| {
                                        anyhow_error_and_log(
                                            "Error trying to access an entry that should be here",
                                        )
                                    })?
                                    .1,
                            );
                        }
                        None => break,
                    }
                }
            }
            None => {
                let _ = results.insert(sid, data);
            }
        }
        Ok(())
    }

    ///Processes the randomness in a deterministic order (dictated by [`SessionId`]) into the [`BasePreprocessing`].
    fn process_randoms(
        &self,
        data: Vec<Share<R>>,
        sid: SessionId,
        next_sid_to_push: &mut Iter<SessionId>,
        results: &mut BTreeMap<SessionId, Vec<Share<R>>>,
    ) -> anyhow::Result<()> {
        match next_sid_to_push.peeking_next(|next_sid| **next_sid == sid) {
            Some(_) => {
                //push, and try pushing whats in map
                (*self.base_preproc.try_write().map_err(|_| {
                    anyhow_error_and_log("Error locking the base preprocessing store for write ")
                })?)
                .append_randoms(data);
                let results_keys = results.keys().cloned().collect_vec();
                for sid in results_keys {
                    match next_sid_to_push.peeking_next(|next_sid| **next_sid == sid) {
                        Some(_) => {
                            (*self.base_preproc.try_write().map_err(|_| {
                                anyhow_error_and_log(
                                    "Error locking the base preprocessing store for write ",
                                )
                            })?)
                            .append_randoms(
                                results
                                    .remove_entry(&sid)
                                    .ok_or_else(|| {
                                        anyhow_error_and_log(
                                            "Error trying to access an entry that should be here",
                                        )
                                    })?
                                    .1,
                            );
                        }
                        None => break,
                    }
                }
            }
            None => {
                let _ = results.insert(sid, data);
            }
        }
        Ok(())
    }

    ///Processes the bits in a deterministic order (dictated by [`SessionId`]) into the [`BitPreprocessing`].
    fn process_bits(
        &self,
        data: Vec<Share<R>>,
        sid: SessionId,
        next_sid_to_push: &mut Iter<SessionId>,
        results: &mut BTreeMap<SessionId, Vec<Share<R>>>,
    ) -> anyhow::Result<()> {
        match next_sid_to_push.peeking_next(|next_sid| **next_sid == sid) {
            Some(_) => {
                //push, and try pushing whats in map
                (*self.bit_preproc.try_write().map_err(|_| {
                    anyhow_error_and_log("Error locking the bit preprocessing store for write ")
                })?)
                .append_bits(data);
                let results_keys = results.keys().cloned().collect_vec();
                for sid in results_keys {
                    match next_sid_to_push.peeking_next(|next_sid| **next_sid == sid) {
                        Some(_) => {
                            (*self.bit_preproc.try_write().map_err(|_| {
                                anyhow_error_and_log(
                                    "Error locking the bit preprocessing store for write ",
                                )
                            })?)
                            .append_bits(
                                results
                                    .remove_entry(&sid)
                                    .ok_or_else(|| {
                                        anyhow_error_and_log(
                                            "Error trying to access an entry that should be here",
                                        )
                                    })?
                                    .1,
                            );
                        }
                        None => break,
                    }
                }
            }
            None => {
                let _ = results.insert(sid, data);
            }
        }
        Ok(())
    }

    ///Generic function to execute the actual preprocessing protocol using the sessions
    #[instrument(skip(self,sessions,task_basic_gen,runtime_handle), fields(own_identity = ?sessions[0].own_identity()))]
    fn execute_preprocessing<
        Rnd: Rng + CryptoRng + Sync + 'static,
        S: BaseSessionHandles<Rnd> + 'static,
        P: BasePreprocessing<R> + 'static,
        TaskOutput,
    >(
        &self,
        sessions: &mut Vec<S>,
        total_size: usize,
        batch_size: usize,
        type_orchestration: TypeOrchestration,
        task_basic_gen: impl Fn(S, tracing::Span) -> TaskOutput,
        runtime_handle: Handle,
    ) -> anyhow::Result<()>
    where
        TaskOutput: Future<Output = (S, anyhow::Result<P>)> + Send,
        TaskOutput: Send + 'static,
    {
        let num_sessions = sessions.len();
        let num_loops = div_ceil(total_size, batch_size * num_sessions);

        let mut session_ids_in_order = sessions
            .iter()
            .map(|session| session.session_id())
            .collect_vec();
        session_ids_in_order.sort();

        for _ in 0..num_loops {
            //Within each orchestrator (which is a native thread), the multiple sessions are run
            //by the shared tokio runtime
            let mut basic_gen_tasks = JoinSet::new();
            let mut bit_gen_tasks = JoinSet::new();
            for _ in 0..num_sessions {
                basic_gen_tasks.spawn(task_basic_gen(
                    sessions
                        .pop()
                        .ok_or_else(|| anyhow_error_and_log("Error trying to pop sessions"))?,
                    tracing::Span::current(),
                ));
            }

            let mut next_sid_to_push = session_ids_in_order.iter();
            runtime_handle.block_on(async {
                let mut triple_results = BTreeMap::new();
                let mut randomness_results = BTreeMap::new();
                while let Some(task_output) = basic_gen_tasks.join_next().await {
                    let (new_session, preproc) = task_output?;
                    let mut preproc = preproc?;
                    match type_orchestration {
                        TypeOrchestration::Triples => {
                            let triples = preproc.next_triple_vec(batch_size)?;
                            let sid = new_session.session_id();
                            self.process_triples(
                                triples,
                                sid,
                                &mut next_sid_to_push,
                                &mut triple_results,
                            )?;

                            sessions.push(new_session);
                        }
                        TypeOrchestration::Randoms => {
                            let randoms = preproc.next_random_vec(batch_size)?;
                            let sid = new_session.session_id();
                            self.process_randoms(
                                randoms,
                                sid,
                                &mut next_sid_to_push,
                                &mut randomness_results,
                            )?;

                            sessions.push(new_session);
                        }
                        TypeOrchestration::Bits => {
                            bit_gen_tasks.spawn(task_bit_gen(
                                batch_size,
                                new_session,
                                preproc,
                                tracing::Span::current(),
                            ));
                        }
                    }
                }
                Ok::<(), anyhow::Error>(())
            })?;

            runtime_handle.block_on(async {
                let mut bit_results: BTreeMap<SessionId, Vec<Share<R>>> = BTreeMap::new();
                while let Some(task_output) = bit_gen_tasks.join_next().await {
                    let (new_session, bits) =
                        task_output.map_err(|_| anyhow_error_and_log("error"))??;
                    let sid = new_session.session_id();
                    self.process_bits(bits, sid, &mut next_sid_to_push, &mut bit_results)?;

                    sessions.push(new_session);
                }
                Ok::<(), anyhow::Error>(())
            })?;
        }
        Ok(())
    }
}

///Auxiliary function used in [`PreprocessingOrchestrator::execute_preprocessing`] to generate bits from filled [`BasePreprocessing`]
async fn task_bit_gen<
    Z: RingEmbed + Solve + ErrorCorrect + Invert,
    Rnd: Rng + CryptoRng + Sync,
    S: BaseSessionHandles<Rnd>,
    Prep: BasePreprocessing<Z>,
>(
    batch_size: usize,
    mut session: S,
    mut preproc: Prep,
    span: tracing::Span,
) -> anyhow::Result<(S, Vec<Share<Z>>)> {
    let bits = RealBitGenEven::gen_bits_even(batch_size, &mut preproc, &mut session)
        .instrument(span)
        .await?;

    Ok((session, bits))
}
#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc, thread};

    use itertools::Itertools;

    use crate::{
        algebra::{
            base_ring::Z64,
            residue_poly::ResiduePoly64,
            structure_traits::{One, Zero},
        },
        computation::SessionId,
        execution::{
            online::preprocessing::{create_memory_factory, BasePreprocessing, BitPreprocessing},
            runtime::{
                party::Identity,
                test_runtime::{generate_fixed_identities, DistributedTestRuntime},
            },
            sharing::shamir::{RevealOp, ShamirSharings},
            tfhe_internals::parameters::PARAMS_P8_SMALL_NO_SNS,
        },
    };

    use super::{PreprocessingOrchestrator, TypeOrchestration};

    fn check_triples_reconstruction(
        triple_preprocs: &mut [Box<dyn BasePreprocessing<ResiduePoly64>>],
        identities: &[Identity],
        num_triples: usize,
        threshold: usize,
    ) {
        //Retrieve triples and try reconstruct them
        let mut triples_map = HashMap::new();
        for ((party_idx, _party_id), triple_preproc) in identities
            .iter()
            .enumerate()
            .zip(triple_preprocs.iter_mut())
        {
            let triple_len = triple_preproc.triples_len();

            assert_eq!(triple_len, num_triples);

            let triples_shares = triple_preproc.next_triple_vec(num_triples).unwrap();
            triples_map.insert(party_idx + 1, triples_shares);
        }

        let mut vec_sharings_a = vec![ShamirSharings::default(); num_triples];
        let mut vec_sharings_b = vec![ShamirSharings::default(); num_triples];
        let mut vec_sharings_c = vec![ShamirSharings::default(); num_triples];
        for (_, triples) in triples_map {
            for (idx, triple) in triples.iter().enumerate() {
                let _ = vec_sharings_a[idx].add_share(triple.a);
                let _ = vec_sharings_b[idx].add_share(triple.b);
                let _ = vec_sharings_c[idx].add_share(triple.c);
            }
        }

        for (a, (b, c)) in vec_sharings_a
            .iter()
            .zip(vec_sharings_b.iter().zip(vec_sharings_c.iter()))
        {
            let aa = a.reconstruct(threshold).unwrap();
            let bb = b.reconstruct(threshold).unwrap();
            let cc = c.reconstruct(threshold).unwrap();
            assert_eq!(aa * bb, cc);
        }
    }

    fn check_bits_reconstruction(
        bit_preprocs: &mut [Box<dyn BitPreprocessing<ResiduePoly64>>],
        identities: &[Identity],
        num_bits: usize,
        threshold: usize,
    ) {
        //Retrieve bits and try reconstruct them
        let mut bits_map = HashMap::new();
        for ((party_idx, _party_id), bit_preproc) in
            identities.iter().enumerate().zip(bit_preprocs.iter_mut())
        {
            let bit_len = bit_preproc.bits_len();
            assert_eq!(bit_len, num_bits);

            let bits_shares = bit_preproc.next_bit_vec(num_bits).unwrap();
            bits_map.insert(party_idx + 1, bits_shares);
        }

        let mut vec_sharings = vec![ShamirSharings::default(); num_bits];
        for (_, bits) in bits_map {
            for (idx, bit) in bits.iter().enumerate() {
                let _ = vec_sharings[idx].add_share(*bit);
            }
        }

        for b in vec_sharings {
            let b = b.reconstruct(threshold).unwrap().to_scalar().unwrap();

            assert_eq!(b * (Z64::ONE - b), Z64::ZERO);
        }
    }

    fn check_randomness_reconstruction(
        random_preprocs: &mut [Box<dyn BasePreprocessing<ResiduePoly64>>],
        identities: &[Identity],
        num_randomness: usize,
        threshold: usize,
    ) {
        //Retrieve bits and try reconstruct them
        let mut randomness_map = HashMap::new();
        for ((party_idx, _party_id), random_preproc) in identities
            .iter()
            .enumerate()
            .zip(random_preprocs.iter_mut())
        {
            let randomness_len = random_preproc.randoms_len();
            assert_eq!(randomness_len, num_randomness);

            let randomness_shares = random_preproc.next_random_vec(num_randomness).unwrap();

            randomness_map.insert(party_idx + 1, randomness_shares);
        }

        let mut vec_sharings = vec![ShamirSharings::default(); num_randomness];
        for (_, randomness) in randomness_map {
            for (idx, bit) in randomness.iter().enumerate() {
                let _ = vec_sharings[idx].add_share(*bit);
            }
        }

        for b in vec_sharings {
            let _b = b.reconstruct(threshold).unwrap();
        }
    }

    fn test_orchestrator_large(
        num_sessions: u128,
        num_correlations: usize,
        batch_size: usize,
        num_parties: usize,
        threshold: u8,
        type_orchestration: TypeOrchestration,
    ) -> (Vec<Identity>, Vec<PreprocessingOrchestrator<ResiduePoly64>>) {
        //Create identities and runtime
        let identities = generate_fixed_identities(num_parties);
        let runtimes = (0..num_sessions)
            .map(|_| (DistributedTestRuntime::<ResiduePoly64>::new(identities.clone(), threshold)))
            .collect_vec();
        let runtimes = Arc::new(runtimes);

        let mut threads = Vec::new();

        //For test runtime we need multiple runtimes for mutltiple channels
        let rt = tokio::runtime::Runtime::new().unwrap();
        for party_id in 0..num_parties {
            let runtimes = runtimes.clone();
            let rt_handle = rt.handle().clone();
            threads.push(thread::spawn(move || {
                let _guard = rt_handle.enter();
                println!("Thread created for {party_id}");

                //For each party, create num_sessions sessions
                let mut sessions = runtimes
                    .iter()
                    .zip(0..num_sessions)
                    .map(|(runtime, session_id)| {
                        runtime.large_session_for_party(SessionId(session_id), party_id)
                    })
                    .collect_vec();

                let mut inmemory_factory = create_memory_factory();

                //DKGParams just for being able to call new (no SNS for ResiduePoly64)
                let params = PARAMS_P8_SMALL_NO_SNS;

                let orchestrator = PreprocessingOrchestrator::<ResiduePoly64>::new(
                    inmemory_factory.as_mut(),
                    params,
                )
                .unwrap();
                orchestrator
                    .orchestrate_large_session_processing(
                        batch_size,
                        num_correlations,
                        type_orchestration,
                        &mut sessions,
                        rt_handle.clone(),
                    )
                    .unwrap();

                orchestrator
            }));
        }

        let mut orchestrators = Vec::new();
        for thread in threads {
            orchestrators.push(thread.join().unwrap());
        }

        (identities, orchestrators)
    }

    #[test]
    fn test_triple_orchestrator_large() {
        let num_parties = 5;
        let threshold = 1;
        let num_sessions = 5_u128;

        //Each batch is 100 long
        let batch_size = 100;

        //Want 1k, so each session needs running twice (5 sessions, each batch is 100)
        let num_triples = 1000;

        let (identities, orchestrators) = test_orchestrator_large(
            num_sessions,
            num_triples,
            batch_size,
            num_parties,
            threshold,
            TypeOrchestration::Triples,
        );

        let mut triples_preproc = orchestrators
            .into_iter()
            .map(|orchestrator| {
                Arc::into_inner(orchestrator.base_preproc)
                    .unwrap()
                    .into_inner()
                    .unwrap()
            })
            .collect_vec();

        check_triples_reconstruction(
            &mut triples_preproc,
            &identities,
            num_triples,
            threshold as usize,
        );
    }

    #[test]
    fn test_bit_orchestrator_large() {
        let num_parties = 5;
        let threshold = 1;
        let num_sessions = 5_u128;

        //Each batch is 100 long
        let batch_size = 100;

        //Want 1k, so each session needs running twice (5 sessions, each batch is 100)
        let num_bits = 1000;

        let (identities, orchestrators) = test_orchestrator_large(
            num_sessions,
            num_bits,
            batch_size,
            num_parties,
            threshold,
            TypeOrchestration::Bits,
        );

        let mut bit_preprocs = orchestrators
            .into_iter()
            .map(|orchestrator| {
                Arc::into_inner(orchestrator.bit_preproc)
                    .unwrap()
                    .into_inner()
                    .unwrap()
            })
            .collect_vec();

        check_bits_reconstruction(&mut bit_preprocs, &identities, num_bits, threshold as usize);
    }

    #[test]
    fn test_random_orchestrator_large() {
        let num_parties = 5;
        let threshold = 1;
        let num_sessions = 5_u128;

        //Each batch is 100 long
        let batch_size = 100;

        //Want 1k, so each session needs running twice (5 sessions, each batch is 100)
        let num_randomness = 1000;

        let (identities, orchestrators) = test_orchestrator_large(
            num_sessions,
            num_randomness,
            batch_size,
            num_parties,
            threshold,
            TypeOrchestration::Randoms,
        );

        let mut random_preprocs = orchestrators
            .into_iter()
            .map(|orchestrator| {
                Arc::into_inner(orchestrator.base_preproc)
                    .unwrap()
                    .into_inner()
                    .unwrap()
            })
            .collect_vec();

        check_randomness_reconstruction(
            &mut random_preprocs,
            &identities,
            num_randomness,
            threshold as usize,
        );
    }

    fn test_orchestrator_small(
        num_sessions: u128,
        num_correlations: usize,
        batch_size: usize,
        num_parties: usize,
        threshold: u8,
        type_orchestration: TypeOrchestration,
    ) -> (Vec<Identity>, Vec<PreprocessingOrchestrator<ResiduePoly64>>) {
        //Create identities and runtime
        let identities = generate_fixed_identities(num_parties);
        let runtimes = (0..num_sessions)
            .map(|_| (DistributedTestRuntime::<ResiduePoly64>::new(identities.clone(), threshold)))
            .collect_vec();
        let runtimes = Arc::new(runtimes);

        let mut threads = Vec::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        for party_id in 0..num_parties {
            let runtimes = runtimes.clone();
            let rt_handle = rt.handle().clone();
            threads.push(thread::spawn(move || {
                let _guard = rt_handle.enter();
                println!("Thread created for {party_id}");

                //For test runtime we need multiple runtimes for mutltiple channels

                //For each party, create num_sessions sessions
                let mut sessions = runtimes
                    .iter()
                    .zip(0..num_sessions)
                    .map(|(runtime, session_id)| {
                        runtime.small_session_for_party(SessionId(session_id), party_id, None)
                    })
                    .collect_vec();

                let mut inmemory_factory = create_memory_factory();

                //DKGParams just for being able to call new (no SNS for ResiduePoly64)
                let params = PARAMS_P8_SMALL_NO_SNS;

                let orchestrator = PreprocessingOrchestrator::<ResiduePoly64>::new(
                    inmemory_factory.as_mut(),
                    params,
                )
                .unwrap();
                orchestrator
                    .orchestrate_small_session_processing(
                        batch_size,
                        num_correlations,
                        type_orchestration,
                        &mut sessions,
                        rt_handle.clone(),
                    )
                    .unwrap();
                orchestrator
            }));
        }

        let mut orchestrators = Vec::new();
        for thread in threads {
            orchestrators.push(thread.join().unwrap());
        }

        (identities, orchestrators)
    }

    #[test]
    fn test_triple_orchestrator_small() {
        let num_parties = 5;
        let threshold = 1;
        let num_sessions = 5_u128;

        //Each batch is 100 long
        let batch_size = 100;

        //Want 1k, so each session needs running twice (5 sessions, each batch is 100)
        let num_triples = 1000;

        let (identities, orchestrators) = test_orchestrator_small(
            num_sessions,
            num_triples,
            batch_size,
            num_parties,
            threshold,
            TypeOrchestration::Triples,
        );

        let mut triple_preprocs = orchestrators
            .into_iter()
            .map(|orchestrator| {
                Arc::into_inner(orchestrator.base_preproc)
                    .unwrap()
                    .into_inner()
                    .unwrap()
            })
            .collect_vec();

        check_triples_reconstruction(
            &mut triple_preprocs,
            &identities,
            num_triples,
            threshold as usize,
        );
    }

    #[test]
    fn test_bit_orchestrator_small() {
        let num_parties = 5;
        let threshold = 1;
        let num_sessions = 5_u128;

        //Each batch is 100 long
        let batch_size = 100;

        //Want 1k, so each session needs running twice (5 sessions, each batch is 100)
        let num_bits = 1000;

        let (identities, orchestrators) = test_orchestrator_small(
            num_sessions,
            num_bits,
            batch_size,
            num_parties,
            threshold,
            TypeOrchestration::Bits,
        );

        let mut bit_preprocs = orchestrators
            .into_iter()
            .map(|orchestrator| {
                Arc::into_inner(orchestrator.bit_preproc)
                    .unwrap()
                    .into_inner()
                    .unwrap()
            })
            .collect_vec();

        check_bits_reconstruction(&mut bit_preprocs, &identities, num_bits, threshold as usize);
    }

    #[test]
    fn test_randomness_orchestrator_small() {
        let num_parties = 5;
        let threshold = 1;
        let num_sessions = 5_u128;

        //Each batch is 100 long
        let batch_size = 100;

        //Want 1k, so each session needs running twice (5 sessions, each batch is 100)
        let num_randomness = 1000;

        let (identities, orchestrators) = test_orchestrator_small(
            num_sessions,
            num_randomness,
            batch_size,
            num_parties,
            threshold,
            TypeOrchestration::Randoms,
        );

        let mut random_preprocs = orchestrators
            .into_iter()
            .map(|orchestrator| {
                Arc::into_inner(orchestrator.base_preproc)
                    .unwrap()
                    .into_inner()
                    .unwrap()
            })
            .collect_vec();

        check_randomness_reconstruction(
            &mut random_preprocs,
            &identities,
            num_randomness,
            threshold as usize,
        );
    }
}
