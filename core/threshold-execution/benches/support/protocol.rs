use aes_prng::AesRng;
use algebra::{
    PRSSConversions,
    structure_traits::{ErrorCorrect, Invert},
};
use rand::SeedableRng;
use threshold_execution::{
    config::BatchParams,
    online::preprocessing::TriplePreprocessing,
    runtime::{
        sessions::small_session::SmallSession,
        test_runtime::{DistributedTestRuntime, generate_fixed_roles},
    },
    small_execution::{
        agree_random::DummyAgreeRandom,
        offline::{Preprocessing, SecureSmallPreprocessing},
        prss::{AbortRealPrssInit, DerivePRSSState, PRSSInit, PRSSSetup},
    },
};
use threshold_types::{network::NetworkMode, role::Role, session_id::SessionId};

/// Keeps epoch PRSS setup outside timing; each request receives a fresh session and counter domain.
pub struct ProtocolSetup<Z: ErrorCorrect> {
    runtime: DistributedTestRuntime<Z, Role, 4>,
    setups: Vec<(Role, PRSSSetup<Z>)>,
    next_session_id: u128,
}

impl<Z: ErrorCorrect + Invert + PRSSConversions> ProtocolSetup<Z> {
    /// Creates consistent PRSS setups with the test runtime's deterministic seed agreement.
    pub fn new(rt: &tokio::runtime::Runtime, parties: usize, threshold: u8) -> Self {
        let runtime = DistributedTestRuntime::new(
            generate_fixed_roles(parties),
            threshold,
            NetworkMode::Sync,
            None,
        );
        let setups = (1..=parties)
            .map(|party| {
                let role = Role::indexed_from_one(party);
                let mut session = runtime.base_session_for_party(
                    SessionId::from(1),
                    role,
                    Some(AesRng::seed_from_u64(party as u64)),
                );
                let setup = rt
                    .block_on(AbortRealPrssInit::<DummyAgreeRandom>::default().init(&mut session))
                    .unwrap();
                (role, setup)
            })
            .collect();
        Self {
            runtime,
            setups,
            next_session_id: 2,
        }
    }

    /// Prepares one request across all parties, outside the timed protocol execution.
    pub fn sessions(&mut self) -> Vec<SmallSession<Z>> {
        let sid = SessionId::from(self.next_session_id);
        self.next_session_id += 1;
        self.setups
            .iter()
            .map(|(role, setup)| {
                SmallSession::new_from_prss_state(
                    self.runtime.base_session_for_party(sid, *role, None),
                    setup.new_prss_session_state(sid, *role).unwrap(),
                )
                .unwrap()
            })
            .collect()
    }
}

/// Runs one complete triple batch on every party and propagates task failures.
pub async fn preprocess<Z: ErrorCorrect + Invert + PRSSConversions>(
    sessions: Vec<SmallSession<Z>>,
    amount: usize,
) {
    let parties = sessions.len();
    let mut tasks = tokio::task::JoinSet::new();
    for mut session in sessions {
        tasks.spawn(async move {
            let result = SecureSmallPreprocessing::default()
                .execute(
                    &mut session,
                    BatchParams {
                        triples: amount,
                        randoms: 0,
                    },
                )
                .await
                .unwrap();
            assert_eq!(result.triples_len(), amount);
            std::hint::black_box(result);
        });
    }
    let mut completed = 0;
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
        completed += 1;
    }
    assert_eq!(completed, parties);
}
