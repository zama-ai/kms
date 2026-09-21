use aes_prng::AesRng;
use algebra::{
    PRSSConversions,
    structure_traits::{ErrorCorrect, Invert},
};
use rand::SeedableRng;
use std::sync::Arc;
use threshold_execution::{
    large_execution::vss::DummyVss,
    runtime::{
        sessions::{
            base_session::BaseSession,
            session_parameters::{GenericParameterHandles, SessionParameters},
        },
        test_runtime::generate_fixed_roles,
    },
    small_execution::{
        agree_random::DummyAgreeRandomFromShare,
        prss::{PRSSInit, PRSSPrimitives, PRSSSetup, RobustRealPrssInit, SecurePRSSState},
    },
};
use threshold_networking::local::LocalNetworkingProducer;
use threshold_types::{network::NetworkMode, role::Role, session_id::SessionId};

/// Initializes one party outside benchmark timing, with deterministic dummy setup protocols.
pub fn setup_prss<Z: ErrorCorrect + Invert + PRSSConversions>(
    rt: &tokio::runtime::Runtime,
    parties: usize,
    threshold: u8,
) -> PRSSSetup<Z> {
    let role = Role::indexed_from_one(1);
    let parameters = SessionParameters::new(
        threshold,
        SessionId::from(1),
        role,
        generate_fixed_roles(parties),
    )
    .unwrap();
    let producer = LocalNetworkingProducer::from_roles(parameters.roles());
    let mut session = BaseSession::new(
        parameters,
        Arc::new(producer.user_net(role, NetworkMode::Sync, None)),
        AesRng::seed_from_u64(42),
    )
    .unwrap();
    rt.block_on(async {
        RobustRealPrssInit::<DummyAgreeRandomFromShare, DummyVss>::default()
            .init(&mut session)
            .await
            .unwrap()
    })
}

#[derive(Clone, Copy)]
pub enum PrssWorkload {
    Prss,
    Przs,
    Mask,
    TripleInputs,
}

impl PrssWorkload {
    pub fn name(self) -> &'static str {
        match self {
            Self::Prss => "prss_next",
            Self::Przs => "przs_next",
            Self::Mask => "prss_mask_next",
            Self::TripleInputs => "triple_inputs",
        }
    }

    // Mask generation supports only Z128.
    pub fn for_ring<Z: ErrorCorrect>() -> impl Iterator<Item = Self> {
        [Self::Prss, Self::Przs, Self::Mask, Self::TripleInputs]
            .into_iter()
            .filter(|workload| !matches!(workload, Self::Mask) || Z::CHAR_LOG2 == 128)
    }

    // For triple inputs, request_size is the number of triples (three PRSS and one PRZS value each).
    pub fn output_value_count(self, request_size: usize) -> usize {
        if matches!(self, Self::TripleInputs) {
            4 * request_size
        } else {
            request_size
        }
    }

    /// Executes the PRSS workload and consumes its outputs with `black_box`. This is what we measure.
    /// `request_size` counts triples for `TripleInputs`, shares for all other workloads.
    /// Triple inputs contain three PRSS shares and one PRZS share per triple.
    pub async fn run<Z: ErrorCorrect + Invert + PRSSConversions>(
        self,
        prss_state: &mut SecurePRSSState<Z>,
        threshold: u8,
        request_size: usize,
    ) {
        let role = Role::indexed_from_one(1);
        match self {
            Self::Prss => {
                std::hint::black_box(prss_state.prss_next_vec(role, request_size).await.unwrap());
            }
            Self::Przs => {
                std::hint::black_box(
                    prss_state
                        .przs_next_vec(role, threshold, request_size)
                        .await
                        .unwrap(),
                );
            }
            Self::Mask => {
                std::hint::black_box(
                    prss_state
                        .mask_next_vec(role, 1 << 70, request_size)
                        .await
                        .unwrap(),
                );
            }
            Self::TripleInputs => {
                let prss = prss_state
                    .prss_next_vec(role, 3 * request_size)
                    .await
                    .unwrap();
                let przs = prss_state
                    .przs_next_vec(role, threshold, request_size)
                    .await
                    .unwrap();
                std::hint::black_box((prss, przs));
            }
        }
    }
}
