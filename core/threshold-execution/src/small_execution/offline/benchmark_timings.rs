use std::time::{Duration, Instant};

use algebra::structure_traits::Ring;

use crate::runtime::sessions::base_session::BaseSessionHandles;

// Opt-in attribution for the local stage probe. Ordinary benchmarks have no subscriber for this target.
pub(super) struct StageTimings {
    last: Option<Instant>,
    stages: Vec<(&'static str, Duration)>,
}

impl StageTimings {
    pub(super) fn new() -> Self {
        let enabled = tracing::enabled!(target: "prss_bench_stages", tracing::Level::INFO);
        Self {
            stages: if enabled {
                Vec::with_capacity(6)
            } else {
                Vec::new()
            },
            last: enabled.then(Instant::now),
        }
    }

    pub(super) fn finish_stage(&mut self, stage: &'static str) {
        if let Some(last) = self.last {
            let now = Instant::now();
            self.stages.push((stage, now.duration_since(last)));
            self.last = Some(now);
        }
    }

    pub(super) fn emit<Z: Ring>(&self, session: &impl BaseSessionHandles, amount: usize) {
        // Emit only after all stages finish so formatting is outside this party's measured stages.
        for &(stage, elapsed) in &self.stages {
            tracing::info!(target: "prss_bench_stages",
                ring_bits = Z::CHAR_LOG2, extension_degree = Z::EXTENSION_DEGREE,
                parties = session.num_parties(), threshold = session.threshold(),
                party = session.my_role().one_based(), sid = ?session.session_id(),
                triples = amount, stage, elapsed_ns = elapsed.as_nanos() as u64,
            );
        }
    }
}
