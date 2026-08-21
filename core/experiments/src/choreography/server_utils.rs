use std::io::Write;
use std::time::Duration;

#[cfg(feature = "measure_memory")]
use crate::allocator::MEM_ALLOCATOR;
use aes_prng::AesRng;
use algebra::structure_traits::{ErrorCorrect, Invert};
use futures_util::future::{join_all, try_join_all};
use itertools::Itertools;
use rand::RngCore;
use threshold_execution::malicious_execution::runtime::malicious_session::GenericSmallSessionStruct;
use threshold_execution::runtime::sessions::base_session::{BaseSession, BaseSessionHandles};
use threshold_execution::runtime::sessions::session_parameters::GenericParameterHandles;
use threshold_execution::small_execution::prf::PRSSConversions;
use threshold_execution::small_execution::prss::DerivePRSSState;
use threshold_types::session_id::SessionId;

/// Fills tracing span fields with aggregate network and memory stats for multiple parallel sessions:
/// - total number of sessions
/// - max number of rounds across all sessions
/// - total number of bytes sent across all sessions
/// - total number of bytes received across all sessions
/// - peak memory usage in bytes as given by the custom allocator
pub async fn fill_network_memory_info_multiple_sessions<B: BaseSessionHandles>(
    sessions: Vec<B>,
    duration: Option<Duration>,
) {
    let span = tracing::Span::current();
    // Take the max number of rounds across all sessions
    // (as they ran in parallel the sum isn't really a good measure)
    let num_rounds_per_session = join_all(
        sessions
            .iter()
            .map(|session| session.network().get_current_round()),
    )
    .await;
    let num_rounds_per_session = sessions
        .iter()
        .zip(num_rounds_per_session)
        .filter(|(_, rounds)| *rounds > 0)
        .collect_vec();
    let num_rounds = num_rounds_per_session
        .iter()
        .fold(0, |cur_max, (_, rounds)| cur_max.max(*rounds));

    span.record("total_num_sessions", sessions.len());
    span.record("network_round", num_rounds);

    let total_num_byte_sent = join_all(
        num_rounds_per_session
            .iter()
            .map(|(session, _)| session.network().get_num_byte_sent()),
    )
    .await
    .iter()
    .sum::<usize>();

    let total_num_byte_received = try_join_all(
        num_rounds_per_session
            .iter()
            .map(|(session, _)| session.network().get_num_byte_received()),
    )
    .await
    .unwrap()
    .iter()
    .sum::<usize>();

    span.record("network_sent", total_num_byte_sent);
    span.record("network_received", total_num_byte_received);

    #[cfg(feature = "measure_memory")]
    span.record("peak_mem", MEM_ALLOCATOR.get().unwrap().peak_usage());

    // Write to file (as it's much easier to parse than tracing logs)
    // but contains a bit less info (doesn't have exact params etc for example)
    let role = sessions[0].my_role();
    let file_name = format!("session_stats/session_stats_{role}.txt");
    let stats_line = format!(
        "\nname={},role={},num_sessions={},num_rounds={},network_sent(B)={},network_received(B)={},time_active(ms)={}",
        span.metadata()
            .map(|m| m.name())
            .unwrap_or("unknown_span_name"),
        role,
        sessions.len(),
        num_rounds,
        total_num_byte_sent,
        total_num_byte_received,
        duration.map(|d| d.as_millis()).unwrap_or(0),
    );
    #[cfg(feature = "measure_memory")]
    let stats_line = format!(
        "{},peak_mem(B)={}",
        stats_line,
        MEM_ALLOCATOR.get().unwrap().peak_usage()
    );

    if let Some(parent) = std::path::Path::new(&file_name).parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        tracing::error!(
            "Can't write stats. Failed to create directory {}: {}",
            parent.display(),
            e
        );
        return;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_name)
        .unwrap()
        .write_all(stats_line.as_bytes())
        .unwrap();
}

pub async fn fill_network_memory_info_single_session<B: BaseSessionHandles>(
    session: B,
    duration: Option<Duration>,
) {
    fill_network_memory_info_multiple_sessions(vec![session], duration).await;
}

/// Fills up the 96 MSBs with randomness and fills the 32 LSBs with the given sid
/// (so it's easier to find "real" sid by looking at bin rep)
pub fn gen_random_sid(rng: &mut AesRng, current_sid: u128) -> SessionId {
    SessionId::from(
        ((rng.next_u64() as u128) << 64)
            | ((rng.next_u32() as u128) << 32)
            | (current_sid & 0xFFFF_FFFF),
    )
}

pub fn create_small_sessions<
    Z: ErrorCorrect + Invert + PRSSConversions,
    PRSSSetupType: DerivePRSSState<Z>,
>(
    base_sessions: Vec<BaseSession>,
    prss_setup: &PRSSSetupType,
) -> Vec<GenericSmallSessionStruct<Z, PRSSSetupType::OutputType>> {
    base_sessions
        .into_iter()
        .map(|base_session| {
            let prss_state = prss_setup.new_prss_session_state(base_session.session_id());
            GenericSmallSessionStruct::new_from_prss_state(base_session, prss_state).unwrap()
        })
        .collect_vec()
}
