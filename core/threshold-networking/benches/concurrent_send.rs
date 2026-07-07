//! Concurrent `NetworkSession::send` benchmark.
//!
//! Several tasks call `send` on one shared session at once. `send` touches only
//! one migrated field — `num_byte_sent` — so this is where the `RwLock` -> atomic
//! change can matter under contention: the old `RwLock<usize>` write lock forces
//! concurrent senders to serialize (and, under tokio, to yield to the scheduler),
//! whereas `AtomicUsize::fetch_add` lets them proceed lock-free.
//!
//! This benchmark deliberately depends only on the public `Networking::send` and
//! on `NetworkSession::new_for_bench` (whose migrated fields are constructed via
//! `Default::default()`), so it compiles and runs unchanged both on the current
//! atomic code and after `git revert e7ee8ba40` (the RwLock version). Run it in
//! each state and compare:
//!
//!   cargo bench -p threshold-networking --bench concurrent_send --features bench-internals
//!
//! Note: `send` is allocation-bound (tag serialization + two heap allocations),
//! so the counter is <1% of each call; expect the concurrency effect to be real
//! but modest compared to the isolated counter contention.

use std::sync::Arc;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use tokio::runtime::Builder;
use tokio::sync::mpsc::UnboundedReceiver;

use threshold_networking::sending_service::{ArcSendValueRequest, NetworkSession};
use threshold_types::network::{NetworkMode, Networking};
use threshold_types::party::{Identity, RoleAssignment};
use threshold_types::role::Role;
use threshold_types::session_id::SessionId;

/// The single peer every task sends to (so they contend on one channel + the
/// one `num_byte_sent`).
const PEER_ROLE: usize = 2;
/// Sends per task per measured iteration (amortizes task-spawn overhead).
const SENDS_PER_TASK: usize = 2_000;
/// Concurrency levels: 1 = no contention (baseline), then increasing contention.
const TASK_COUNTS: [usize; 3] = [1, 4, 8];
/// Payload size per send.
const VALUE_LEN: usize = 256;

/// Build one shared session (owner = party 1, peer = party 2) plus the peer's
/// receivers.
fn make_shared_session() -> (
    Arc<NetworkSession>,
    Vec<UnboundedReceiver<ArcSendValueRequest>>,
) {
    let owner = Identity::new("127.0.0.1".to_string(), 10001, None);
    let peer = Identity::new("127.0.0.1".to_string(), 10002, None);
    let mut others = RoleAssignment::default();
    others.insert(Role::indexed_from_one(PEER_ROLE), peer);
    let (session, receivers) =
        NetworkSession::new_for_bench(owner, SessionId::from(0), &others, NetworkMode::Sync);
    (Arc::new(session), receivers)
}

fn bench_concurrent_send(c: &mut Criterion) {
    let rt = Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .unwrap();
    let mut group = c.benchmark_group("NetworkSession/concurrent_send");

    for &tasks in &TASK_COUNTS {
        // One session shared across all iterations and all tasks. Drainers empty
        // the unbounded channels (as the real SendingService would) so they stay
        // bounded; the counter (`num_byte_sent`) grows across iterations, which is
        // harmless for both the atomic (wraps) and RwLock (`usize`) versions.
        let (session, receivers) = make_shared_session();
        let _drainers: Vec<_> = receivers
            .into_iter()
            .map(|mut rx| rt.spawn(async move { while rx.recv().await.is_some() {} }))
            .collect();
        let value = Arc::new(vec![0u8; VALUE_LEN]);

        group.throughput(Throughput::Elements((tasks * SENDS_PER_TASK) as u64));
        group.bench_function(format!("{tasks}tasks"), |b| {
            b.to_async(&rt).iter(|| {
                let session = Arc::clone(&session);
                let value = Arc::clone(&value);
                async move {
                    let mut handles = Vec::with_capacity(tasks);
                    for _ in 0..tasks {
                        let session = Arc::clone(&session);
                        let value = Arc::clone(&value);
                        handles.push(tokio::spawn(async move {
                            let peer = Role::indexed_from_one(PEER_ROLE);
                            for _ in 0..SENDS_PER_TASK {
                                <NetworkSession as Networking<Role>>::send(
                                    &session,
                                    Arc::clone(&value),
                                    &peer,
                                )
                                .await
                                .unwrap();
                            }
                        }));
                    }
                    for h in handles {
                        h.await.unwrap();
                    }
                }
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_concurrent_send);
criterion_main!(benches);
