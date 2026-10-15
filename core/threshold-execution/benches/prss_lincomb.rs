//! Before/after benchmark of the PRSS linear-combination backends on one branch, one binary.
//!
//! `PRSS.Next` is `sum_A f_A(alpha_i) * psi(r_A, cnt)`; the sum is evaluated by `algebra::lincomb::LinearCombinator`
//! with the backend auto-detected at session setup (AVX-512 IFMA on x86-64 CPUs with `avx512ifma`, scalar
//! otherwise). The backend can be forced with the `MPC_LINCOMB_BACKEND` environment variable, so the comparison
//! is two runs of the same binary:
//!
//! ```text
//! cargo bench -p threshold-execution -F testing --bench prss_lincomb                                # auto
//! MPC_LINCOMB_BACKEND=scalar cargo bench -p threshold-execution -F testing --bench prss_lincomb     # before
//! ```
//!
//! Criterion group names carry the backend, so both runs keep their own baselines under `target/criterion`.
//! Sizes: 16 is one counter group on one thread, 1_024 one Rayon task, 16_384 sixteen tasks (the Rayon split is
//! `MPC_PRSS_PAR_MIN_CHUNK`, default 1024 values per task). The backend only applies to rings with one AES
//! block per coefficient; today the fast path exists for `ResiduePolyF4Z128`, `ResiduePolyF4Z64` is listed for
//! reference and runs the scalar backend in both configurations.

use algebra::galois_rings::degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128};
use algebra::lincomb::LinearCombinator;
use algebra::structure_traits::{ErrorCorrect, Invert};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use threshold_execution::small_execution::prf::PRSSConversions;
use threshold_execution::small_execution::prss::{DerivePRSSState, PRSSPrimitives, PRSSSetup};
use threshold_types::role::Role;
use threshold_types::session_id::SessionId;

const SIZES: [usize; 3] = [16, 1_024, 16_384];
const PARTIES: [(usize, usize); 2] = [(7, 2), (13, 4)];

fn bench_ring<Z: ErrorCorrect + Invert + PRSSConversions>(
    c: &mut Criterion,
    rt: &tokio::runtime::Runtime,
    ring: &str,
    backend: &str,
) {
    let role = Role::indexed_from_one(1);
    let sid = SessionId::from(42);
    for (parties, threshold) in PARTIES {
        let setup = rt
            .block_on(PRSSSetup::<Z>::testing_party_epoch_init(
                parties, threshold, role,
            ))
            .unwrap();
        let mut state = setup.new_prss_session_state(sid, role).unwrap();
        let mut group = c.benchmark_group(format!(
            "prss_next/{backend}/{ring}/n{parties}_t{threshold}"
        ));
        for size in SIZES {
            group.throughput(Throughput::Elements(size as u64));
            group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
                b.iter(|| {
                    let shares = rt.block_on(state.prss_next_vec(role, size)).unwrap();
                    black_box(shares);
                });
            });
        }
        group.finish();
    }
}

fn bench_prss_lincomb(c: &mut Criterion) {
    let backend = format!(
        "{:?}",
        LinearCombinator::<ResiduePolyF4Z128>::detected_backend()
    );
    println!(
        "lincomb backend for ResiduePolyF4Z128: {backend} (set MPC_LINCOMB_BACKEND=scalar|ifma to force)"
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    bench_ring::<ResiduePolyF4Z128>(c, &rt, "F4Z128", &backend);
    bench_ring::<ResiduePolyF4Z64>(c, &rt, "F4Z64", &backend);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_prss_lincomb
}
criterion_main!(benches);
