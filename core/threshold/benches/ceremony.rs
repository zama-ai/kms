use std::collections::HashMap;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use itertools::Itertools;
use threshold_fhe::{
    algebra::{galois_rings::degree_8::ResiduePolyF8Z64, structure_traits::Ring},
    execution::{
        runtime::{
            session::ParameterHandles,
            test_runtime::{generate_fixed_identities, DistributedTestRuntime},
        },
        zk::ceremony::{Ceremony, RealCeremony},
    },
    networking::NetworkMode,
    session_id::SessionId,
};
use tokio::task::JoinSet;

// This benchmark performs two-party CRS ceremony.
// This should be the time that the CRS ceremony takes for two rounds
// since party0 will update the CRS and party1 will verify, then
// party1 will update the CRS and party0 will verify.
fn bench_ceremony(c: &mut Criterion) {
    let mut group = c.benchmark_group("crs ceremony");
    group.sample_size(10);

    let threshold = 0usize;
    let num_parties = 2usize;
    for witness_dim in [10, 100, 57249] {
        group.bench_with_input(
            BenchmarkId::from_parameter(witness_dim),
            &witness_dim,
            |b, dim| {
                let identities = generate_fixed_identities(num_parties);
                //CRS generation requires sync network
                let runtime: DistributedTestRuntime<
                    ResiduePolyF8Z64,
                    { ResiduePolyF8Z64::EXTENSION_DEGREE },
                > = DistributedTestRuntime::new(
                    identities,
                    threshold as u8,
                    NetworkMode::Sync,
                    None,
                );

                let session_id = SessionId(2);
                let rt = tokio::runtime::Runtime::new().unwrap();
                let _guard = rt.enter();

                b.iter(|| {
                    let mut set = JoinSet::new();
                    for (index_id, _identity) in runtime.identities.clone().into_iter().enumerate()
                    {
                        let dim = *dim;
                        let mut session =
                            runtime.small_session_for_party(session_id, index_id, None);
                        set.spawn(async move {
                            let real_ceremony = RealCeremony::default();
                            let out = real_ceremony
                                .execute::<ResiduePolyF8Z64, _, _>(&mut session, dim, None)
                                .await
                                .unwrap();
                            (session.my_role().unwrap(), out)
                        });
                    }

                    let results = rt
                        .block_on(async {
                            let mut results = HashMap::new();
                            while let Some(v) = set.join_next().await {
                                let (role, pp) = v.unwrap();
                                results.insert(role, pp);
                            }
                            results
                        })
                        .into_iter()
                        .collect_vec();
                    let buf = bincode::serialize(&results[0].1).unwrap();
                    tracing::info!("crs bytes: {}", buf.len());
                });
            },
        );
    }
    group.finish()
}

criterion_group!(ceremony, bench_ceremony);
criterion_main!(ceremony);
