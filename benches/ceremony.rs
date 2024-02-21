use std::{collections::HashMap, sync::Arc};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use distributed_decryption::{
    algebra::residue_poly::ResiduePoly64,
    computation::SessionId,
    execution::{
        runtime::{
            session::{ParameterHandles, SmallSession64},
            test_runtime::{generate_fixed_identities, DistributedTestRuntime},
        },
        zk::ceremony::{Ceremony, RealCeremony},
    },
};
use itertools::Itertools;
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
                let runtime: DistributedTestRuntime<ResiduePoly64> =
                    DistributedTestRuntime::new(identities, threshold as u8);

                let session_id = SessionId(2);
                let rt = tokio::runtime::Runtime::new().unwrap();
                let _guard = rt.enter();

                b.iter(|| {
                    let mut set = JoinSet::new();
                    for (index_id, identity) in runtime.identities.clone().into_iter().enumerate() {
                        let role_assignments = runtime.role_assignments.clone();
                        let net = Arc::clone(&runtime.user_nets[index_id]);
                        let threshold = runtime.threshold;

                        let dim = *dim;
                        set.spawn(async move {
                            let mut session = SmallSession64::new(
                                session_id,
                                role_assignments,
                                net,
                                threshold,
                                None,
                                identity,
                                None,
                            )
                            .unwrap();

                            let real_ceremony = RealCeremony::default();
                            let out = real_ceremony
                                .execute::<ResiduePoly64, _, _>(&mut session, dim)
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
