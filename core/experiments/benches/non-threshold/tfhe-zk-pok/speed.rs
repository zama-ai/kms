#![allow(clippy::unit_arg)]
//! Speed benchmarks for ZK proof-of-knowledge operations.
//!
//! Measures wall-clock time for:
//!   - CRS generation
//!   - Proof generation  (CRS pre-computed)
//!   - Proof verification in TwoSteps mode (proof pre-computed)
//!   - Proof verification in Batched mode  (proof pre-computed)
//!
//! Run with:
//!   cargo bench --bench non-threshold_tfhe-zk-pok_speed

#[path = "../utilities.rs"]
mod utilities;

use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion};
use experiments::zk_utils::{
    nist_gen_crs, nist_gen_crs_from_params, nist_gen_proof, nist_gen_proof_inputs,
    nist_pke_params_from_dkg, nist_seeded_rng, nist_verify_batched, nist_verify_two_steps,
};
use threshold_execution::tfhe_internals::parameters::DKGParams;
use utilities::ALL_PARAMS;

/// Benchmark CRS generation.
fn bench_crs_gen(group: &mut BenchmarkGroup<'_, WallTime>, params: DKGParams) {
    let pke_params = nist_pke_params_from_dkg(params);

    group.bench_function("crs_gen", |b| {
        b.iter(|| {
            let mut rng = nist_seeded_rng(*b"BENCHCRS");
            std::hint::black_box(nist_gen_crs_from_params(&pke_params, &mut rng));
        });
    });
}

/// Benchmark proof generation.
/// The CRS and commits are pre-computed outside the timed region.
fn bench_proof_gen(group: &mut BenchmarkGroup<'_, WallTime>, params: DKGParams) {
    let crs = nist_gen_crs(params);
    let (public_commit, private_commit, metadata) = nist_gen_proof_inputs(&crs, params);

    group.bench_function("load_verify_proof_gen", |b| {
        b.iter(|| {
            std::hint::black_box(nist_gen_proof(
                &crs,
                &public_commit,
                &private_commit,
                &metadata,
                tfhe::zk::ZkComputeLoad::Verify,
            ));
        });
    });

    group.bench_function("load_proof_proof_gen", |b| {
        b.iter(|| {
            std::hint::black_box(nist_gen_proof(
                &crs,
                &public_commit,
                &private_commit,
                &metadata,
                tfhe::zk::ZkComputeLoad::Proof,
            ));
        });
    });
}

/// Benchmark proof verification in TwoSteps pairing mode.
/// The CRS, commits, and proof are all pre-computed outside the timed region.
fn bench_verify_two_steps(group: &mut BenchmarkGroup<'_, WallTime>, params: DKGParams) {
    let crs = nist_gen_crs(params);
    let (public_commit, private_commit, metadata) = nist_gen_proof_inputs(&crs, params);
    let proof = nist_gen_proof(
        &crs,
        &public_commit,
        &private_commit,
        &metadata,
        tfhe::zk::ZkComputeLoad::Verify,
    );

    group.bench_function("load_verify_verify_two_steps", |b| {
        b.iter(|| {
            std::hint::black_box(
                nist_verify_two_steps(&proof, &crs, &public_commit, &metadata).unwrap(),
            );
        });
    });

    let proof = nist_gen_proof(
        &crs,
        &public_commit,
        &private_commit,
        &metadata,
        tfhe::zk::ZkComputeLoad::Proof,
    );

    group.bench_function("load_proof_verify_two_steps", |b| {
        b.iter(|| {
            std::hint::black_box(
                nist_verify_two_steps(&proof, &crs, &public_commit, &metadata).unwrap(),
            );
        });
    });
}

/// Benchmark proof verification in Batched pairing mode.
/// The CRS, commits, and proof are all pre-computed outside the timed region.
fn bench_verify_batched(group: &mut BenchmarkGroup<'_, WallTime>, params: DKGParams) {
    let crs = nist_gen_crs(params);
    let (public_commit, private_commit, metadata) = nist_gen_proof_inputs(&crs, params);
    let proof = nist_gen_proof(
        &crs,
        &public_commit,
        &private_commit,
        &metadata,
        tfhe::zk::ZkComputeLoad::Proof,
    );

    group.bench_function("load_proof_verify_batched", |b| {
        b.iter(|| {
            std::hint::black_box(
                nist_verify_batched(&proof, &crs, &public_commit, &metadata).unwrap(),
            );
        });
    });

    let proof = nist_gen_proof(
        &crs,
        &public_commit,
        &private_commit,
        &metadata,
        tfhe::zk::ZkComputeLoad::Verify,
    );

    group.bench_function("load_verify_verify_batched", |b| {
        b.iter(|| {
            std::hint::black_box(
                nist_verify_batched(&proof, &crs, &public_commit, &metadata).unwrap(),
            );
        });
    });
}

fn main() {
    for (params_name, params) in ALL_PARAMS {
        let bench_name = format!("non-threshold_zk-pok_{params_name}");
        let mut c = Criterion::default().sample_size(10).configure_from_args();

        {
            let mut group = c.benchmark_group(&bench_name);

            bench_crs_gen(&mut group, params);
            bench_proof_gen(&mut group, params);
            bench_verify_two_steps(&mut group, params);
            bench_verify_batched(&mut group, params);

            group.finish();
        }

        c.final_summary();
    }
}
