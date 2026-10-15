//! Before/after benchmark of the local partial decryption `b - <a, s>` of noise-flooding decryption.
//!
//! The inner product of the ciphertext masks with the SnS key share goes through
//! `algebra::lincomb::LinearCombinator` with the key share prepared once: blocks of a request go into lanes (16
//! or 8 per group), single blocks put eight key coefficients per lane. Three series are measured on synthetic
//! material of production dimensions (random key share and ciphertexts; the arithmetic does not depend on the
//! values):
//!
//! * `fold`: the previous implementation, one `ResiduePoly * Z128` and one addition per key coefficient.
//! * `Scalar`: the combinator's scalar backend (the same arithmetic as the fold, through the new code path).
//! * `Avx512Ifma`: the IFMA backend, when the CPU has `avx512ifma`.
//!
//! The backend series follows `MPC_LINCOMB_BACKEND` like the other benchmarks, so one run on an AVX-512 machine
//! shows `fold` and `Avx512Ifma`, and `MPC_LINCOMB_BACKEND=scalar` shows `fold` and `Scalar`:
//!
//! ```text
//! cargo bench -p threshold-execution -F testing --bench ddec_lincomb
//! MPC_LINCOMB_BACKEND=scalar cargo bench -p threshold-execution -F testing --bench ddec_lincomb
//! ```
//!
//! Block counts: 1 (bool, euint4), 2 (euint8), 8 (euint32), 16 (euint64), 64 (euint256) packed blocks; the key
//! dimensions are those of `BC_PARAMS_SNS` (4096 for the SnS key, 6144 for the SnS compression key). Times are
//! for one call on the calling thread, groups of 16 blocks in parallel on Rayon, as in the request path.

use algebra::base_ring::Z128;
use algebra::galois_rings::common::ResiduePoly;
use algebra::lincomb::LinearCombinator;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::SeedableRng;
use std::hint::black_box;
use threshold_execution::endpoints::decryption::{
    PreparedSnsKeys, SnsDecryptionKeyType, masked_partial_decrypt_with, synthetic,
};
use threshold_execution::tfhe_internals::parameters::BC_PARAMS_SNS;
use threshold_types::rng::AesRng;

const BLOCKS: [usize; 5] = [1, 2, 8, 16, 64];

fn bench_key(c: &mut Criterion, key_type: SnsDecryptionKeyType, name: &str, lwe_dimension: usize) {
    let mut rng = AesRng::seed_from_u64(0);
    let key_set = synthetic::private_key_set::<4>(&mut rng, BC_PARAMS_SNS, lwe_dimension);
    let key_share = match key_type {
        SnsDecryptionKeyType::SnsKey => &key_set.glwe_secret_key_share_sns_as_lwe,
        SnsDecryptionKeyType::SnsCompressionKey => &key_set.glwe_sns_compression_key_as_lwe,
    }
    .as_ref()
    .unwrap();
    let prepared = PreparedSnsKeys::prepare(&key_set).key(key_type).unwrap();
    let backend = format!("{:?}", prepared.backend());

    let mut group = c.benchmark_group(format!("partial_decrypt128/{name}_dim{lwe_dimension}"));
    for blocks in BLOCKS {
        let ct = synthetic::squashed_radix_ciphertext(&mut rng, blocks, lwe_dimension);
        let masks: Vec<ResiduePoly<Z128, 4>> = vec![ResiduePoly::default(); blocks];
        group.throughput(Throughput::Elements(blocks as u64));
        group.bench_with_input(BenchmarkId::new("fold", blocks), &blocks, |b, _| {
            b.iter(|| {
                let out: Vec<_> = ct
                    .packed_blocks()
                    .zip(&masks)
                    .map(|(block, mask)| {
                        synthetic::partial_decrypt128_fold(key_share, block) + *mask
                    })
                    .collect();
                black_box(out);
            });
        });
        group.bench_with_input(BenchmarkId::new(&backend, blocks), &blocks, |b, _| {
            b.iter(|| {
                let out = masked_partial_decrypt_with(&prepared, &ct, masks.clone()).unwrap();
                black_box(out);
            });
        });
    }
    group.finish();
}

fn bench_ddec_lincomb(c: &mut Criterion) {
    println!(
        "lincomb backend for ResiduePolyF4Z128: {:?} (set MPC_LINCOMB_BACKEND=scalar|ifma to force)",
        LinearCombinator::<algebra::galois_rings::degree_4::ResiduePolyF4Z128>::detected_backend()
    );
    // GLWE dimension 2 x N 2048 and packing-KS GLWE dimension 6 x N 1024 of BC_PARAMS_SNS.
    bench_key(c, SnsDecryptionKeyType::SnsKey, "sns_key", 4096);
    bench_key(
        c,
        SnsDecryptionKeyType::SnsCompressionKey,
        "sns_compression_key",
        6144,
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_ddec_lincomb
}
criterion_main!(benches);
