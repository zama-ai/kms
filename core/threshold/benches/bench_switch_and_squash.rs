use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use tfhe::{set_server_key, FheUint16, FheUint2, FheUint32, FheUint64, FheUint8};
use threshold_fhe::execution::{
    random::get_rng,
    tfhe_internals::{
        parameters::{DKGParams, BC_PARAMS_SNS},
        test_feature::gen_key_set,
        utils::expanded_encrypt,
    },
};

fn bench_switch_and_squash(c: &mut Criterion) {
    let mut group = c.benchmark_group("switch_and_squash");
    group.sample_size(10);

    let params: DKGParams = BC_PARAMS_SNS;
    let keyset = gen_key_set(params, tfhe::Tag::default(), &mut get_rng());
    set_server_key(keyset.public_keys.server_key.clone());

    let public_key = bc2wrap::serialize(&(keyset.public_keys.public_key)).unwrap();
    let server_key = bc2wrap::serialize(&(keyset.public_keys.server_key)).unwrap();
    let conversion_key =
        bc2wrap::serialize(keyset.public_keys.server_key.noise_squashing_key().unwrap()).unwrap();
    let client_key = bc2wrap::serialize(&(keyset.client_key)).unwrap();

    println!(
        "key sizes (kiB, serialized): public key={}  client key={}  server key={} conversion key={}",
        public_key.len() / 1024,
        client_key.len() / 1024,
        server_key.len() / 1024,
        conversion_key.len() / 1024
    );

    // generate ciphertexts to be used in benchmarks
    let msg8 = 5_u8;
    let msg16 = 5_u16;
    let msg32 = 5_u32;
    let msg64 = 5_u64;

    let ct2: FheUint2 = expanded_encrypt(&keyset.public_keys.public_key, msg8, 2).unwrap();
    let ct8: FheUint8 = expanded_encrypt(&keyset.public_keys.public_key, msg8, 8).unwrap();
    let ct16: FheUint16 = expanded_encrypt(&keyset.public_keys.public_key, msg16, 16).unwrap();
    let ct32: FheUint32 = expanded_encrypt(&keyset.public_keys.public_key, msg32, 32).unwrap();
    let ct64: FheUint64 = expanded_encrypt(&keyset.public_keys.public_key, msg64, 64).unwrap();

    // benchmark s&s for the blocks that make up a u2
    group.bench_function(BenchmarkId::new("s&s", "u2"), |b| {
        b.iter(|| {
            let (raw_ct, _id, _tag, _rerand_metadata) = ct2.clone().into_raw_parts();
            let server_key = keyset.public_keys.server_key.as_ref();
            let sns_key = keyset.public_keys.server_key.noise_squashing_key().unwrap();
            let _ = black_box(sns_key.squash_radix_ciphertext_noise(server_key, &raw_ct));
        });
    });

    // benchmark s&s for the blocks that make up a u8
    group.bench_function(BenchmarkId::new("s&s", "u8"), |b| {
        b.iter(|| {
            let (raw_ct, _id, _tag, _rerand_metadata) = ct8.clone().into_raw_parts();
            let server_key = keyset.public_keys.server_key.as_ref();
            let sns_key = keyset.public_keys.server_key.noise_squashing_key().unwrap();
            let _ = black_box(sns_key.squash_radix_ciphertext_noise(server_key, &raw_ct));
        });
    });

    // benchmark s&s for the blocks that make up a u16
    group.bench_function(BenchmarkId::new("s&s", "u16"), |b| {
        b.iter(|| {
            let (raw_ct, _id, _tag, _rerand_metadata) = ct16.clone().into_raw_parts();
            let server_key = keyset.public_keys.server_key.as_ref();
            let sns_key = keyset.public_keys.server_key.noise_squashing_key().unwrap();
            let _ = black_box(sns_key.squash_radix_ciphertext_noise(server_key, &raw_ct));
        });
    });

    // benchmark s&s for the blocks that make up a u32
    group.bench_function(BenchmarkId::new("s&s", "u32"), |b| {
        b.iter(|| {
            let (raw_ct, _id, _tag, _rerand_metadata) = ct32.clone().into_raw_parts();
            let server_key = keyset.public_keys.server_key.as_ref();
            let sns_key = keyset.public_keys.server_key.noise_squashing_key().unwrap();
            let _ = black_box(sns_key.squash_radix_ciphertext_noise(server_key, &raw_ct));
        });
    });

    // benchmark s&s for the blocks that make up a u64
    group.bench_function(BenchmarkId::new("s&s", "u64"), |b| {
        b.iter(|| {
            let (raw_ct, _id, _tag, _rerand_metadata) = ct64.clone().into_raw_parts();
            let server_key = keyset.public_keys.server_key.as_ref();
            let sns_key = keyset.public_keys.server_key.noise_squashing_key().unwrap();
            let _ = black_box(sns_key.squash_radix_ciphertext_noise(server_key, &raw_ct));
        });
    });
}

criterion_group!(switch_and_squash, bench_switch_and_squash);
criterion_main!(switch_and_squash);
