use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use tfhe::{set_server_key, FheUint16, FheUint8};
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
    let keyset = gen_key_set(params, &mut get_rng());

    let msg8 = 5_u8;
    let msg16 = 5_u16;

    set_server_key(keyset.public_keys.server_key.clone());

    let ct8: FheUint8 = expanded_encrypt(&keyset.public_keys.public_key, msg8, 8).unwrap();
    let ct16: FheUint16 = expanded_encrypt(&keyset.public_keys.public_key, msg16, 16).unwrap();
    let public_key = bincode::serialize(&(keyset.public_keys.public_key)).unwrap();
    let server_key = bincode::serialize(&(keyset.public_keys.server_key)).unwrap();
    let conversion_key = bincode::serialize(
        &(keyset
            .public_keys
            .server_key
            .clone()
            .into_raw_parts()
            .4
            .unwrap()),
    )
    .unwrap();
    let client_key = bincode::serialize(&(keyset.client_key)).unwrap();

    println!(
        "key sizes (kiB, serialized): public key={}  client key={}  server key={} conversion key={}",
        public_key.len() / 1024,
        client_key.len() / 1024,
        server_key.len() / 1024,
        conversion_key.len() / 1024
    );

    // benchmark s&s for a single ct block
    group.bench_function(BenchmarkId::new("s+s", "single_block"), |b| {
        b.iter(|| {
            let (raw_ct, _id, _tag) = ct8.clone().into_raw_parts();
            let server_key = keyset.public_keys.server_key.as_ref();
            let sns_key = keyset
                .public_keys
                .server_key
                .clone()
                .into_raw_parts()
                .4
                .unwrap();
            let _ = black_box(sns_key.squash_radix_ciphertext_noise(server_key, &raw_ct));
        });
    });

    // benchmark s&s for the blocks that make up a u8 sequentially
    group.bench_function(BenchmarkId::new("s+s", "u8_sequential"), |b| {
        b.iter(|| {
            let (raw_ct, _id, _tag) = ct8.clone().into_raw_parts();
            let server_key = keyset.public_keys.server_key.as_ref();
            let sns_key = keyset
                .public_keys
                .server_key
                .clone()
                .into_raw_parts()
                .4
                .unwrap();
            let _ = black_box(sns_key.squash_radix_ciphertext_noise(server_key, &raw_ct));
        });
    });

    // benchmark s&s for the blocks that make up a u16 sequentially
    group.bench_function(BenchmarkId::new("s+s", "u16_sequential"), |b| {
        b.iter(|| {
            let (raw_ct, _id, _tag) = ct16.clone().into_raw_parts();
            let server_key = keyset.public_keys.server_key.as_ref();
            let sns_key = keyset
                .public_keys
                .server_key
                .clone()
                .into_raw_parts()
                .4
                .unwrap();
            let _ = black_box(sns_key.squash_radix_ciphertext_noise(server_key, &raw_ct));
        });
    });
}

criterion_group!(switch_and_squash, bench_switch_and_squash);
criterion_main!(switch_and_squash);
