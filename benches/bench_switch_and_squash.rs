use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use distributed_decryption::{
    execution::{
        constants::REAL_PARAM_PATH,
        random::get_rng,
        tfhe_internals::{parameters::NoiseFloodParameters, test_feature::gen_key_set},
    },
    file_handling::read_as_json,
};
use tfhe::{integer::IntegerCiphertext, prelude::FheEncrypt, FheUint16, FheUint8};

fn bench_switch_and_squash(c: &mut Criterion) {
    let mut group = c.benchmark_group("switch_and_squash");
    group.sample_size(10);
    let key_params = REAL_PARAM_PATH.to_string();

    println!("using key parameters: {key_params}");

    let params: NoiseFloodParameters = read_as_json(key_params).unwrap();
    let keyset = gen_key_set(params, &mut get_rng());

    let msg8 = 5_u8;
    let ct8 = FheUint8::encrypt(msg8, &keyset.public_key);
    let msg16 = 5_u16;
    let ct16 = FheUint16::encrypt(msg16, &keyset.public_key);

    let public_key = bincode::serialize(&(keyset.public_key)).unwrap();
    let server_key = bincode::serialize(&(keyset.server_key)).unwrap();
    let conversion_key = bincode::serialize(&(keyset.conversion_key)).unwrap();
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
            let (raw_ct, _id) = ct8.clone().into_raw_parts();
            let _ = keyset
                .conversion_key
                .to_large_ciphertext_block(&raw_ct.blocks()[0]);
        });
    });

    // benchmark s&s for the blocks that make up a u8 sequentially
    group.bench_function(BenchmarkId::new("s+s", "u8_sequential"), |b| {
        b.iter(|| {
            let (raw_ct, _id) = ct8.clone().into_raw_parts();
            let _ = keyset.conversion_key.to_large_ciphertext(&raw_ct);
        });
    });

    // benchmark s&s for the blocks that make up a u16 sequentially
    group.bench_function(BenchmarkId::new("s+s", "u16_sequential"), |b| {
        b.iter(|| {
            let (raw_ct, _id) = ct16.clone().into_raw_parts();
            let _ = keyset.conversion_key.to_large_ciphertext(&raw_ct);
        });
    });
}

criterion_group!(switch_and_squash, bench_switch_and_squash);
criterion_main!(switch_and_squash);
