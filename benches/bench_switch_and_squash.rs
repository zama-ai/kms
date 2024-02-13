use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use distributed_decryption::{
    execution::{constants::REAL_PARAM_PATH, random::get_rng},
    file_handling::read_as_json,
    lwe::{gen_key_set, to_large_ciphertext_block, ThresholdLWEParameters},
};

fn bench_switch_and_squash(c: &mut Criterion) {
    let mut group = c.benchmark_group("switch_and_squash");
    group.sample_size(10);
    let key_params = REAL_PARAM_PATH.to_string();

    println!("using key parameters: {key_params}");

    let params: ThresholdLWEParameters = read_as_json(key_params).unwrap();
    let keyset = gen_key_set(params, &mut get_rng());

    let msg8 = 5_u8;
    let ct8 = keyset.pk.encrypt(&mut get_rng(), msg8);

    let msg16 = 5_u16;
    let ct16 = keyset.pk.encrypt(&mut get_rng(), msg16);

    let pks = bincode::serialize(&(keyset.pk)).unwrap();
    let cks = bincode::serialize(&(keyset.ck)).unwrap();
    let sks = bincode::serialize(&(keyset.sk)).unwrap();

    println!(
        "key sizes (kiB, serialized): pk={}  sk={}  ck={}",
        pks.len() / 1024,
        sks.len() / 1024,
        cks.len() / 1024
    );

    // benchmark s&s for a single ct block
    group.bench_function(BenchmarkId::new("s+s", "single_block"), |b| {
        b.iter(|| {
            let _ = to_large_ciphertext_block(&keyset.ck, &ct8[0]);
        });
    });

    // benchmark s&s for the blocks that make up a u8 sequentially
    group.bench_function(BenchmarkId::new("s+s", "u8_sequential"), |b| {
        b.iter(|| {
            let _: Vec<_> = ct8
                .iter()
                .map(|ct_block| to_large_ciphertext_block(&keyset.ck, ct_block))
                .collect();
        });
    });

    // benchmark s&s for the blocks that make up a u16 sequentially
    group.bench_function(BenchmarkId::new("s+s", "u16_sequential"), |b| {
        b.iter(|| {
            let _: Vec<_> = ct16
                .iter()
                .map(|ct_block| to_large_ciphertext_block(&keyset.ck, ct_block))
                .collect();
        });
    });
}

criterion_group!(switch_and_squash, bench_switch_and_squash);
criterion_main!(switch_and_squash);
