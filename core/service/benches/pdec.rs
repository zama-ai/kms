//! Public-decryption deserialization and signing benchmarks.

use bytes::Bytes;
use criterion::{BatchSize, BenchmarkId, Criterion, black_box, criterion_group};
use kms_grpc::kms::v1::CiphertextFormat;
use kms_lib::{
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::signatures::SigningSchemeType,
    engine::{
        base::{
            deserialize_to_low_level,
            pdec_bench::{SignInput, SignStage},
        },
        centralized::central_kms::generate_client_fhe_key,
    },
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tfhe::{
    FheBool, FheTypes, FheUint8, FheUint64, FheUint256,
    prelude::{FheEncrypt, SquashNoise},
    safe_serialization::{safe_deserialize, safe_serialize},
};
use thread_handles::{init_rayon_thread_pool, spawn_compute_bound};
use threshold_execution::tfhe_internals::parameters::BC_PARAMS_SNS;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

struct CiphertextFixture {
    name: &'static str,
    fhe_type: FheTypes,
    bytes: Bytes,
}

type CompressedList = tfhe::CompressedSquashedNoiseCiphertextList;

enum Extracted {
    Bool(tfhe::SquashedNoiseFheBool),
    Uint(tfhe::SquashedNoiseFheUint),
}

fn parse_list(bytes: &Bytes) -> CompressedList {
    safe_deserialize(std::io::Cursor::new(bytes), SAFE_SER_SIZE_LIMIT).unwrap()
}

fn extract_first(list: &CompressedList, fhe_type: FheTypes) -> Extracted {
    match fhe_type {
        FheTypes::Bool => Extracted::Bool(list.get(0).unwrap().unwrap()),
        _ => Extracted::Uint(list.get(0).unwrap().unwrap()),
    }
}

fn clone_underlying(extracted: &Extracted) {
    match extracted {
        Extracted::Bool(ct) => {
            black_box(ct.underlying_squashed_noise_ciphertext().clone());
        }
        Extracted::Uint(ct) => {
            black_box(ct.underlying_squashed_noise_ciphertext().clone());
        }
    }
}

fn ciphertext_fixtures() -> Vec<CiphertextFixture> {
    let key = generate_client_fhe_key(BC_PARAMS_SNS, tfhe::Tag::default(), None);
    tfhe::set_server_key(key.generate_server_key());
    let mut fixtures = Vec::new();
    macro_rules! add_fixture {
        ($name:expr, $fhe_type:expr, $ciphertext:expr) => {{
            let squashed = $ciphertext.squash_noise().unwrap();
            let list = tfhe::CompressedSquashedNoiseCiphertextListBuilder::new()
                .push(squashed)
                .build()
                .unwrap();
            let mut bytes = Vec::new();
            safe_serialize(&list, &mut bytes, SAFE_SER_SIZE_LIMIT).unwrap();
            eprintln!("fixture={} serialized_bytes={}", $name, bytes.len());
            fixtures.push(CiphertextFixture {
                name: $name,
                fhe_type: $fhe_type,
                bytes: Bytes::from(bytes),
            });
        }};
    }
    add_fixture!("bool", FheTypes::Bool, FheBool::encrypt(true, &key));
    add_fixture!("u8", FheTypes::Uint8, FheUint8::encrypt(42u8, &key));
    add_fixture!("u64", FheTypes::Uint64, FheUint64::encrypt(42u64, &key));
    add_fixture!("u256", FheTypes::Uint256, FheUint256::encrypt(42u64, &key));
    fixtures
}

fn signing_cases() -> Vec<(&'static str, SignInput)> {
    let ecdsa = [SigningSchemeType::Ecdsa256k1];
    let ed25519 = [SigningSchemeType::Ed25519];
    let mldsa = [SigningSchemeType::MlDsa65];
    let combined = [SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa65];
    vec![
        ("ecdsa/u64/b1", SignInput::new(1, false, &ecdsa)),
        ("ed25519/u64/b1", SignInput::new(1, false, &ed25519)),
        ("mldsa65/u64/b1", SignInput::new(1, false, &mldsa)),
        ("ecdsa+mldsa65/u64/b1", SignInput::new(1, false, &combined)),
        ("ecdsa+mldsa65/u64/b8", SignInput::new(8, false, &combined)),
        ("ecdsa+mldsa65/u256/b8", SignInput::new(8, true, &combined)),
    ]
}

fn pdec_handoff(c: &mut Criterion) {
    let runtime = runtime();
    let mut group = c.benchmark_group("pdec/handoff");
    group.sample_size(30);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
    // Empty work isolates the Rayon handoff.
    group.bench_function("noop", |b| {
        b.to_async(&runtime).iter(|| async {
            black_box(spawn_compute_bound(|| black_box(1usize)).await.unwrap());
        });
    });
    group.finish();
}

fn pdec_deserialize(c: &mut Criterion) {
    let fixtures = ciphertext_fixtures();
    let runtime = runtime();
    let mut group = c.benchmark_group("pdec/big_compressed_deserialize");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
    for fixture in fixtures {
        let fhe_type = fixture.fhe_type;
        let bytes = fixture.bytes;
        let parsed = parse_list(&bytes);
        let extracted = extract_first(&parsed, fhe_type);
        // Parsing stops before GLWE expansion.
        group.bench_with_input(
            BenchmarkId::new("parse_list", fixture.name),
            &bytes,
            |b, bytes| b.iter(|| black_box(parse_list(bytes))),
        );
        // First-element access expands the packed GLWE.
        group.bench_function(BenchmarkId::new("extract_first", fixture.name), |b| {
            b.iter(|| black_box(extract_first(&parsed, fhe_type)));
        });
        // The service clones the extracted ciphertext.
        group.bench_function(BenchmarkId::new("clone_underlying", fixture.name), |b| {
            b.iter(|| clone_underlying(&extracted));
        });
        // The caller parses, extracts, and clones the ciphertext.
        group.bench_with_input(
            BenchmarkId::new("direct", fixture.name),
            &bytes,
            |b, bytes| {
                b.iter_batched(
                    || bytes.clone(),
                    |bytes| {
                        black_box(
                            deserialize_to_low_level(
                                fhe_type,
                                CiphertextFormat::BigCompressed,
                                &bytes,
                                None,
                            )
                            .unwrap(),
                        )
                    },
                    BatchSize::SmallInput,
                );
            },
        );
        // The Rayon variant adds a pool handoff to the same work.
        group.bench_with_input(
            BenchmarkId::new("rayon", fixture.name),
            &bytes,
            |b, bytes| {
                b.to_async(&runtime).iter_batched(
                    || bytes.clone(),
                    |bytes| async move {
                        black_box(
                            spawn_compute_bound(move || {
                                deserialize_to_low_level(
                                    fhe_type,
                                    CiphertextFormat::BigCompressed,
                                    &bytes,
                                    None,
                                )
                            })
                            .await
                            .unwrap()
                            .unwrap(),
                        );
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn pdec_sign(c: &mut Criterion) {
    let cases = signing_cases();
    let runtime = runtime();
    let mut group = c.benchmark_group("pdec/sign");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
    for (name, fixture) in cases {
        // The caller signs the complete result.
        group.bench_with_input(BenchmarkId::new("full", name), &fixture, |b, fixture| {
            b.iter_batched(
                || fixture.clone(),
                |input| input.run(SignStage::Full).unwrap(),
                BatchSize::SmallInput,
            );
        });
        // Scheme entries reuse the prepared external signature.
        group.bench_with_input(
            BenchmarkId::new("scheme_entries", name),
            &fixture,
            |b, fixture| {
                b.iter_batched(
                    || fixture.clone(),
                    |input| input.run(SignStage::SchemeEntries).unwrap(),
                    BatchSize::SmallInput,
                );
            },
        );
        if name == "ecdsa/u64/b1" {
            // The legacy ECDSA field remains in the wire response.
            group.bench_with_input(
                BenchmarkId::new("legacy_signature", name),
                &fixture,
                |b, fixture| {
                    b.iter_batched(
                        || fixture.clone(),
                        |input| input.run(SignStage::LegacySignature).unwrap(),
                        BatchSize::SmallInput,
                    );
                },
            );
            // The external EIP-712 field remains in the wire response.
            group.bench_with_input(
                BenchmarkId::new("eip712_signature", name),
                &fixture,
                |b, fixture| {
                    b.iter_batched(
                        || fixture.clone(),
                        |input| input.run(SignStage::Eip712Signature).unwrap(),
                        BatchSize::SmallInput,
                    );
                },
            );
        }
        // The Rayon variant signs the same complete result.
        group.bench_with_input(
            BenchmarkId::new("rayon_full", name),
            &fixture,
            |b, fixture| {
                b.to_async(&runtime).iter_batched(
                    || fixture.clone(),
                    |input| async move {
                        spawn_compute_bound(move || input.run(SignStage::Full))
                            .await
                            .unwrap()
                            .unwrap();
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

#[derive(Clone)]
enum LoadWork {
    Deserialize(FheTypes, Bytes),
    Sign(Box<SignInput>),
}

async fn run_load_work(work: &LoadWork, rayon: bool) {
    match work {
        LoadWork::Deserialize(fhe_type, bytes) => {
            let fhe_type = *fhe_type;
            let bytes = bytes.clone();
            if rayon {
                black_box(
                    spawn_compute_bound(move || {
                        deserialize_to_low_level(
                            fhe_type,
                            CiphertextFormat::BigCompressed,
                            &bytes,
                            None,
                        )
                    })
                    .await
                    .unwrap()
                    .unwrap(),
                );
            } else {
                black_box(
                    deserialize_to_low_level(
                        fhe_type,
                        CiphertextFormat::BigCompressed,
                        &bytes,
                        None,
                    )
                    .unwrap(),
                );
            }
        }
        LoadWork::Sign(input) => {
            let input = (**input).clone();
            if rayon {
                spawn_compute_bound(move || input.run(SignStage::Full))
                    .await
                    .unwrap()
                    .unwrap();
            } else {
                input.run(SignStage::Full).unwrap();
            }
        }
    }
}

fn percentile(samples: &mut [Duration], percentile: usize) -> Duration {
    if samples.is_empty() {
        return Duration::ZERO;
    }
    samples.sort_unstable();
    samples[(samples.len() - 1) * percentile / 100]
}

async fn load_trial(
    name: &str,
    work: Arc<Vec<LoadWork>>,
    rayon: bool,
    concurrency: usize,
    trial_duration: Duration,
) {
    let start = tokio::time::Instant::now() + Duration::from_millis(20);
    let end = start + trial_duration;
    let heartbeat = tokio::spawn(async move {
        let mut timer = tokio::time::interval_at(start, Duration::from_millis(1));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut delays = Vec::new();
        while tokio::time::Instant::now() < end {
            let target = timer.tick().await;
            delays.push(tokio::time::Instant::now().saturating_duration_since(target));
        }
        delays
    });
    let mut tasks = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let work = Arc::clone(&work);
        tasks.push(tokio::spawn(async move {
            tokio::time::sleep_until(start).await;
            let mut latencies = Vec::new();
            let mut i = 0;
            while tokio::time::Instant::now() < end {
                let begun = Instant::now();
                run_load_work(&work[i % work.len()], rayon).await;
                latencies.push(begun.elapsed());
                i += 1;
                // Each iteration stands for a new request; give other Tokio tasks a turn.
                tokio::task::yield_now().await;
            }
            latencies
        }));
    }
    let mut latencies = Vec::new();
    for task in tasks {
        latencies.extend(task.await.unwrap());
    }
    let mut delays = heartbeat.await.unwrap();
    let count = latencies.len();
    let p50 = percentile(&mut latencies, 50);
    let p95 = percentile(&mut latencies, 95);
    let p99 = percentile(&mut latencies, 99);
    let wake_p99 = percentile(&mut delays, 99);
    let wake_max = delays.last().copied().unwrap_or_default();
    println!(
        "load/{name}/{} concurrency={concurrency} operations={count} ops_per_sec={:.1} latency_p50_us={:.1} latency_p95_us={:.1} latency_p99_us={:.1} tokio_wakeup_p99_us={:.1} tokio_wakeup_max_us={:.1}",
        if rayon { "rayon" } else { "direct" },
        count as f64 / trial_duration.as_secs_f64(),
        p50.as_secs_f64() * 1e6,
        p95.as_secs_f64() * 1e6,
        p99.as_secs_f64() * 1e6,
        wake_p99.as_secs_f64() * 1e6,
        wake_max.as_secs_f64() * 1e6,
    );
}

fn load_report(smoke: bool) {
    let thread_count = |name: &str, default| {
        std::env::var(name)
            .map(|value| value.parse::<usize>().unwrap())
            .unwrap_or(default)
    };
    let tokio_threads = thread_count("PDEC_TOKIO_THREADS", 3);
    let rayon_threads = thread_count("PDEC_RAYON_THREADS", 15);
    assert!(tokio_threads > 0 && rayon_threads > 0);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(tokio_threads)
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(init_rayon_thread_pool(rayon_threads))
        .unwrap();
    eprintln!("tokio_threads={tokio_threads} rayon_threads={rayon_threads}");
    let fixtures = ciphertext_fixtures();
    let deserialization = |name: &str| {
        let fixture = fixtures
            .iter()
            .find(|fixture| fixture.name == name)
            .unwrap();
        LoadWork::Deserialize(fixture.fhe_type, fixture.bytes.clone())
    };
    let u64_work = deserialization("u64");
    let u256_work = deserialization("u256");
    let sign_work = LoadWork::Sign(Box::new(SignInput::new(
        1,
        false,
        &[SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa65],
    )));
    let cases = [
        // Uint64 jobs represent shorter deserialization work.
        ("u64", vec![u64_work.clone()]),
        // Uint256 jobs represent the longest deserialization work.
        ("u256", vec![u256_work.clone()]),
        // Paired jobs include ECDSA and ML-DSA signing.
        ("sign_mixed", vec![sign_work.clone()]),
        // Mixed jobs combine both ciphertext widths with paired signing.
        ("mixed", vec![u64_work, u256_work, sign_work]),
    ];
    for (name, work) in cases {
        let work = Arc::new(work);
        for concurrency in if smoke { &[1][..] } else { &[1, 3, 12, 48] } {
            let trial_duration = if smoke {
                Duration::from_millis(100)
            } else {
                Duration::from_secs(3)
            };
            runtime.block_on(load_trial(
                name,
                Arc::clone(&work),
                false,
                *concurrency,
                trial_duration,
            ));
            runtime.block_on(load_trial(
                name,
                Arc::clone(&work),
                true,
                *concurrency,
                trial_duration,
            ));
            if smoke {
                break;
            }
        }
        if smoke {
            break;
        }
    }
}

criterion_group!(benches, pdec_handoff, pdec_deserialize, pdec_sign);

fn smoke() {
    let runtime = runtime();
    eprintln!(
        "rayon_threads={}",
        runtime
            .block_on(spawn_compute_bound(rayon::current_num_threads))
            .unwrap()
    );
    runtime
        .block_on(spawn_compute_bound(|| black_box(1usize)))
        .unwrap();
    for fixture in ciphertext_fixtures() {
        let parsed = parse_list(&fixture.bytes);
        let extracted = extract_first(&parsed, fixture.fhe_type);
        clone_underlying(&extracted);
        black_box(
            deserialize_to_low_level(
                fixture.fhe_type,
                CiphertextFormat::BigCompressed,
                &fixture.bytes,
                None,
            )
            .unwrap(),
        );
        runtime
            .block_on(spawn_compute_bound(move || {
                deserialize_to_low_level(
                    fixture.fhe_type,
                    CiphertextFormat::BigCompressed,
                    &fixture.bytes,
                    None,
                )
            }))
            .unwrap()
            .unwrap();
    }
    for (_, fixture) in signing_cases() {
        for stage in [
            SignStage::Full,
            SignStage::LegacySignature,
            SignStage::Eip712Signature,
            SignStage::SchemeEntries,
        ] {
            fixture.clone().run(stage).unwrap();
        }
        runtime
            .block_on(spawn_compute_bound(move || fixture.run(SignStage::Full)))
            .unwrap()
            .unwrap();
    }
    eprintln!("pdec benchmark smoke check passed");
}

fn main() {
    if std::env::var_os("PDEC_SMOKE").is_some() {
        smoke();
    } else if std::env::var_os("PDEC_LOAD_REPORT").is_some() {
        load_report(false);
    } else if std::env::var_os("PDEC_LOAD_SMOKE").is_some() {
        load_report(true);
    } else {
        benches();
    }
}
