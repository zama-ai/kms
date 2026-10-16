//! Measures public-decryption deserialization and signing with Criterion.
//!
//! Full-operation timings track service costs; stage timings identify where that time goes.
//! Fixtures are prepared outside the timed regions.

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
use std::time::Duration;
use tfhe::{
    FheBool, FheTypes, FheUint8, FheUint64, FheUint256,
    prelude::{FheEncrypt, SquashNoise},
    safe_serialization::{safe_deserialize, safe_serialize},
};
use threshold_execution::tfhe_internals::parameters::BC_PARAMS_SNS;

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

/// Deserializes a compressed list without extracting a ciphertext.
fn parse_list(bytes: &Bytes) -> CompressedList {
    safe_deserialize(std::io::Cursor::new(bytes), SAFE_SER_SIZE_LIMIT).unwrap()
}

/// Extracts the first ciphertext from a parsed list.
fn extract_first(list: &CompressedList, fhe_type: FheTypes) -> Extracted {
    match fhe_type {
        FheTypes::Bool => Extracted::Bool(list.get(0).unwrap().unwrap()),
        _ => Extracted::Uint(list.get(0).unwrap().unwrap()),
    }
}

/// Clones the low-level ciphertext that the service returns.
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

/// Builds one serialized BigCompressed ciphertext for each measured type.
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

/// Builds signing inputs for individual and paired signature schemes.
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

/// Measures full deserialization and its parsing, extraction, and cloning stages.
fn pdec_deserialize(c: &mut Criterion) {
    let fixtures = ciphertext_fixtures();
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
    }
    group.finish();
}

/// Measures full result signing and its individual signature stages.
fn pdec_sign(c: &mut Criterion) {
    let cases = signing_cases();
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
        // Requested schemes sign the prepared hash or payload.
        group.bench_with_input(
            BenchmarkId::new("requested_signatures", name),
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
    }
    group.finish();
}

criterion_group!(benches, pdec_deserialize, pdec_sign);

/// Runs each isolated benchmark path once to check fixture and operation setup.
fn smoke() {
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
    }
    eprintln!("pdec benchmark smoke check passed");
}

/// Selects the smoke check or Criterion benchmarks.
fn main() {
    if std::env::var_os("PDEC_SMOKE").is_some() {
        smoke();
    } else {
        benches();
    }
}
