//! Criterion micro-benchmark for the threshold **user-decrypt** server-side compute, stage by stage,
//! on the **BigCompressed** path that CI/production uses, parametrized over ciphertext size.
//!
use algebra::{
    galois_rings::{common::pack_residue_poly, degree_4::ResiduePolyF4Z128},
    structure_traits::Ring,
};
use criterion::{Criterion, criterion_group, criterion_main};
use kms_grpc::kms::v1::CiphertextFormat;
use kms_lib::{
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::{
        encryption::{Encryption, PkeScheme, PkeSchemeType, UnifiedPublicEncKey},
        signatures::gen_sig_keys,
        signcryption::{SigncryptFHEPlaintext, UnifiedSigncryptionKeyOwned},
    },
    engine::base::deserialize_to_low_level,
};
use rand::{Rng, SeedableRng};
use tfhe::{
    CompressedSquashedNoiseCiphertextListBuilder, FheTypes, FheUint64, FheUint256,
    prelude::SquashNoise, safe_serialization::safe_serialize, set_server_key,
};
use threshold_execution::{
    constants::REAL_KEY_PATH,
    endpoints::decryption::{
        LowLevelCiphertext, LowLevelCiphertextAndKeys, OfflineNoiseFloodSession,
        SmallOfflineNoiseFloodSession, SnsDecryptionKeyType, partial_decrypt_using_noiseflooding,
        partial_decrypt128,
    },
    runtime::test_runtime::{DistributedTestRuntime, generate_fixed_roles},
    tests::ensure_real_keys_setup,
    tfhe_internals::{
        test_feature::{KeySet, keygen_all_party_shares_from_client_key},
        utils::expanded_encrypt,
    },
};
use threshold_types::{network::NetworkMode, role::Role, session_id::SessionId};

const EXT: usize = ResiduePolyF4Z128::EXTENSION_DEGREE;
/// Domain separator for user decryption (value mirrors the crate-internal `DSEP_USER_DECRYPTION`).
const DSEP: hashing::DomainSep = *b"USER_DEC";
/// BigCompressed ciphertexts are decrypted with the SnS compression key.
const DDEC_KEY: SnsDecryptionKeyType = SnsDecryptionKeyType::SnsCompressionKey;

fn bench_user_decrypt(c: &mut Criterion) {
    ensure_real_keys_setup();
    let keyset: KeySet = test_utils::read_element(REAL_KEY_PATH).unwrap();
    set_server_key(keyset.public_keys.server_key.clone());

    let mut rng = aes_prng::AesRng::seed_from_u64(0xDEC0DE);
    let params = keyset.get_cpu_params().unwrap();
    let key_shares = keygen_all_party_shares_from_client_key::<_, EXT>(
        &keyset.client_key,
        params,
        &mut rng,
        4,
        1,
    )
    .unwrap();
    let sk_share = &key_shares[0];

    // Build the BigCompressed wire form for a given FHE type (the coprocessor's upstream work).
    macro_rules! big_compressed {
        ($t:ty, $bits:expr, $msg:expr) => {{
            let ct: $t = expanded_encrypt(&keyset.public_keys.public_key, $msg, $bits).unwrap();
            let squashed = ct.squash_noise().unwrap();
            let list = CompressedSquashedNoiseCiphertextListBuilder::new()
                .push(squashed)
                .build()
                .unwrap();
            let mut bytes = Vec::new();
            safe_serialize(&list, &mut bytes, SAFE_SER_SIZE_LIMIT).unwrap();
            bytes
        }};
    }
    let big_u64 = big_compressed!(FheUint64, 64, rng.r#gen::<u64>());
    let big_u256 = big_compressed!(FheUint256, 256, rng.r#gen::<u128>());

    // Signcryption key: party signing key + a fresh MlKem receiver key (as a user would provide).
    let enc_pk = {
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        enc.keygen().unwrap().1
    };
    let mut enc_buf = Vec::new();
    safe_serialize(&enc_pk, &mut enc_buf, SAFE_SER_SIZE_LIMIT).unwrap();
    let client_enc_key = UnifiedPublicEncKey::deserialize_and_validate(&enc_buf).unwrap();
    let (_spk, ssk) = gen_sig_keys(&mut rng);
    let signcryption_key =
        UnifiedSigncryptionKeyOwned::new(ssk, client_enc_key, b"0xclient".to_vec());
    let link = vec![0u8; 32];

    // One-party SmallSession with PRSS, reused across sizes.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let runtime = DistributedTestRuntime::<ResiduePolyF4Z128, _, EXT>::new(
        generate_fixed_roles(4),
        1,
        NetworkMode::Sync,
        None,
    );
    let small_session = rt.block_on(runtime.small_session_for_party(
        SessionId::from(1u128),
        Role::indexed_from_one(1),
        None,
    ));
    let mut nf = SmallOfflineNoiseFloodSession::new(small_session);

    let mut group = c.benchmark_group("user_decrypt");
    group.sample_size(20);

    for (size, fhe_type, big_bytes) in [
        ("euint64", FheTypes::Uint64, big_u64.as_slice()),
        ("euint256", FheTypes::Uint256, big_u256.as_slice()),
    ] {
        // Per-size derived data (computed once, reused/borrowed by the closures below).
        let ct_large = match deserialize_to_low_level(
            fhe_type,
            CiphertextFormat::BigCompressed,
            big_bytes,
            None,
        )
        .unwrap()
        {
            LowLevelCiphertext::BigCompressed(ct) => ct,
            _ => unreachable!("built a BigCompressed ciphertext above"),
        };

        let partials = ct_large
            .packed_blocks()
            .map(|blk| partial_decrypt128(sk_share, blk, DDEC_KEY).unwrap())
            .collect::<Vec<_>>();
        let packed = pack_residue_poly(&partials);
        let pdec_serialized = bc2wrap::serialize(&packed).unwrap();

        group.bench_function(format!("deserialize/{size}/BigCompressed"), |b| {
            b.iter(|| {
                criterion::black_box(
                    deserialize_to_low_level(
                        fhe_type,
                        CiphertextFormat::BigCompressed,
                        big_bytes,
                        None,
                    )
                    .unwrap(),
                )
            });
        });

        group.bench_function(format!("partial_decrypt128/{size}"), |b| {
            b.iter(|| {
                let out: Vec<_> = ct_large
                    .packed_blocks()
                    .map(|blk| partial_decrypt128::<EXT>(sk_share, blk, DDEC_KEY).unwrap())
                    .collect();
                criterion::black_box(out)
            });
        });

        // pack and serialize measured separately: each closure times exactly one operation.
        group.bench_function(format!("pack/{size}"), |b| {
            b.iter(|| criterion::black_box(pack_residue_poly(&partials)));
        });

        group.bench_function(format!("serialize/{size}"), |b| {
            b.iter(|| criterion::black_box(bc2wrap::serialize(&packed).unwrap()));
        });

        group.bench_function(format!("signcrypt/{size}"), |b| {
            b.iter(|| {
                let mut r = aes_prng::AesRng::seed_from_u64(7);
                criterion::black_box(
                    signcryption_key
                        .signcrypt_plaintext(&mut r, &DSEP, &pdec_serialized, fhe_type, &link)
                        .unwrap(),
                )
            });
        });

        // End-to-end: mirrors `inner_user_decrypt`'s per-ciphertext body for one party (incl. the PRSS
        // mask-prep, via `partial_decrypt_using_noiseflooding`). Measures compute only — not the
        // rayon/tokio scheduling shape of the real handler.
        group.bench_function(format!("end_to_end/{size}/BigCompressed"), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let low = deserialize_to_low_level(
                        fhe_type,
                        CiphertextFormat::BigCompressed,
                        big_bytes,
                        None,
                    )
                    .unwrap();
                    let ct = match low {
                        LowLevelCiphertext::BigCompressed(c) => {
                            LowLevelCiphertextAndKeys::BigCompressed(c)
                        }
                        _ => unreachable!("built a BigCompressed ciphertext above"),
                    };
                    let (pmap, _pf, _t) =
                        partial_decrypt_using_noiseflooding(&mut nf, ct, sk_share)
                            .await
                            .unwrap();
                    let pdec = pmap.into_values().next().unwrap();
                    let packed = pack_residue_poly(&pdec);
                    let serialized = bc2wrap::serialize(&packed).unwrap();
                    let mut r = aes_prng::AesRng::seed_from_u64(7);
                    criterion::black_box(
                        signcryption_key
                            .signcrypt_plaintext(&mut r, &DSEP, &serialized, fhe_type, &link)
                            .unwrap(),
                    )
                })
            });
        });
    }
}

criterion_group! {
    name = user_decrypt;
    config = Criterion::default().without_plots();
    targets = bench_user_decrypt
}
criterion_main!(user_decrypt);
