//! Known answers for the PRSS PRFs and requests.
//!
//! - OpenSSL outputs for single psi and chi evaluations pin the AES inputs, independently of the Rust encoders.
//! - Known-good digests of PRSS, PRZS and mask outputs, recorded on main branch at commit `0e427a1d9` (Oct 8 2026).
//!
//! Parties running different versions must compute identical shares for the same setup, session, role and counters,
//! so a changed digest is a protocol change. On failure the test prints the current table.

use crate::{
    constants::B_SWITCH_SQUASH,
    small_execution::prf::{
        ChiAes, PRSSConversions, PrfKey, PsiAes, accumulate_psi_counters, chi, psi,
    },
    small_execution::prss::{DerivePRSSState, PRSSPrimitives, PRSSSetup},
};
use algebra::{
    galois_rings::{
        degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128},
        degree_8::{ResiduePolyF8Z64, ResiduePolyF8Z128},
    },
    structure_traits::{ErrorCorrect, Invert, Ring},
};
use hashing::{DomainSep, serialize_hash_element};
use threshold_types::{role::Role, session_id::SessionId};

/// Part of the recorded digests; changing it changes every digest.
const DSEP_DIGESTS: DomainSep = *b"PRSSGOLD";

/// Single values.
const AMOUNTS: [usize; 5] = [1, 15, 16, 17, 33];

/// Mask requests.
const MASK_AMOUNTS: [usize; 3] = [1, 17, 1025];

/// Each case runs its requests from zero counters and from counters close to each PRF's limit.
const STARTS: [(&str, [u128; 3]); 2] = [
    ("zero", [0, 0, 0]),
    (
        "high",
        [
            (1 << 112) - 20_000,
            (1 << 104) - 20_000,
            (1 << 120) - 20_000,
        ],
    ),
];

const EXPECTED: &[(&str, &str)] = &[
    (
        "F4Z64 n=4 t=1 start=zero",
        "37b6380cf2cfb388ed66d41d8ad1ab3907bf44d866e30bf0b001150f406f0b04",
    ),
    (
        "F4Z64 n=4 t=1 start=high",
        "eaaadb75ba1606d85c4fdbd1e6fa1943da958afefc0be143e310134e3c02fbcb",
    ),
    (
        "F4Z128 n=4 t=1 start=zero",
        "0386a0a233780db4b37c074562c60fa1d0a67eed8456a4e431d7d242acbabeb6",
    ),
    (
        "F4Z128 n=4 t=1 start=high",
        "a9a237eb22d72d1414ad6a0ce75493f990338d1846598144f2416c0b4d0cfe24",
    ),
    (
        "F8Z64 n=4 t=1 start=zero",
        "845a55105c25841adadc9d498ac2e5a89cca30119fdbb0aa5d6df7769fcaf09d",
    ),
    (
        "F8Z64 n=4 t=1 start=high",
        "039aa334fb8e648b5ab1fc3be64927ade3b40c1d996cc5153c0667449a3fe82f",
    ),
    (
        "F8Z128 n=4 t=1 start=zero",
        "e5e49be91dcd6fc15bfdfd654ecdd6256866616a9464536c5a1b56f8d5e30db7",
    ),
    (
        "F8Z128 n=4 t=1 start=high",
        "1c611b07675408c91c76166caa5db48c8bd19c91e4637c7f55b933301694c12f",
    ),
    (
        "F4Z64 n=13 t=4 start=zero",
        "1970337c2ea2877a0c7c56b0a9df92eef9a93af9372a87ec42de087d1ded20ec",
    ),
    (
        "F4Z64 n=13 t=4 start=high",
        "ab08cfcf5dc69e0cd36f842fff11f14f131f59e8f3de28b41060e2fd45b60901",
    ),
    (
        "F4Z128 n=13 t=4 start=zero",
        "e37a299d121a671e08aa7d36a5d8fe1eb03b72567c30877306596cc5a3d0e58f",
    ),
    (
        "F4Z128 n=13 t=4 start=high",
        "39f37152d08c70f83ad13c9fac41b08ab7054add96dd48c650c73e22e7676ef5",
    ),
    (
        "F8Z64 n=13 t=4 start=zero",
        "528fa8e056b27607ba1711cdacd2a5f664301502de58f9058880dddaa8c44ac9",
    ),
    (
        "F8Z64 n=13 t=4 start=high",
        "5c8ed3b6447c7730555db1b9b634ea92573f573cce3c69d89fb05650789f9d60",
    ),
    (
        "F8Z128 n=13 t=4 start=zero",
        "2aa5ecc497add1fbb37180ccfecc8fd64d71079d5526061d6079695bddd2fe7b",
    ),
    (
        "F8Z128 n=13 t=4 start=high",
        "1e85fbf82cda4f2701ac44a4769e49aa64981ed0a141cfda325c04c942ca1ff8",
    ),
];

/// Runs the same request sequence for every role and returns one digest per start.
async fn digests<Z: ErrorCorrect + Invert + PRSSConversions>(
    ring: &str,
    parties: usize,
    threshold: usize,
) -> Vec<(String, String)> {
    let mut transcripts = vec![(Vec::new(), Vec::new()); STARTS.len()];
    for role in (1..=parties).map(Role::indexed_from_one) {
        let setup = PRSSSetup::<Z>::testing_party_epoch_init(parties, threshold, role)
            .await
            .unwrap();
        for ((_, [prss_ctr, przs_ctr, mask_ctr]), (transcript, counters)) in
            STARTS.into_iter().zip(&mut transcripts)
        {
            let mut state = setup
                .new_prss_session_state(SessionId::from(42), role)
                .unwrap();
            state.counters.prss_ctr = prss_ctr;
            state.counters.przs_ctr = przs_ctr;
            state.counters.mask_ctr = mask_ctr;
            for amount in AMOUNTS {
                transcript.push(state.prss_next_vec(role, amount).await.unwrap());
            }
            // Threshold t evaluates every chi index; threshold one covers the shortest sum.
            for przs_threshold in [1, threshold as u8] {
                for amount in AMOUNTS {
                    let values = state.przs_next_vec(role, przs_threshold, amount).await;
                    transcript.push(values.unwrap());
                }
            }
            // Masks are only defined over Z128 rings.
            if Z::NUM_BITS_STAT_SEC_BASE_RING == 128 {
                for amount in MASK_AMOUNTS {
                    let values = state.mask_next_vec(role, B_SWITCH_SQUASH, amount).await;
                    transcript.push(values.unwrap());
                }
            }
            counters.push([
                state.counters.prss_ctr,
                state.counters.przs_ctr,
                state.counters.mask_ctr,
            ]);
        }
    }
    STARTS
        .into_iter()
        .zip(transcripts)
        .map(|((start_name, _), transcript)| {
            let digest = serialize_hash_element(&DSEP_DIGESTS, &transcript).unwrap();
            let hex = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            (
                format!("{ring} n={parties} t={threshold} start={start_name}"),
                hex,
            )
        })
        .collect()
}

#[tokio::test]
async fn prss_outputs_match_recorded_digests() {
    let mut actual = Vec::new();
    for (parties, threshold) in [(4, 1), (13, 4)] {
        actual.extend(digests::<ResiduePolyF4Z64>("F4Z64", parties, threshold).await);
        actual.extend(digests::<ResiduePolyF4Z128>("F4Z128", parties, threshold).await);
        actual.extend(digests::<ResiduePolyF8Z64>("F8Z64", parties, threshold).await);
        actual.extend(digests::<ResiduePolyF8Z128>("F8Z128", parties, threshold).await);
    }
    let expected: Vec<_> = EXPECTED
        .iter()
        .map(|&(case, digest)| (case.to_string(), digest.to_string()))
        .collect();
    let table: String = actual
        .iter()
        .map(|(case, digest)| format!("    (\"{case}\", \"{digest}\"),\n"))
        .collect();
    assert_eq!(actual, expected, "current digests:\n{table}");
}

/// Evaluates psi at one counter through the grouped path.
fn psi_group_of_one<Z: Ring + PRSSConversions>(key: &PsiAes, ctr: u128) -> Z {
    let mut values = [Z::ZERO];
    accumulate_psi_counters(key, ctr, Z::ONE, &mut values);
    values[0]
}

// Fixed AES-128-ECB outputs generated with OpenSSL, independently of the Rust encoders and AES backend.
// These pin session/domain key derivation, input byte order, coefficient order, and Z64's low-half truncation.
// Generator: OpenSSL 4.0.3 29 Sep 2026 (Library: OpenSSL 4.0.3 29 Sep 2026).
// Host: macOS 27.0.1 (build 26A434), Apple M5 Max (Mac17,7; 18 cores).
// Commands used, wrapped for readability; printf concatenates the hex blocks without separators.
// psi:
// printf '%s' \
//   'ffffffffffffffff0000000000000000ffffffffffffffff0000000000000100' \
//   'ffffffffffffffff0000000000000200ffffffffffffffff0000000000000300' \
//   '0000000000000000010000000000000000000000000000000100000000000100' \
//   '0000000000000000010000000000020000000000000000000100000000000300' \
//   | xxd -r -p | openssl enc -aes-128-ecb -K 072543618fadcbe9f8dabc9e70523416 -nosalt -nopad | xxd -p -c 256
// chi:
// printf '%s' \
//   'ffffffffffffffff0000000000a50000ffffffffffffffff0000000000a50100' \
//   'ffffffffffffffff0000000000a50200ffffffffffffffff0000000000a50300' \
//   '00000000000000000100000000a5000000000000000000000100000000a50100' \
//   '00000000000000000100000000a5020000000000000000000100000000a50300' \
//   | xxd -r -p | openssl enc -aes-128-ecb -K 062543618fadcbe9f8dabc9e70523416 -nosalt -nopad | xxd -p -c 256
#[test]
fn psi_chi_known_answers() {
    let key = PrfKey([0x17; 16]);
    let sid = SessionId::from(0x0123456789abcdef_fedcba9876543210_u128);
    let psi_key = PsiAes::new(&key, sid);
    let chi_key = ChiAes::new(&key, sid);
    // Consecutive counters cross the 64-bit carry; j sets both low and high bits of chi's index byte.
    let first_counter = u64::MAX as u128;
    let j = 0xa5;
    // OpenSSL keys: psi=072543618fadcbe9f8dabc9e70523416, chi=062543618fadcbe9f8dabc9e70523416.
    // Each row contains four encrypted blocks interpreted as little-endian u128 coefficients.
    let expected_psi = [
        [
            0xbd97cd92845ede50fb3b62d1b6fcec8a_u128,
            0x92335305f109de4b97143f475b826968,
            0xa92c6ab666a1fcf0026c9b8efcbe3b9d,
            0xb76b2a4cfcf86b34d0da67caa8248926,
        ],
        [
            0x0cecd5013c98a503f8bfbab2ed7bde52,
            0x4aeb14867a1b9adef700a61e59f6893f,
            0x3aaeb5c53f83feb24fbc9791b9a6c90b,
            0xa3060312f0c5dd36695906a5d839ce96,
        ],
    ];
    let expected_chi = [
        [
            0x7029f3ae30775cd217b90f1c45625783_u128,
            0xf3cfd51e048aba13e3241ac878a5e43e,
            0xcdfabff0e7036b6ca56ffde04ae7f699,
            0xb1c9ef830777eafb93b8354ac88a2ec4,
        ],
        [
            0x4964b524f5851c6184153d98c849120e,
            0xb8e796e503e7409f6eb3279b3be9a72b,
            0x2cc7457d00028ee7e22241d5f2e451c2,
            0x31af557614a25a6488bfd8547f8c033f,
        ],
    ];
    for (offset, (psi_coefs, chi_coefs)) in expected_psi.into_iter().zip(expected_chi).enumerate() {
        let counter = first_counter + offset as u128;
        assert_eq!(
            psi::<ResiduePolyF4Z128>(&psi_key, counter)
                .coefs
                .map(|c| c.0),
            psi_coefs
        );
        assert_eq!(
            psi_group_of_one::<ResiduePolyF4Z128>(&psi_key, counter)
                .coefs
                .map(|c| c.0),
            psi_coefs
        );
        assert_eq!(
            chi::<ResiduePolyF4Z128>(&chi_key, counter, j)
                .coefs
                .map(|c| c.0),
            chi_coefs
        );
        // Compare coefficient arrays directly: expected values must not use the production conversion helpers.
        assert_eq!(
            psi::<ResiduePolyF4Z64>(&psi_key, counter)
                .coefs
                .map(|c| c.0),
            psi_coefs.map(|c| c as u64)
        );
        assert_eq!(
            psi_group_of_one::<ResiduePolyF4Z64>(&psi_key, counter)
                .coefs
                .map(|c| c.0),
            psi_coefs.map(|c| c as u64)
        );
        assert_eq!(
            chi::<ResiduePolyF4Z64>(&chi_key, counter, j)
                .coefs
                .map(|c| c.0),
            chi_coefs.map(|c| c as u64)
        );
    }
}
