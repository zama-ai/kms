//! A Solana user decryption goes through the same client path as an EVM one; only the receiver
//! and the linker differ. The responses here are built and signed the way the servers build them,
//! without running MPC: the plaintext is Shamir-shared and each share is signcrypted to the
//! Solana user.

use std::collections::HashMap;
use std::num::Wrapping;

use aes_prng::AesRng;
use algebra::base_ring::Z128;
use algebra::galois_rings::degree_4::ResiduePolyF4;
use algebra::sharing::shamir::{InputOp, ShamirSharings};
use algebra::structure_traits::Ring;
use kms_grpc::kms::v1::{
    TypedCiphertext, TypedPlaintext, TypedSigncryptedCiphertext, UserDecryptionRequest,
    UserDecryptionResponse, UserDecryptionResponsePayload,
};
use kms_grpc::rpc_types::{PlaintextReceiver, fhe_types_to_num_blocks, protobuf_to_alloy_domain};
use rand::SeedableRng;
use tfhe::FheTypes;
use threshold_execution::tfhe_internals::parameters::AugmentedCiphertextParameters;

use crate::client::client_wasm::Client;
use crate::client::user_decryption_wasm::ParsedUserDecryptionRequest;
use crate::consts::{SAFE_SER_SIZE_LIMIT, TEST_PARAM};
use crate::cryptography::encryption::{
    Encryption, PkeScheme, PkeSchemeType, UnifiedPrivateEncKey, UnifiedPublicEncKey,
};
use crate::cryptography::signatures::{
    NodeSigningIdentity, PrivateSigKey, PublicSigKey, gen_sig_keys,
};
use crate::cryptography::signcryption::{SigncryptFHEPlaintext, UnifiedSigncryptionKey};
use crate::dummy_domain;
use crate::engine::base::sign_user_decryption_result;
use crate::engine::validation::DSEP_USER_DECRYPTION;
use kms_grpc::rpc_types::alloy_to_protobuf_domain;

const USER_KEY: [u8; 32] = [0x11; 32];
/// A Solana host chain id: top byte 0x01, then a 56-bit cluster tag.
const SOLANA_HOST_CHAIN_ID: u64 = (0x01 << 56) | 12_345;
const EXTRA_DATA: [u8; 3] = [0x9a, 0x9b, 0x9c];
const PLAINTEXT: u8 = 0xab;
const DEGREE: usize = 1;

fn solana_handle() -> Vec<u8> {
    let mut handle = [0xa1u8; 32];
    handle[22..30].copy_from_slice(&SOLANA_HOST_CHAIN_ID.to_be_bytes());
    handle.to_vec()
}

struct Fixture {
    request: UserDecryptionRequest,
    enc_pk: UnifiedPublicEncKey,
    enc_sk: UnifiedPrivateEncKey,
    server_pks: HashMap<u32, PublicSigKey>,
    server_sks: Vec<PrivateSigKey>,
}

impl Fixture {
    fn new(num_servers: u32) -> Self {
        let mut rng = AesRng::seed_from_u64(7);
        let (enc_sk, enc_pk) = Encryption::new(PkeSchemeType::MlKem512, &mut rng)
            .keygen()
            .unwrap();
        let mut enc_key = Vec::new();
        tfhe::safe_serialization::safe_serialize(&enc_pk, &mut enc_key, SAFE_SER_SIZE_LIMIT)
            .unwrap();
        let request = UserDecryptionRequest {
            request_id: None,
            typed_ciphertexts: vec![TypedCiphertext {
                ciphertext: vec![].into(),
                fhe_type: FheTypes::Uint8 as i32,
                external_handle: solana_handle(),
                ciphertext_format: 0,
            }],
            key_id: None,
            client_address: PlaintextReceiver::Solana(USER_KEY).to_string(),
            enc_key,
            domain: Some(alloy_to_protobuf_domain(&dummy_domain()).unwrap()),
            extra_data: EXTRA_DATA.to_vec(),
            context_id: None,
            epoch_id: None,
            signing_schemes: vec![],
        };
        let (server_pks, server_sks) = (1..=num_servers)
            .map(|party_id| {
                let (pk, sk) = gen_sig_keys(&mut rng);
                ((party_id, pk), sk)
            })
            .unzip();
        Self {
            request,
            enc_pk,
            enc_sk,
            server_pks,
            server_sks,
        }
    }

    /// The client of the user the request names.
    fn client(&self) -> Client {
        Client::new(
            self.server_pks.clone(),
            HashMap::new(),
            PlaintextReceiver::Solana(USER_KEY),
            None,
            TEST_PARAM,
            None,
        )
    }

    /// One response per server, each signcrypting `plaintexts[party]` to the Solana user under the
    /// request's link and signed as the server signs it.
    fn responses(&self, plaintexts: Vec<Vec<u8>>, degree: u32) -> Vec<UserDecryptionResponse> {
        let mut rng = AesRng::seed_from_u64(8);
        let (link, domain, receiver) = self.request.compute_link_checked().unwrap();
        assert_eq!(receiver, PlaintextReceiver::Solana(USER_KEY));
        plaintexts
            .into_iter()
            .zip(&self.server_sks)
            .enumerate()
            .map(|(index, (plaintext, sk))| {
                let party_id = index as u32 + 1;
                let signcrypted_ciphertext =
                    UnifiedSigncryptionKey::new(sk, &self.enc_pk, receiver.as_bytes())
                        .signcrypt_plaintext(
                            &mut rng,
                            &DSEP_USER_DECRYPTION,
                            &plaintext,
                            FheTypes::Uint8,
                            &link,
                        )
                        .unwrap()
                        .payload;
                let payload = UserDecryptionResponsePayload {
                    verification_key: bc2wrap::serialize(&self.server_pks[&party_id]).unwrap(),
                    digest: link.clone(),
                    signcrypted_ciphertexts: vec![TypedSigncryptedCiphertext {
                        fhe_type: FheTypes::Uint8 as i32,
                        signcrypted_ciphertext,
                        external_handle: solana_handle(),
                        packing_factor: 1,
                    }],
                    party_id,
                    degree,
                };
                let signed = sign_user_decryption_result(
                    &NodeSigningIdentity::ecdsa_only(sk.clone()),
                    &[],
                    payload,
                    &self.request.enc_key,
                    self.request.extra_data.clone(),
                    &domain,
                )
                .unwrap();
                UserDecryptionResponse {
                    signature: signed.signature,
                    external_signature: signed.external_signature,
                    payload: Some(signed.payload),
                    extra_data: signed.extra_data,
                    signatures: signed.signatures,
                }
            })
            .collect()
    }

    /// Threshold responses whose shares reconstruct [`PLAINTEXT`], encoded as servers publish them
    /// under the default `NoiseFloodSmall` mode: each message block is scaled into the top bits of a
    /// Z128 coefficient, blocks are packed four to a `ResiduePolyF4<Z128>`, and each polynomial is
    /// Shamir-shared.
    fn threshold_responses(&self) -> Vec<UserDecryptionResponse> {
        let mut rng = AesRng::seed_from_u64(9);
        let num_parties = self.server_sks.len();
        let pbs = TEST_PARAM.classic_pbs();
        let bits_in_block = pbs.message_modulus_log();
        let delta_bits = 128 - (pbs.total_block_bits() + 1);
        let num_blocks = fhe_types_to_num_blocks(FheTypes::Uint8, &pbs, 1).unwrap();
        let blocks: Vec<Z128> = (0..num_blocks)
            .map(|index| {
                let block = (PLAINTEXT as u128 >> (index as u32 * bits_in_block))
                    & ((1 << bits_in_block) - 1);
                Wrapping(block << delta_bits)
            })
            .collect();
        let mut per_party_shares = vec![Vec::new(); num_parties];
        for packed in blocks.chunks(ResiduePolyF4::<Z128>::EXTENSION_DEGREE) {
            let mut padded = packed.to_vec();
            padded.resize(ResiduePolyF4::<Z128>::EXTENSION_DEGREE, Wrapping(0));
            let sharing = ShamirSharings::share(
                &mut rng,
                ResiduePolyF4::<Z128>::from_vec(padded).unwrap(),
                num_parties,
                DEGREE,
            )
            .unwrap();
            for (party_shares, share) in per_party_shares.iter_mut().zip(&sharing.shares) {
                party_shares.push(share.value());
            }
        }
        let shares = per_party_shares
            .iter()
            .map(|party_shares| bc2wrap::serialize(party_shares).unwrap())
            .collect();
        self.responses(shares, DEGREE as u32)
    }

    fn process(
        &self,
        client: &Client,
        request: &UserDecryptionRequest,
        responses: &[UserDecryptionResponse],
        threshold: Option<usize>,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let parsed = ParsedUserDecryptionRequest::try_from(request)?;
        let domain = protobuf_to_alloy_domain(request.domain.as_ref().unwrap())?;
        client.process_user_decryption_resp(
            &parsed,
            &domain,
            &self.enc_pk,
            &self.enc_sk,
            threshold,
            responses,
        )
    }
}

fn expected() -> Vec<TypedPlaintext> {
    vec![TypedPlaintext::new(PLAINTEXT as u128, FheTypes::Uint8)]
}

#[test]
fn centralized_solana_user_decryption() {
    let fixture = Fixture::new(1);
    let plaintext = TypedPlaintext::new(PLAINTEXT as u128, FheTypes::Uint8);
    let responses = fixture.responses(vec![plaintext.bytes.clone()], 0);

    let released = fixture
        .process(&fixture.client(), &fixture.request, &responses, None)
        .unwrap();

    assert_eq!(released, expected());
}

#[test]
fn threshold_solana_user_decryption() {
    let fixture = Fixture::new(4);
    let responses = fixture.threshold_responses();
    let client = fixture.client();

    let released = fixture
        .process(&client, &fixture.request, &responses, Some(DEGREE))
        .unwrap();
    assert_eq!(released, expected());

    // 2t + 1 responses still reconstruct, as on EVM.
    let released = fixture
        .process(&client, &fixture.request, &responses[1..], Some(DEGREE))
        .unwrap();
    assert_eq!(released, expected());

    // t + 1 responses do not: a wrong share among them could be neither detected nor corrected.
    assert!(
        fixture
            .process(&client, &fixture.request, &responses[2..], Some(DEGREE))
            .is_err()
    );
}

#[test]
fn a_response_for_another_user_is_refused() {
    let fixture = Fixture::new(4);
    let responses = fixture.threshold_responses();

    // The same request for another Solana user has another link.
    let mut other_user = fixture.request.clone();
    other_user.client_address = PlaintextReceiver::Solana([0x22; 32]).to_string();
    assert!(
        fixture
            .process(&fixture.client(), &other_user, &responses, Some(DEGREE))
            .is_err()
    );

    // A client opening the shares as another user cannot unsigncrypt them.
    let mut other_client = fixture.client();
    other_client.client_address = PlaintextReceiver::Solana([0x22; 32]);
    assert!(
        fixture
            .process(&other_client, &fixture.request, &responses, Some(DEGREE))
            .is_err()
    );
}

/// Writes the threshold Solana responses as a stable test vector for the JS tests, which run them
/// through the same `process_user_decryption_resp_from_js` entry point as the EVM vectors.
#[cfg(feature = "wasm_tests")]
#[test]
fn test_user_decryption_solana_and_write_transcript() {
    use crate::client::user_decryption_wasm::TestingUserDecryptionTranscript;

    let fixture = Fixture::new(4);
    let agg_resp = fixture.threshold_responses();
    let transcript = TestingUserDecryptionTranscript {
        server_addrs: fixture
            .server_pks
            .iter()
            .map(|(party_id, pk)| (*party_id, pk.address()))
            .collect(),
        client_address: PlaintextReceiver::Solana(USER_KEY),
        client_sk: None,
        degree: DEGREE as u32,
        params: TEST_PARAM,
        fhe_types: vec![FheTypes::Uint8 as i32],
        pts: vec![expected()[0].bytes.clone()],
        cts: vec![],
        request: Some(fixture.request.clone()),
        eph_sk: fixture.enc_sk.clone(),
        eph_pk: fixture.enc_pk.clone(),
        agg_resp,
    };
    transcript
        .write_stable_test_vector_json(crate::consts::TEST_SOLANA_THRESHOLD_WASM_TRANSCRIPT_PATH)
        .unwrap();
}
