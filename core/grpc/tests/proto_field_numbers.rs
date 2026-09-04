//! Field numbers of the user-decryption request are additive.
//!
//! Mixed-version safety rests on one property of the schema: while KMS parties run different
//! versions, a party that predates a field must still parse the request well enough to refuse it
//! safely, and every party must produce identical bytes for the requests they both understand.
//! Reusing a retired number, or changing the type behind an existing one, breaks that quietly —
//! the message still decodes, into a different meaning.
//!
//! So the numbers are pinned. Adding a field with a fresh number is a one-line change here;
//! changing an existing one is not possible without saying so out loud.

use prost::Message;
use prost::encoding::{WireType, encode_key, encode_varint};

use kms_grpc::kms::v1::{SigningMetadata, UserDecryptionRequest};

/// `(number, name)` of every field of `UserDecryptionRequest`, in schema order.
const FROZEN_FIELDS: &[(u32, &str)] = &[
    (1, "request_id"),
    (2, "typed_ciphertexts"),
    (3, "key_id"),
    (4, "client_address"),
    (5, "enc_key"),
    (6, "domain"),
    (7, "extra_data"),
    (8, "context_id"),
    (9, "epoch_id"),
    (10, "signing_schemes"),
    (13, "signing_metadata"),
];

/// Field numbers that must never be used.
///
/// 11 and 12 briefly carried the Solana identity and program id as loose bytes fields, on this
/// branch only. They were replaced by the `signing_metadata` envelope at 13 before any release,
/// and are reserved in the schema: bytes and messages share a wire type, so a reused number would
/// decode on an old party as whatever it expected there. (10 was once reserved here too; it was
/// claimed by `signing_schemes` on `main` before this branch shipped, and that allocation wins.)
const RESERVED_GAPS: &[u32] = &[11, 12];

fn schema() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("proto/kms.v1.proto");
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("reading {path:?}: {error}"))
}

/// Fields declared in `message UserDecryptionRequest`, as `(number, name)`.
fn declared_fields() -> Vec<(u32, String)> {
    let schema = schema();
    let start = schema
        .find("message UserDecryptionRequest {")
        .expect("the request message must exist");
    let body = &schema[start..];
    let end = body.find("\n}").expect("the message must be closed");

    body[..end]
        .lines()
        .map(|line| line.split("//").next().unwrap_or("").trim())
        .filter(|line| line.ends_with(';') && line.contains('='))
        .map(|line| {
            let (declaration, number) = line.rsplit_once('=').expect("filtered on '='");
            let number = number
                .trim()
                .trim_end_matches(';')
                .trim()
                .parse::<u32>()
                .unwrap_or_else(|error| panic!("field number in {line:?}: {error}"));
            let name = declaration
                .split_whitespace()
                .next_back()
                .expect("a field has a name")
                .to_string();
            (number, name)
        })
        .collect()
}

#[test]
fn user_decryption_request_field_numbers_are_frozen() {
    let declared = declared_fields();
    let frozen: Vec<(u32, String)> = FROZEN_FIELDS
        .iter()
        .map(|(number, name)| (*number, name.to_string()))
        .collect();

    assert_eq!(
        declared, frozen,
        "the user-decryption request schema changed.\n\
         Adding a field with a fresh number: add it to FROZEN_FIELDS here too.\n\
         Anything else — renumbering, retyping, removing — breaks parties that are still running \
         the previous version, and needs a decision, not a test update.",
    );
}

#[test]
fn reserved_gaps_stay_unfilled() {
    let declared = declared_fields();

    for gap in RESERVED_GAPS {
        assert!(
            !declared.iter().any(|(number, _)| number == gap),
            "field number {gap} was skipped deliberately; reusing it makes an old party read the \
             new field as whatever it expected there",
        );
    }
}

#[test]
fn solana_fields_survive_protobuf_round_trip() {
    let request = UserDecryptionRequest {
        client_address: String::new(),
        signing_metadata: vec![SigningMetadata::solana(vec![0x11; 32], vec![0x22; 32])],
        ..Default::default()
    };

    let decoded = UserDecryptionRequest::decode(request.encode_to_vec().as_slice())
        .expect("a request this party produced must decode");

    assert_eq!(decoded, request);
}

#[test]
fn evm_request_leaves_solana_fields_unset() {
    // An EVM producer that predates the Solana fields emits exactly this, and it must keep
    // meaning what it always meant.
    let request = UserDecryptionRequest {
        client_address: "0xdadB0d80178819F2319190D340ce9A924f783711".to_string(),
        ..Default::default()
    };

    let decoded =
        UserDecryptionRequest::decode(request.encode_to_vec().as_slice()).expect("decode");

    assert_eq!(decoded.signing_metadata, vec![]);
    assert_eq!(decoded.client_address, request.client_address);
}

#[test]
fn request_with_unknown_field_still_decodes() {
    // The other direction of the mixed-version window, and the one that actually matters: a party
    // running the older version receives a request from a newer producer. It must parse what it
    // knows and ignore the rest, so that it can refuse the request on its merits instead of
    // failing to read it at all — a decode error is indistinguishable from a network fault and
    // would be retried forever.
    let request = UserDecryptionRequest {
        client_address: "0xdadB0d80178819F2319190D340ce9A924f783711".to_string(),
        enc_key: vec![0xab; 16],
        ..Default::default()
    };

    let mut bytes = request.encode_to_vec();
    encode_key(9_999, WireType::LengthDelimited, &mut bytes);
    encode_varint(4, &mut bytes);
    bytes.extend_from_slice(b"\x01\x02\x03\x04");

    let decoded = UserDecryptionRequest::decode(bytes.as_slice())
        .expect("an unknown field must not make the request unreadable");

    assert_eq!(decoded, request, "the known fields survive unchanged");
}
