//! The normative Solana linker v1 vectors, and the runner that consumes them.
//!
//! One code path builds the set and checks it. `cargo test` builds every record in memory from the
//! canonical binding and compares byte-for-byte with the committed
//! `core/grpc/test-vectors/solana_linker_v1.json`; running the same binary with
//! `ZAMA_UPDATE_SOLANA_LINKER_VECTORS=1` rewrites that file and its digest instead. There is no
//! second generator to drift from the runner, and no committed byte that was not produced by the
//! code under test.
//!
//! # The cross-repository contract
//!
//! These vectors are the linker half of the specification's shared fixture set; the permit
//! half lives in the fhevm repository. Five implementations — SDK TypeScript, relayer, Connector
//! Rust, KMS Core Rust, KMS client/WASM — must consume *the same bytes*, so the set carries its own
//! SHA-256 in `solana_linker_v1.sha256`, in `sha256sum` line format:
//!
//! ```text
//! <64 lowercase hex digits>  solana_linker_v1.json
//! ```
//!
//! Any repository holding a copy writes the same two files and CI compares the digests. A copy that
//! was "adjusted locally" changes the digest and is caught; a copy that is merely stale is caught
//! too. That is the whole mechanism — deliberately smaller than a submodule or a published artifact,
//! and it fails loudly rather than silently diverging.
//!
//! # Conventions that carry weight
//!
//! * **Every 64-bit value is a decimal string.** A JSON number reaches a TypeScript consumer as an
//!   IEEE-754 double. Every chain id here sets bit 63, so every one of them exceeds 2^53 and would
//!   be silently rounded. The set contains no JSON numbers at all, and a test enforces that.
//! * **Every rejecting record names its rule and its single mutation.** A negative vector that
//!   fails "somehow" tests nothing: an implementation could reject it for an unrelated reason and
//!   look correct. `derived_from` names an accepted base, `mutation` names the one change.
//! * **The registry is part of the published surface.** `cluster_registry` is the reviewed registry
//!   of public-cluster chain ids, shared with the deployment procedure: a cluster configuration is
//!   reviewed against these entries, and they are derived by the same rule and the same code as
//!   every record's chain id, so the two cannot drift apart.
//! * **The set is self-contained.** This file deliberately does not use `tests/common`: a published
//!   reference must not move because a shared test helper was edited. It mirrors the conventions of
//!   the permit set's `permit_vectors.rs` rather than importing anything from it.
//!
//! # Frozen
//!
//! The scheme tag `SolanaUserDecryptionLinker:v1`, the call separator `SOLLNK01` and the specified
//! element layout are frozen by this set. `solana_frozen_constants.rs` pins them independently;
//! after this point a change to any of those bytes is a version bump in the scheme tag, not an edit.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::LazyLock;

use hashing::{DSEP_LIST, unsafe_hash_list_w_size};
use kms_grpc::solana_binding::{
    DSEP_SOLANA_LINKER, SOLANA_LINKER_SCHEME_TAG, SolanaUserDecryptBinding,
    SolanaUserDecryptBindingError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Identity of the set
// ---------------------------------------------------------------------------

/// Schema identifier. A consumer that does not recognize it must refuse the file rather than guess.
const SCHEMA: &str = "zama-solana-linker-vectors/v1";

/// Which generator produced the set, so a diverging copy can be traced to its source.
const GENERATOR: &str = "kms:core/grpc/tests/solana_linker_vectors.rs";

const VECTOR_FILE: &str = "solana_linker_v1.json";
const DIGEST_FILE: &str = "solana_linker_v1.sha256";

/// Set to any value to rewrite the committed set instead of checking it.
const UPDATE_ENV: &str = "ZAMA_UPDATE_SOLANA_LINKER_VECTORS";

/// Frozen tag of the deployment-time chain-id derivation rule.
///
/// The rule is a *test-side* artifact here: production KMS never derives a chain id, it receives one
/// as data embedded in the handles. The vectors record the genesis hash and the derived id together
/// so that the layers which do derive it — cluster configuration, the SDK — can be checked against
/// the same pairs.
const CHAIN_ID_DERIVATION_TAG: &str = "zama-solana-chain-id-v1";

/// Prose form of the same rule, written into the file for non-Rust consumers.
const CHAIN_ID_DERIVATION_RULE: &str = concat!(
    "digest = SHA-256(ASCII(\"zama-solana-chain-id-v1\") || base58_decode(genesis_hash)); ",
    "chain_id = 0x8000000000000000 | (be_u64(digest[0..8]) & 0x7fffffffffffffff)",
);

/// Bit 63 marks a Solana-kind host chain.
const CHAIN_KIND_BIT: u64 = 1 << 63;

/// Width of the link, and of every identity the binding accepts.
const LINK_LEN: usize = 32;

/// Largest integer a JSON number survives intact in a TypeScript consumer.
const JAVASCRIPT_SAFE_INTEGER: u64 = (1u64 << 53) - 1;

// ---------------------------------------------------------------------------
// Shared inputs
// ---------------------------------------------------------------------------

/// The cluster the permit fixtures are signed against, as its genesis hash — base58, the form the
/// derivation rule consumes and the form a Solana RPC returns.
///
/// The permit set records the same 32 bytes as hex; [`PERMIT_GENESIS_HASH_HEX`] pins that they are
/// the same cluster, which is what "the two halves reference the same objects" means concretely.
const REFERENCE_GENESIS: &str = "5fEG2HwSyUNArDbENzk4BMqq6ppxwvVQa5UNGXpij6QD";

/// `deployment.genesis_hash` of the fhevm permit set, hex.
const PERMIT_GENESIS_HASH_HEX: &str =
    "4539cf79f66704d313b4047b712d24ee29653cdf7484b18bc05992c01c105576";

/// A second, real cluster: Solana mainnet-beta's genesis hash.
///
/// Used by the wrong-chain-id record. A real value rather than a fabricated one, so that a consumer
/// which happens to know the mainnet chain id can check this set against its own configuration.
const OTHER_GENESIS: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";

/// The recipient: the permit set's `user_pubkey`, the raw 32-byte ed25519 wallet key.
const RECEIVER_ID_HEX: &str = "c11a7cf8eb1cdfcb1bcb84b9d8314ddec3bb1410f0a95badd9c4384f643a6427";

/// The permit set's `verifying_program_id`.
const VERIFYING_PROGRAM_ID_HEX: &str =
    "4cd3022dff504a675caf2d9b4f4014d0b3dc3ea17ffb97ba355cec5a933a30ee";

/// The permit set's `kms_routing.kms_context_id`, as parsed from the signed `extra_data`.
const KMS_CONTEXT_ID_HEX: &str = "bb801121e2ea198af189c9331dfc57f675802c35206f96a5964deeac39f79d18";

/// The permit set's `kms_routing.kms_epoch_id`.
const KMS_EPOCH_ID_HEX: &str = "7772d6a5c7fc28db485c51abbe18cba52b775baf1015b59ac363e5bf5827a3f2";

/// Derivation of the handle filler, so a regenerating implementation reproduces these bytes.
///
/// Handles are the one input the permit layer does not carry, so there is nothing to align them to.
/// A hash-derived filler is used rather than a repeated byte so that no accidental structure —
/// a run of zeros, an ascending pattern — can make a layout bug look correct.
const HANDLE_DERIVATION_TAG: &str = "zama-solana-linker-vectors/v1 handle ";

/// Name of the canonical transport key: the 869-byte serialized `UnifiedPublicEncKey::MlKem512`
/// container a KMS user-decryption request actually carries. The name is the one the permit set's
/// `transport_keys` table uses; that set still records the bare 800-byte encapsulation key under it
/// and regenerates to this container under the settled permit-v1 representation, after which the
/// two files share the key byte-for-byte again.
const TRANSPORT_REFERENCE: &str = "reference-mlkem-512";

/// A second key of the same width, for the substitution record.
const TRANSPORT_ATTACKER: &str = "attacker-mlkem-512";

/// The bare 800-byte ML-KEM-512 encapsulation key — a width no conforming KMS request carries.
const TRANSPORT_BARE: &str = "bare-mlkem-512-800";

/// The bare ML-KEM-512 encapsulation key, 800 bytes — the permit set's current `reference-mlkem-512`,
/// byte-identical to it. Demoted from reference to a single negative record: production KMS request
/// validation rejects this width, so no accepted request ever carries it, and it survives here only
/// to show that the linker as an algorithm binds whatever bytes it is given.
const BARE_MLKEM_512_HEX: &str = concat!(
    "27b792b8740145b905d2b19f3575cb5cc27746ec1869b89a80217182c06d9e66877492ac1a515d31e275244712769b10fde778e1e9b6ff9c1fbeec2f51b63377",
    "e621ce408035fc9c7fb6a4846c12ab82b3fe75cc91544a5ea511aed07712f60250989d9ff46a38f7a999120b924a6100f278eb25422a1278732a1082d85b9397",
    "8e31d5b462b7ad319c8749519238d0b82e5760de9ca49a6b52826b07a6a8134051aef3b63b225c0201126f36e23657dc0f67a9b59c0a5bea89393952674a3156",
    "fdd2035594bd0c9a537e3b49278091becc6845c43e2022700c0478edb7b9d8a0801bd9b98ad2006ccb3db1a2c36d005736d87d28aa96bfd329bf9aa3c05cb521",
    "660c36211e61d65e63abb295aa2ade8096d3f41136fa713b61bf84d75cf45c4cd287861cd7a96e106ff6336cdda88a92a9a29c14a5cab0c537e318d629bae996",
    "9631a1a8eff0b02b3904ed17a7361733758abcae984d0fb55a1d628302151627db570828c11c74b278597d672671fc00a5c25c7aadfc8f7be008532c9ff59b01",
    "aca534e8382a297a7dfc4965f56619e3ec8fb5380137c45f12404cbe772ffce5c9b24ccb28e2193681651d43b07f83aa4b662e19b98c4197666f9b626a4c880b",
    "0a14b40b8c8e7629557931ae901abf16a06c6b561e1861b40a9c933553d8f28b4a80b3d2d865488941d77a128155064884c67cb8c6921a4cc0b7c9bf059c5101",
    "521b0119157489e8c5566f86386f3905d9987825f5045f957273a76a1af599a585b674b6a696ba9affc12410b04c2a482730d95dd4023d0b1825b23792b8c0b2",
    "aa7116fcc4b959a35a68eb2a3fda078ad3bc3e69280b94636f6795c44a06dacc00156032aca9924e5cb618e11ec6215599807b57955871ec7f819228088c5304",
    "7379a72b8f0d6a7cd89c7f258c73876892236cae8cdb0b80640324e0c8c2f081f2079e7c53bea86435fa4563826b838213677515aef5160f4ddc1200b214fcd0",
    "1ca4976948b86c1bc512ffc08f948889fa058292c3b5369b56265435a1d993f111ccfa6761547b86323779e40b0f4d41af6e4a34583cc28502353c7a1028b725",
    "8bfdd3c82d8e64cf6d91e5b1815df57d2791eb20bc6c0bc208eb7db167f454e0",
);

/// The canonical reference transport key: a genuine serialized `UnifiedPublicEncKey::MlKem512`
/// container, 869 bytes, the width and representation a KMS user-decryption request actually
/// carries. Every reference record binds these bytes.
///
/// Generated deterministically, once, by the KMS crate's own machinery, so that any reviewer can
/// reproduce these bytes rather than take them on trust. The generation expression, verbatim:
///
/// ```ignore
/// let mut rng = AesRng::seed_from_u64(1689); // the seed: the issue number this work lands under
/// let (_sk, pk) = Encryption::new(PkeSchemeType::MlKem512, &mut rng).keygen().unwrap();
/// let mut buf = Vec::new();
/// tfhe::safe_serialization::safe_serialize(&pk, &mut buf, SAFE_SER_SIZE_LIMIT).unwrap();
/// ```
///
/// It cannot be produced *here*: `kms-grpc` does not depend on the encryption or safe-serialization
/// machinery, which is why the bytes are embedded rather than computed. What that costs — the risk
/// that tfhe's framing moves and this literal silently stops being a container — is paid back by
/// `core/service/tests/solana_vector_container.rs`, which reads these committed bytes back out of
/// the JSON and safe-deserializes them on the side of the tree that can.
///
/// The linker itself is indifferent: it hashes the transport key verbatim and enforces no
/// structure. A real container is used anyway so that every reference record is a request a
/// consumer could actually have sent, not a width with arbitrary bytes behind it.
const REFERENCE_CONTAINER_MLKEM_512_HEX: &str = concat!(
    "0300000000000000302e35000000000300000000000000302e311300000000000000556e69666965645075626c6963456e634b65790000000000000000200300",
    "000000000050813ec9f7b53c004191429786739a5660a2a05451c5431c0815745c43956f175449da6cd4702335acaa51064f761508cb262b0457561086a28ee5",
    "acd3ecbe7be095d554b34b61bde9744a7cc67f1189a2714180cf0c4475548813a970e26011a0c0bf28e56b5a16608ff2c7103583f95240a7a18bc37aaace2120",
    "9bea85b50c2ecbb08a6921b0d5909bd71c40461b099dd79b56d972e75b6c502b42075ab2dcc26f85b34a4ef34060452b440173fbb95082d2acc42565b4e9a954",
    "63b9c39ab14714b33349245447b25a42035d64a7371959bac5831f94b3bdc3095e31769d211f9b17b4966ba00cd68bfab42693205c7e349e08527bc5e982256b",
    "9d7e57ce59cb706b160519b1a7c473918e754540dc1c5b14707f6002c7aa7d87c300ead080296683a5c30a73e74b7107087f5760c90350b125bb9e5530af1409",
    "f5900b396116d37306c391a5b7137e1d7720ca58a41af79f9065b1bc01c5fe31cba5ea55b682b537b36cce9b23e5826d2fca0abe86b44ec639f5832d5f7b2278",
    "a4685e4249faa8441b31198f5566f3599fa3675e97aa40cf62a25d3715d5656aa3647641016bcd329717667f1a090dd5f94873c558366614f39a3e93b14f3886",
    "6812616e3b83189e17cc26526a96106696b6548cbaa8a4f222ee31ac72e16a5077c699fb1a3fe68673a8293a21c0e34ccb42e32249f22d3924974dc92f25d60c",
    "37424110892d5e1217a03c15efe4ad49248fe2776b2b65b71f140c7e0ba53c6b4c09992e17799a5ee65247f428b20739a92898eff5acd455c52d02285bcccd82",
    "0767ddf38e4a6026f32802bc9b6fba6b077becc1b5e23653607c592c3a86d56bf103c3d64b01fc7aba912138a8000a872b3af36c8346069fb2756e0ee41e9b03",
    "33bb9994b6cb4e6d1a190df45bc3369fa2f12ad63b8376952335b159b696ba5ec6771903c55361649428b856195dd37a1fbad85d5b9054e0e70250c8a590028e",
    "4bc1385864549be00d96a642ce4b0a88f7b447e627a4702bb4278c4d09812f24293a129f56c96a83faa779504c165c97eec81d535a0458904a73905404b16db9",
    "f5bd23f420cca76e5b13555b19f7e2d43cde771f93dcda9d280f2967e16a9c1f7db8cc2d48",
);

/// The public Solana clusters, name and genesis hash, as the reviewed registry records them.
///
/// Each value was read from that cluster's public RPC — `getGenesisHash` against
/// `https://api.<cluster>.solana.com` — rather than copied from documentation. mainnet-beta's is
/// additionally the genesis the `wrong-chain-id` record already carries ([`OTHER_GENESIS`]), and a
/// test below pins the two to be the same string.
const PUBLIC_CLUSTERS: &[(&str, &str)] = &[
    ("mainnet-beta", OTHER_GENESIS),
    ("devnet", "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"),
    ("testnet", "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"),
];

/// What the registry is for, written into the file for non-Rust consumers.
const CLUSTER_REGISTRY_NOTE: &str = concat!(
    "The reviewed registry of public-cluster chain ids, published here rather than in a ",
    "second document so that the deployment procedure and this fixture set cannot disagree: a ",
    "cluster configuration is correct exactly when its chain id equals the entry below, and each ",
    "entry is the chain_id_derivation_rule applied to the genesis hash beside it. Genesis hashes ",
    "were read from each cluster's public RPC (getGenesisHash), not transcribed from ",
    "documentation. Registering a further cluster means adding it here and regenerating; these ",
    "three are the ones a deployment review is expected to check against. No KMS code path derives ",
    "a chain id — a party reads the one the handles embed — so this section is a deployment-time ",
    "and SDK-side surface, not an input to the linker.",
);

/// Provenance of the shared inputs, written into the file so a reader of the JSON alone can tell
/// which values are supposed to match the permit set and which are this layer's own.
const SHARED_INPUTS: &str = concat!(
    "Recipient, verifying program id, KMS context and epoch ids and the reference cluster are the ",
    "fhevm permit set's (test-fixtures/permit/permit_v1.json, record ",
    "reference-permit-two-domains): the two halves of the specification's fixture set bind the ",
    "same objects. Handles are this layer's own — the permit carries none. Two deliberate ",
    "divergences from the permit set as it stands today: (1) chain ids here are derived by the ",
    "settled zama-solana-chain-id-v1 rule, while the permit set still records a stand-in ",
    "derivation, so the same genesis hash yields a different id there and that set is due for ",
    "regeneration; (2) the canonical transport key here is the 869-byte serialized ",
    "UnifiedPublicEncKey::MlKem512 container a KMS request actually carries — the selected ",
    "permit-v1 representation, which the permit signs as well — while the permit set still ",
    "records the bare 800-byte encapsulation key under the shared name reference-mlkem-512 and ",
    "regenerates to this container. The bare key survives here only as bare-mlkem-512-800, in a ",
    "negative record: production request validation rejects that width, and the linker's ",
    "indifference to it is the one thing the record shows.",
);

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// Expected outcome of a record. `acceptable` has no meaning at this layer: a link either is or is
/// not the one a response must carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VectorResult {
    /// A well-formed request the canonical binding accepts, whose recorded link is the one a
    /// conforming response must carry.
    Valid,
    /// Must be rejected, by the layer named in `class` and the rule named in `rule`.
    Invalid,
}

/// Which layer rejects a record, and therefore what a consumer must assert about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum VectorClass {
    /// Accepted, and its link is the reference for these fields.
    Valid,
    /// Constructible, but its link differs from its base's: a response carrying this link answers a
    /// different request, and l3 byte equality rejects it.
    LinkDivergence,
    /// The canonical constructor refuses these fields; no link exists for them.
    ConstructionReject,
    /// A 32-byte value computed over the same fields under a scheme tag this version does not
    /// define. It is not the v1 link, and l3 must reject it on byte inequality alone — no consumer
    /// may parse the tag out of a response to decide.
    ForeignSchemeLink,
}

/// Which check refuses a `construction-reject` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RejectedBy {
    /// `SolanaUserDecryptBinding::new`.
    Constructor,
    /// `SolanaUserDecryptBinding::validate_declared_chain_id`, for a caller that holds a chain id
    /// of its own alongside the request.
    DeclaredChainIdCheck,
}

/// A vector file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VectorFile {
    /// Schema identifier.
    schema: String,
    /// What this file covers, in prose.
    description: String,
    /// Which generator produced it.
    generator: String,
    /// How to regenerate it.
    regenerate_with: String,
    /// Companion file holding this set's SHA-256, and how the digest is compared across repositories.
    set_digest_file: String,
    /// The cross-repository contract, in prose.
    set_digest_contract: String,
    /// Which inputs are shared with the permit set, and where the two diverge today.
    shared_inputs: String,
    /// Frozen tag of the chain-id derivation rule.
    chain_id_derivation: String,
    /// The rule itself, in prose.
    chain_id_derivation_rule: String,
    /// What the registry below is, and who else reads it.
    cluster_registry_note: String,
    /// The reviewed registry: public cluster name to its genesis hash and derived chain id.
    ///
    /// This is the surface a deployment review checks a cluster configuration against. It is not an
    /// input to anything in this set — no record reads it — which is deliberate: the registry and
    /// the records derive their ids by one call to one function, so an entry that disagreed with a
    /// record's derivation would be a bug in the rule, not a stale table.
    cluster_registry: BTreeMap<String, ClusterEntry>,
    /// The linker scheme tag every `valid` record is computed under.
    scheme_tag: String,
    /// The linker call separator, ASCII.
    dsep: String,
    /// The list-setting separator the KMS list hash prepends ahead of the call separator, ASCII.
    dsep_list: String,
    /// Transport keys by name. Kept out of the records because one key is 1600 hex characters and
    /// would make every diff unreadable.
    transport_keys: BTreeMap<String, String>,
    /// The records, in a fixed order: valid, then link divergences, then construction rejects, then
    /// foreign-scheme links.
    records: Vec<Record>,
}

/// One registry entry: a public cluster's genesis hash and the chain id the rule derives from it.
///
/// The three chain-id forms are the same three every record carries, spelled the same way, so that
/// a consumer comparing its own configuration against this file needs one parser, not two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ClusterEntry {
    /// Cluster genesis hash, base58 — the form `getGenesisHash` returns and the rule consumes.
    genesis_hash: String,
    /// The same genesis hash as bytes, hex.
    genesis_hash_bytes: String,
    /// Chain id, decimal string.
    chain_id_decimal: String,
    /// Chain id, `0x`-prefixed hex.
    chain_id_hex: String,
    /// Chain id as the eight big-endian bytes the handles embed and the linker hashes, hex.
    chain_id_be_bytes: String,
}

/// One record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Record {
    /// Stable identifier, referenced by `derived_from`.
    name: String,
    /// What this record is for, in prose.
    comment: String,
    /// Expected outcome.
    result: VectorResult,
    /// Which layer decides the outcome.
    class: VectorClass,
    /// For a rejecting record: the rule that must reject it, from the closed dictionary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rule: Option<String>,
    /// For a rejecting record: the accepted record it was derived from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    derived_from: Option<String>,
    /// For a rejecting record: the single change applied to that base.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mutation: Option<String>,
    /// For a `construction-reject` record: which check refuses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rejected_by: Option<RejectedBy>,
    /// Cluster genesis hash, base58 — the form the derivation rule consumes.
    genesis_hash: String,
    /// The same genesis hash as bytes, hex.
    genesis_hash_bytes: String,
    /// Chain id, decimal string.
    chain_id_decimal: String,
    /// Chain id, `0x`-prefixed hex.
    chain_id_hex: String,
    /// Chain id as the eight big-endian bytes the handles embed and the linker hashes, hex.
    chain_id_be_bytes: String,
    /// A chain id declared separately from the request, decimal string. Present only where a record
    /// exists to exercise that check; the linker does not hash it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    declared_chain_id_decimal: Option<String>,
    /// The recipient, hex. A conforming request carries 32 bytes; wrong-width records do not.
    receiver_id: String,
    /// The verifying program id, hex.
    verifying_program_id: String,
    /// The KMS context id, hex.
    kms_context_id: String,
    /// The KMS epoch id, hex.
    kms_epoch_id: String,
    /// The ciphertext handles in request order, hex, duplicates preserved.
    handles: Vec<String>,
    /// Name of this record's transport key in the file's `transport_keys` table.
    transport_key: String,
    /// The scheme tag this record's preimage opens with.
    scheme_tag: String,
    /// The call separator this record's preimage uses.
    dsep: String,
    /// The full byte sequence the hasher consumes — `HASH_LST ‖ dsep ‖ u64le(count) ‖ elements` —
    /// hex. Absent exactly when no link exists for the record. Present so that five implementations
    /// can compare their construction before comparing digests, which is where a one-byte
    /// disagreement is actually diagnosable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    linker_hasher_input: Option<String>,
    /// SHAKE-256 of `linker_hasher_input`, 32 bytes, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    link: Option<String>,
}

/// Rule names used by [`Record::rule`], as a closed dictionary.
///
/// The names are part of the cross-implementation contract: each implementation maps its own error
/// type onto these, which is how "every implementation rejects for the same reason" becomes
/// checkable rather than aspirational. They are deliberately coarser than the binding's error enum —
/// no indices, no lengths — and `identity-width` is spelled the same way as in the permit set so
/// that a consumer of both files needs one mapping, not two.
mod rule {
    // link-divergence
    pub const CHANGED_HANDLE: &str = "changed-handle";
    pub const CHANGED_HANDLE_ORDER: &str = "changed-handle-order";
    pub const WRONG_TRANSPORT_KEY: &str = "wrong-transport-key";
    pub const WRONG_RECIPIENT: &str = "wrong-recipient";
    pub const WRONG_VERIFYING_PROGRAM_ID: &str = "wrong-verifying-program-id";
    pub const WRONG_KMS_CONTEXT: &str = "wrong-kms-context";
    pub const WRONG_KMS_EPOCH: &str = "wrong-kms-epoch";
    pub const WRONG_CHAIN_ID: &str = "wrong-chain-id";
    pub const DUPLICATED_HANDLE: &str = "duplicated-handle";

    // construction-reject
    pub const EMPTY_HANDLE_LIST: &str = "empty-handle-list";
    pub const HANDLE_WIDTH: &str = "handle-width";
    pub const HANDLE_CHAIN_KIND_BIT: &str = "handle-chain-kind-bit";
    pub const MIXED_EMBEDDED_CHAIN_IDS: &str = "mixed-embedded-chain-ids";
    pub const DECLARED_CHAIN_ID_MISMATCH: &str = "declared-chain-id-mismatch";
    pub const IDENTITY_WIDTH: &str = "identity-width";

    // foreign-scheme-link
    pub const UNKNOWN_SCHEME_VERSION: &str = "unknown-scheme-version";
    pub const CROSS_VERSION_REPLAY: &str = "cross-version-replay";

    /// Every rule name, for coverage checks in both directions.
    pub const ALL: &[&str] = &[
        CHANGED_HANDLE,
        CHANGED_HANDLE_ORDER,
        WRONG_TRANSPORT_KEY,
        WRONG_RECIPIENT,
        WRONG_VERIFYING_PROGRAM_ID,
        WRONG_KMS_CONTEXT,
        WRONG_KMS_EPOCH,
        WRONG_CHAIN_ID,
        DUPLICATED_HANDLE,
        EMPTY_HANDLE_LIST,
        HANDLE_WIDTH,
        HANDLE_CHAIN_KIND_BIT,
        MIXED_EMBEDDED_CHAIN_IDS,
        DECLARED_CHAIN_ID_MISMATCH,
        IDENTITY_WIDTH,
        UNKNOWN_SCHEME_VERSION,
        CROSS_VERSION_REPLAY,
    ];
}

// ---------------------------------------------------------------------------
// Base58 and the chain-id derivation rule
// ---------------------------------------------------------------------------

/// Bitcoin/Solana base58 alphabet.
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decodes base58, or `None` on a symbol outside the alphabet.
///
/// Written out rather than taken from a crate: the workspace ships no base58 direct dependency, and
/// a normative generator adding one for twenty lines of long division is a worse trade than the
/// twenty lines. `base58_round_trips_known_solana_values` pins it against real genesis hashes.
fn base58_decode(text: &str) -> Option<Vec<u8>> {
    let mut digits: Vec<u8> = Vec::new();

    for symbol in text.bytes() {
        let mut carry = BASE58_ALPHABET.iter().position(|c| *c == symbol)? as u32;
        for digit in digits.iter_mut().rev() {
            let value = u32::from(*digit) * 58 + carry;
            *digit = (value & 0xff) as u8;
            carry = value >> 8;
        }
        while carry > 0 {
            digits.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    // A leading '1' is the digit zero, which the long division above cannot distinguish from
    // "nothing yet"; each one is a leading zero byte of the decoded value.
    let mut decoded = vec![0u8; text.bytes().take_while(|symbol| *symbol == b'1').count()];
    decoded.extend_from_slice(&digits);
    Some(decoded)
}

/// The settled deployment-time rule: `0x8000000000000000 | (be_u64(SHA-256(tag ‖ genesis)[0..8]) &
/// 0x7fffffffffffffff)`.
///
/// Test-side only. Production KMS never derives a chain id — it reads the one the handles embed —
/// which is why this lives in the vector generator and not in the crate.
fn derive_chain_id(genesis_hash_base58: &str) -> u64 {
    let genesis = base58_decode(genesis_hash_base58).expect("a base58 genesis hash");

    let mut hasher = Sha256::new();
    hasher.update(CHAIN_ID_DERIVATION_TAG.as_bytes());
    hasher.update(&genesis);
    let digest = hasher.finalize();

    let leading = u64::from_be_bytes(digest[..8].try_into().expect("eight bytes"));
    CHAIN_KIND_BIT | (leading & !CHAIN_KIND_BIT)
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

fn bytes(hex_string: &str) -> Vec<u8> {
    hex::decode(hex_string).expect("a hex literal in this file")
}

/// A ciphertext handle on `chain_id`, its filler derived from `index` so that no two handles of one
/// request are confusable and no run of equal bytes can hide a layout error.
fn handle(chain_id: u64, index: u8) -> Vec<u8> {
    let mut bytes = Sha256::digest(format!("{HANDLE_DERIVATION_TAG}{index}").as_bytes()).as_slice()
        [..32]
        .to_vec();
    bytes[22..30].copy_from_slice(&chain_id.to_be_bytes());
    bytes
}

/// The transport keys, by name.
fn transport_keys() -> BTreeMap<String, Vec<u8>> {
    // A real serialized UnifiedPublicEncKey::MlKem512, not a filler of the right width: see
    // REFERENCE_CONTAINER_MLKEM_512_HEX for the seed and the expression that produced it.
    let reference = bytes(REFERENCE_CONTAINER_MLKEM_512_HEX);
    assert_eq!(
        reference.len(),
        869,
        "the canonical key is the width a request carries",
    );

    // The reference key with its first byte flipped: a different key of the same width. The
    // smallest possible difference is the strongest test — the linker binds bytes, so a one-bit
    // substitution must move the link exactly as far as a wholly different key would.
    let mut attacker = reference.clone();
    attacker[0] ^= 0xff;

    let bare = bytes(BARE_MLKEM_512_HEX);
    assert_eq!(
        bare.len(),
        800,
        "the bare key is the raw encapsulation-key width",
    );

    BTreeMap::from([
        (TRANSPORT_REFERENCE.to_string(), reference),
        (TRANSPORT_ATTACKER.to_string(), attacker),
        (TRANSPORT_BARE.to_string(), bare),
    ])
}

/// The request fields of one record, before they are rendered as hex.
#[derive(Clone, Debug)]
struct Inputs {
    genesis: &'static str,
    verifying_program_id: Vec<u8>,
    receiver_id: Vec<u8>,
    kms_context_id: Vec<u8>,
    kms_epoch_id: Vec<u8>,
    handles: Vec<Vec<u8>>,
    transport_key: &'static str,
    declared_chain_id: Option<u64>,
}

impl Inputs {
    /// The reference request: the permit set's identities, two handles, the shared transport key.
    fn reference() -> Self {
        let chain_id = derive_chain_id(REFERENCE_GENESIS);
        Self {
            genesis: REFERENCE_GENESIS,
            verifying_program_id: bytes(VERIFYING_PROGRAM_ID_HEX),
            receiver_id: bytes(RECEIVER_ID_HEX),
            kms_context_id: bytes(KMS_CONTEXT_ID_HEX),
            kms_epoch_id: bytes(KMS_EPOCH_ID_HEX),
            handles: vec![handle(chain_id, 1), handle(chain_id, 2)],
            transport_key: TRANSPORT_REFERENCE,
            declared_chain_id: None,
        }
    }

    fn chain_id(&self) -> u64 {
        derive_chain_id(self.genesis)
    }

    fn with_handles(mut self, handles: Vec<Vec<u8>>) -> Self {
        self.handles = handles;
        self
    }

    fn transport_key_bytes(&self) -> Vec<u8> {
        transport_keys()
            .remove(self.transport_key)
            .expect("every named transport key is in the table")
    }

    fn try_build(&self) -> Result<SolanaUserDecryptBinding, SolanaUserDecryptBindingError> {
        SolanaUserDecryptBinding::new(
            &self.verifying_program_id,
            &self.receiver_id,
            &self.kms_context_id,
            &self.kms_epoch_id,
            self.handles.iter().map(|handle| handle.as_slice()),
            &self.transport_key_bytes(),
        )
    }
}

// ---------------------------------------------------------------------------
// Building the set
// ---------------------------------------------------------------------------

/// The retired v0 scheme tag: gone from the implementation, it appears here only as the thing a
/// response must not be believed for. The JSON carries it in full — that is the vector.
fn retired_scheme_tag() -> String {
    ["SolanaUserDecryptionLinker", ":v0"].concat()
}

/// A scheme version this implementation does not define.
fn unknown_scheme_tag() -> String {
    ["SolanaUserDecryptionLinker", ":v2"].concat()
}

/// A record before its bytes are computed.
struct Draft {
    name: &'static str,
    comment: &'static str,
    result: VectorResult,
    class: VectorClass,
    rule: Option<&'static str>,
    derived_from: Option<&'static str>,
    mutation: Option<&'static str>,
    rejected_by: Option<RejectedBy>,
    scheme_tag: String,
    inputs: Inputs,
}

impl Draft {
    fn valid(name: &'static str, comment: &'static str, inputs: Inputs) -> Self {
        Self {
            name,
            comment,
            result: VectorResult::Valid,
            class: VectorClass::Valid,
            rule: None,
            derived_from: None,
            mutation: None,
            rejected_by: None,
            scheme_tag: canonical_scheme_tag(),
            inputs,
        }
    }

    fn invalid(
        name: &'static str,
        comment: &'static str,
        class: VectorClass,
        rule: &'static str,
        derived_from: &'static str,
        mutation: &'static str,
        inputs: Inputs,
    ) -> Self {
        Self {
            name,
            comment,
            result: VectorResult::Invalid,
            class,
            rule: Some(rule),
            derived_from: Some(derived_from),
            mutation: Some(mutation),
            rejected_by: matches!(class, VectorClass::ConstructionReject)
                .then_some(RejectedBy::Constructor),
            scheme_tag: canonical_scheme_tag(),
            inputs,
        }
    }

    fn rejected_by(mut self, rejected_by: RejectedBy) -> Self {
        self.rejected_by = Some(rejected_by);
        self
    }

    fn under_scheme_tag(mut self, scheme_tag: String) -> Self {
        self.scheme_tag = scheme_tag;
        self
    }
}

fn canonical_scheme_tag() -> String {
    String::from_utf8(SOLANA_LINKER_SCHEME_TAG.to_vec()).expect("the scheme tag is ASCII")
}

fn canonical_dsep() -> String {
    String::from_utf8(DSEP_SOLANA_LINKER.to_vec()).expect("the separator is ASCII")
}

/// The specified preimage and its digest, for a scheme tag other than v1.
///
/// Assembled here rather than through the canonical function, which only knows v1. Everything but
/// the first element is identical to what the canonical function would hash for the same fields,
/// which is precisely the point: the *only* thing that differs is the tag, and the resulting 32
/// bytes must still not be mistaken for the v1 link.
fn foreign_scheme_bytes(inputs: &Inputs, scheme_tag: &str) -> (Vec<u8>, Vec<u8>) {
    let chain_id = inputs.chain_id().to_be_bytes();
    let transport_key = inputs.transport_key_bytes();

    let mut elements: Vec<&[u8]> = vec![
        scheme_tag.as_bytes(),
        &inputs.verifying_program_id,
        &chain_id,
        &inputs.receiver_id,
        &inputs.kms_context_id,
        &inputs.kms_epoch_id,
    ];
    elements.extend(inputs.handles.iter().map(|handle| handle.as_slice()));
    elements.push(&transport_key);

    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(&DSEP_LIST);
    hasher_input.extend_from_slice(&DSEP_SOLANA_LINKER);
    hasher_input.extend_from_slice(&(elements.len() as u64).to_le_bytes());
    for element in &elements {
        hasher_input.extend_from_slice(element);
    }

    (
        hasher_input,
        unsafe_hash_list_w_size(&DSEP_SOLANA_LINKER, &elements, LINK_LEN),
    )
}

fn finish(draft: Draft) -> Record {
    let chain_id = draft.inputs.chain_id();
    let canonical = draft.scheme_tag == canonical_scheme_tag();

    let (hasher_input, link) = match (canonical, draft.inputs.try_build()) {
        (true, Ok(binding)) => (
            Some(hex::encode(binding.linker_hasher_input())),
            Some(hex::encode(binding.compute_link())),
        ),
        (false, Ok(_)) => {
            let (input, link) = foreign_scheme_bytes(&draft.inputs, &draft.scheme_tag);
            (Some(hex::encode(input)), Some(hex::encode(link)))
        }
        // The fields do not form a request, so no link exists for them. That absence is the record.
        (_, Err(_)) => (None, None),
    };

    Record {
        name: draft.name.to_string(),
        comment: draft.comment.to_string(),
        result: draft.result,
        class: draft.class,
        rule: draft.rule.map(str::to_string),
        derived_from: draft.derived_from.map(str::to_string),
        mutation: draft.mutation.map(str::to_string),
        rejected_by: draft.rejected_by,
        genesis_hash: draft.inputs.genesis.to_string(),
        genesis_hash_bytes: hex::encode(
            base58_decode(draft.inputs.genesis).expect("a base58 genesis hash"),
        ),
        chain_id_decimal: chain_id.to_string(),
        chain_id_hex: format!("0x{chain_id:016x}"),
        chain_id_be_bytes: hex::encode(chain_id.to_be_bytes()),
        declared_chain_id_decimal: draft
            .inputs
            .declared_chain_id
            .map(|declared| declared.to_string()),
        receiver_id: hex::encode(&draft.inputs.receiver_id),
        verifying_program_id: hex::encode(&draft.inputs.verifying_program_id),
        kms_context_id: hex::encode(&draft.inputs.kms_context_id),
        kms_epoch_id: hex::encode(&draft.inputs.kms_epoch_id),
        handles: draft.inputs.handles.iter().map(hex::encode).collect(),
        transport_key: draft.inputs.transport_key.to_string(),
        scheme_tag: draft.scheme_tag,
        dsep: canonical_dsep(),
        linker_hasher_input: hasher_input,
        link,
    }
}

/// Every record, in a fixed order.
fn drafts() -> Vec<Draft> {
    let reference_chain_id = derive_chain_id(REFERENCE_GENESIS);
    let other_chain_id = derive_chain_id(OTHER_GENESIS);
    let h = |index: u8| handle(reference_chain_id, index);
    let other = |index: u8| handle(other_chain_id, index);

    let mut drafts = vec![
        // --- valid ---------------------------------------------------------
        Draft::valid(
            "reference-two-handles",
            "The reference request: the permit set's recipient, program id and KMS pair, two \
             handles on the permit set's cluster, and the canonical transport key — the 869-byte \
             serialized UnifiedPublicEncKey::MlKem512 container a KMS request actually carries. \
             Every record below that names a base names this one unless it says otherwise.",
            Inputs::reference(),
        ),
        Draft::valid(
            "single-handle",
            "One handle. Base for the duplication record, and the smallest element count the \
             construction admits (8 = 7 + 1).",
            Inputs::reference().with_handles(vec![h(1)]),
        ),
        Draft::valid(
            "duplicates-bind-by-position",
            "The same handle named twice, at positions 0 and 2. Duplicates are legal — each \
             occurrence is authorized independently on chain and the linker binds every occurrence \
             at its position — so this must be accepted, and its link must differ from any list \
             that collapses the repeat.",
            Inputs::reference().with_handles(vec![h(1), h(2), h(1)]),
        ),
        Draft::valid(
            "eight-handles",
            "A batch: element count 15 = 7 + 8, well past a single-byte count, so a consumer that \
             wrote the count as anything narrower than u64 little-endian still agrees here.",
            Inputs::reference().with_handles((1..=8).map(h).collect()),
        ),
        // --- link divergence -----------------------------------------------
        Draft::invalid(
            "bare-encapsulation-key-width",
            "The bare 800-byte ML-KEM-512 encapsulation key — the permit set's current reference \
             key — in place of the canonical 869-byte container. No conforming request carries \
             this width: production KMS request validation rejects it before any linker runs. The \
             linker as an algorithm enforces no width — that rule lives in the request layer, the \
             wallet permit and the connector — so a link exists for these fields, and the record \
             pins that it is not the reference link: a consumer that froze the bare key as its \
             linker input diverges here.",
            VectorClass::LinkDivergence,
            rule::WRONG_TRANSPORT_KEY,
            "reference-two-handles",
            "the transport key replaced by the bare 800-byte encapsulation key, a width request \
             validation rejects",
            Inputs {
                transport_key: TRANSPORT_BARE,
                ..Inputs::reference()
            },
        ),
        Draft::invalid(
            "changed-handle",
            "One handle replaced by another on the same cluster. A relayer substituting a handle \
             the client never asked for must not produce a response the client accepts.",
            VectorClass::LinkDivergence,
            rule::CHANGED_HANDLE,
            "reference-two-handles",
            "the second handle replaced by a third handle on the same cluster",
            Inputs::reference().with_handles(vec![h(1), h(3)]),
        ),
        Draft::invalid(
            "changed-handle-order",
            "The same two handles, swapped. Order is bound, so a reordered batch is a request the \
             client did not make rather than the same request answered differently.",
            VectorClass::LinkDivergence,
            rule::CHANGED_HANDLE_ORDER,
            "reference-two-handles",
            "the two handles swapped",
            Inputs::reference().with_handles(vec![h(2), h(1)]),
        ),
        Draft::invalid(
            "wrong-transport-key",
            "The substitution this closes: an attacker swapping in a transport key they hold would \
             otherwise receive the result sealed to themselves. The key here differs from the \
             reference in one byte.",
            VectorClass::LinkDivergence,
            rule::WRONG_TRANSPORT_KEY,
            "reference-two-handles",
            "the transport key replaced by a different key of the same width",
            Inputs {
                transport_key: TRANSPORT_ATTACKER,
                ..Inputs::reference()
            },
        ),
        Draft::invalid(
            "wrong-recipient",
            "A result signcrypted to a different wallet key answers a different request.",
            VectorClass::LinkDivergence,
            rule::WRONG_RECIPIENT,
            "reference-two-handles",
            "the recipient's first byte flipped",
            Inputs {
                receiver_id: flip_first(&bytes(RECEIVER_ID_HEX)),
                ..Inputs::reference()
            },
        ),
        Draft::invalid(
            "wrong-verifying-program-id",
            "One half of the deployment domain: the same handles under a different program are a \
             different deployment, even on the same cluster.",
            VectorClass::LinkDivergence,
            rule::WRONG_VERIFYING_PROGRAM_ID,
            "reference-two-handles",
            "the verifying program id's first byte flipped",
            Inputs {
                verifying_program_id: flip_first(&bytes(VERIFYING_PROGRAM_ID_HEX)),
                ..Inputs::reference()
            },
        ),
        Draft::invalid(
            "wrong-kms-context",
            "The party set that produced the result. A response from a different context answers a \
             different question, however similar the request looks.",
            VectorClass::LinkDivergence,
            rule::WRONG_KMS_CONTEXT,
            "reference-two-handles",
            "the KMS context id's first byte flipped",
            Inputs {
                kms_context_id: flip_first(&bytes(KMS_CONTEXT_ID_HEX)),
                ..Inputs::reference()
            },
        ),
        Draft::invalid(
            "wrong-kms-epoch",
            "The share generation. Same context, different epoch, different result.",
            VectorClass::LinkDivergence,
            rule::WRONG_KMS_EPOCH,
            "reference-two-handles",
            "the KMS epoch id's first byte flipped",
            Inputs {
                kms_epoch_id: flip_first(&bytes(KMS_EPOCH_ID_HEX)),
                ..Inputs::reference()
            },
        ),
        Draft::invalid(
            "wrong-chain-id",
            "The other half of the deployment domain, and it does not travel as its own field: it \
             is read out of the handles, so a second cluster necessarily changes the handles too. \
             One program id deployed to two clusters yields two distinct links. The cluster here is \
             Solana mainnet-beta, so the derived id is a value other implementations can check \
             against their own configuration.",
            VectorClass::LinkDivergence,
            rule::WRONG_CHAIN_ID,
            "reference-two-handles",
            "the deployment moved to a second cluster, re-embedding its chain id in both handles",
            Inputs {
                genesis: OTHER_GENESIS,
                ..Inputs::reference()
            }
            .with_handles(vec![other(1), other(2)]),
        ),
        Draft::invalid(
            "duplicated-handle",
            "[h, h] against [h]: duplicates are legal but bound positionally, never collapsed, so \
             a response to a deduplicated list must not verify against the request that named the \
             handle twice.",
            VectorClass::LinkDivergence,
            rule::DUPLICATED_HANDLE,
            "single-handle",
            "the single handle named a second time",
            Inputs::reference().with_handles(vec![h(1), h(1)]),
        ),
        // --- construction reject -------------------------------------------
        Draft::invalid(
            "empty-handle-list",
            "A request naming nothing. There is no link for it, and producing one would mean \
             signcrypting a result to a request with no content.",
            VectorClass::ConstructionReject,
            rule::EMPTY_HANDLE_LIST,
            "reference-two-handles",
            "the handle list emptied",
            Inputs::reference().with_handles(vec![]),
        ),
        Draft::invalid(
            "handle-of-wrong-width",
            "A 31-byte handle. Every element before the transport key has a position-determined \
             width; admitting a short one would break the injectivity the element count relies on.",
            VectorClass::ConstructionReject,
            rule::HANDLE_WIDTH,
            "reference-two-handles",
            "the second handle truncated to 31 bytes",
            Inputs::reference().with_handles(vec![h(1), h(2)[..31].to_vec()]),
        ),
        Draft::invalid(
            "handle-without-the-chain-kind-bit",
            "An EVM-kind handle mixed into a Solana batch, at index 1 rather than 0 so that a \
             check which trusts the first handle fails here. The chain-kind bit is the only \
             structural separator between the two request families.",
            VectorClass::ConstructionReject,
            rule::HANDLE_CHAIN_KIND_BIT,
            "reference-two-handles",
            "the second handle's embedded chain id stripped of bit 63",
            Inputs::reference()
                .with_handles(vec![h(1), handle(reference_chain_id & !CHAIN_KIND_BIT, 2)]),
        ),
        Draft::invalid(
            "mixed-embedded-chain-ids",
            "Two Solana-kind handles from two clusters. Without this check a batch could mix \
             deployments and still produce one link.",
            VectorClass::ConstructionReject,
            rule::MIXED_EMBEDDED_CHAIN_IDS,
            "reference-two-handles",
            "the second handle re-embedded with the mainnet-beta chain id",
            Inputs::reference().with_handles(vec![h(1), other(2)]),
        ),
        Draft::invalid(
            "declared-chain-id-mismatch",
            "A caller holding a chain id of its own — the client recomputing a link from its signed \
             permit fields — declares one cluster while the handles embed another. Note what the \
             link says: the declared value is not hashed, so this record's link equals the \
             reference link exactly. The mismatch is a request-validation rule, checked by \
             validate_declared_chain_id, and a consumer that only compared links would miss it.",
            VectorClass::ConstructionReject,
            rule::DECLARED_CHAIN_ID_MISMATCH,
            "reference-two-handles",
            "a declared chain id naming the mainnet-beta cluster instead of the embedded one",
            Inputs {
                declared_chain_id: Some(other_chain_id),
                ..Inputs::reference()
            },
        )
        .rejected_by(RejectedBy::DeclaredChainIdCheck),
        Draft::invalid(
            "recipient-of-wrong-width",
            "A 20-byte recipient: an EVM address, or a truncated key, offered as a Solana identity. \
             The recipient is a checked 32-byte value end to end.",
            VectorClass::ConstructionReject,
            rule::IDENTITY_WIDTH,
            "reference-two-handles",
            "the recipient truncated to 20 bytes",
            Inputs {
                receiver_id: bytes(RECEIVER_ID_HEX)[..20].to_vec(),
                ..Inputs::reference()
            },
        ),
        Draft::invalid(
            "verifying-program-id-of-wrong-width",
            "A 33-byte program id: long rather than short, so that a length check written as \
             \"at least 32\" fails here.",
            VectorClass::ConstructionReject,
            rule::IDENTITY_WIDTH,
            "reference-two-handles",
            "the verifying program id extended to 33 bytes",
            Inputs {
                verifying_program_id: extend_by_one(&bytes(VERIFYING_PROGRAM_ID_HEX)),
                ..Inputs::reference()
            },
        ),
        Draft::invalid(
            "kms-context-id-of-wrong-width",
            "A 31-byte KMS context id.",
            VectorClass::ConstructionReject,
            rule::IDENTITY_WIDTH,
            "reference-two-handles",
            "the KMS context id truncated to 31 bytes",
            Inputs {
                kms_context_id: bytes(KMS_CONTEXT_ID_HEX)[..31].to_vec(),
                ..Inputs::reference()
            },
        ),
        Draft::invalid(
            "kms-epoch-id-of-wrong-width",
            "A 33-byte KMS epoch id.",
            VectorClass::ConstructionReject,
            rule::IDENTITY_WIDTH,
            "reference-two-handles",
            "the KMS epoch id extended to 33 bytes",
            Inputs {
                kms_epoch_id: extend_by_one(&bytes(KMS_EPOCH_ID_HEX)),
                ..Inputs::reference()
            },
        ),
        // --- foreign scheme link -------------------------------------------
        Draft::invalid(
            "unknown-scheme-version",
            "The reference fields hashed under a scheme version this specification does not define. \
             A consumer must reject it on byte inequality with its own recomputed v1 link and must \
             not parse the tag out of the response to decide — the embedded link is never a source \
             of any value (l1).",
            VectorClass::ForeignSchemeLink,
            rule::UNKNOWN_SCHEME_VERSION,
            "reference-two-handles",
            "the scheme tag element replaced by an undefined later version",
            Inputs::reference(),
        )
        .under_scheme_tag(unknown_scheme_tag()),
        Draft::invalid(
            "cross-version-replay",
            "A response built for the retired scheme version, replayed against a v1 request. Stated \
             plainly: this is not v0's construction — v0 hashed keccak256 over ad-hoc u32-BE length \
             prefixes and is deleted, not reimplemented here. It is the v1 construction under the \
             v0 tag, which makes it the *closest* a retired-version value can get to the v1 link. \
             The normative content is only that it is not equal to it. Rejection itself happens at \
             l3 in the client, which is a core/service concern; this record supplies the bytes.",
            VectorClass::ForeignSchemeLink,
            rule::CROSS_VERSION_REPLAY,
            "reference-two-handles",
            "the scheme tag element replaced by the retired v0 tag",
            Inputs::reference(),
        )
        .under_scheme_tag(retired_scheme_tag()),
    ];

    drafts.sort_by_key(|draft| class_order(draft.class));
    drafts
}

/// Records are grouped by class, and within a class keep their declaration order.
fn class_order(class: VectorClass) -> u8 {
    match class {
        VectorClass::Valid => 0,
        VectorClass::LinkDivergence => 1,
        VectorClass::ConstructionReject => 2,
        VectorClass::ForeignSchemeLink => 3,
    }
}

fn flip_first(value: &[u8]) -> Vec<u8> {
    let mut flipped = value.to_vec();
    flipped[0] ^= 0xff;
    flipped
}

fn extend_by_one(value: &[u8]) -> Vec<u8> {
    let mut extended = value.to_vec();
    extended.push(0x00);
    extended
}

/// The reviewed registry, derived by the same [`derive_chain_id`] every record goes through.
fn cluster_registry() -> BTreeMap<String, ClusterEntry> {
    PUBLIC_CLUSTERS
        .iter()
        .map(|(cluster, genesis)| {
            let chain_id = derive_chain_id(genesis);
            (
                (*cluster).to_string(),
                ClusterEntry {
                    genesis_hash: (*genesis).to_string(),
                    genesis_hash_bytes: hex::encode(
                        base58_decode(genesis).expect("a base58 genesis hash"),
                    ),
                    chain_id_decimal: chain_id.to_string(),
                    chain_id_hex: format!("0x{chain_id:016x}"),
                    chain_id_be_bytes: hex::encode(chain_id.to_be_bytes()),
                },
            )
        })
        .collect()
}

fn build() -> VectorFile {
    VectorFile {
        schema: SCHEMA.to_string(),
        description:
            "Normative vectors for Solana user-decryption linker v1: the specified preimage and its \
             32-byte digest, the fields the linker binds, and the negatives that must not share a \
             link with them. Authorization rules — the wallet permit, its validity window, \
             delegation, ACL and lineage resolution — are a separate layer and are not covered here."
                .to_string(),
        generator: GENERATOR.to_string(),
        regenerate_with: format!(
            "{UPDATE_ENV}=1 cargo test -p kms-grpc --test solana_linker_vectors",
        ),
        set_digest_file: DIGEST_FILE.to_string(),
        set_digest_contract:
            "SHA-256 of this file's bytes, in sha256sum line format. Every repository holding a \
             copy of this set writes the same two files and CI compares the digests; a locally \
             adjusted or stale copy changes the digest and fails."
                .to_string(),
        shared_inputs: SHARED_INPUTS.to_string(),
        chain_id_derivation: CHAIN_ID_DERIVATION_TAG.to_string(),
        chain_id_derivation_rule: CHAIN_ID_DERIVATION_RULE.to_string(),
        cluster_registry_note: CLUSTER_REGISTRY_NOTE.to_string(),
        cluster_registry: cluster_registry(),
        scheme_tag: canonical_scheme_tag(),
        dsep: canonical_dsep(),
        dsep_list: String::from_utf8(DSEP_LIST.to_vec()).expect("the list separator is ASCII"),
        transport_keys: transport_keys()
            .into_iter()
            .map(|(name, key)| (name, hex::encode(key)))
            .collect(),
        records: drafts().into_iter().map(finish).collect(),
    }
}

// ---------------------------------------------------------------------------
// The committed files
// ---------------------------------------------------------------------------

fn vector_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors")
}

fn rendered(file: &VectorFile) -> String {
    let mut json = serde_json::to_string_pretty(file).expect("the set serializes");
    json.push('\n');
    json
}

fn digest_line(json: &str) -> String {
    format!("{}  {VECTOR_FILE}\n", hex::encode(Sha256::digest(json)))
}

/// Rewrites the committed set, once per process, when the update variable is set.
///
/// Every accessor forces this first, so the generator and the checks cannot race: a parallel test
/// either sees the pre-existing file or the freshly written one, never a half-written one.
static MATERIALIZED: LazyLock<()> = LazyLock::new(|| {
    if std::env::var_os(UPDATE_ENV).is_none() {
        return;
    }

    let json = rendered(&build());
    fs::create_dir_all(vector_dir()).expect("the vector directory is writable");
    fs::write(vector_dir().join(VECTOR_FILE), &json).expect("the vector file is writable");
    fs::write(vector_dir().join(DIGEST_FILE), digest_line(&json)).expect("the digest is writable");
});

fn committed_json() -> String {
    LazyLock::force(&MATERIALIZED);
    fs::read_to_string(vector_dir().join(VECTOR_FILE)).unwrap_or_else(|error| {
        panic!(
            "{VECTOR_FILE} is missing or unreadable ({error}). Regenerate it with \
             {UPDATE_ENV}=1 cargo test -p kms-grpc --test solana_linker_vectors",
        )
    })
}

fn committed_digest() -> String {
    LazyLock::force(&MATERIALIZED);
    fs::read_to_string(vector_dir().join(DIGEST_FILE)).expect("the digest file is readable")
}

/// The committed set, as a consumer in another repository would read it.
fn committed() -> VectorFile {
    serde_json::from_str(&committed_json()).expect("the committed set matches the schema")
}

// ---------------------------------------------------------------------------
// The consumer path
// ---------------------------------------------------------------------------

impl VectorFile {
    fn record(&self, name: &str) -> &Record {
        self.records
            .iter()
            .find(|record| record.name == name)
            .unwrap_or_else(|| panic!("no record named {name}"))
    }

    fn transport_key_bytes(&self, record: &Record) -> Vec<u8> {
        let key = self
            .transport_keys
            .get(&record.transport_key)
            .unwrap_or_else(|| panic!("{} names an unknown transport key", record.name));
        hex::decode(key).expect("a hex transport key")
    }
}

impl Record {
    /// Rebuilds the binding from the record alone — the path every consuming implementation takes.
    fn try_build(
        &self,
        file: &VectorFile,
    ) -> Result<SolanaUserDecryptBinding, SolanaUserDecryptBindingError> {
        let handles: Vec<Vec<u8>> = self
            .handles
            .iter()
            .map(|handle| hex::decode(handle).expect("a hex handle"))
            .collect();

        SolanaUserDecryptBinding::new(
            &hex::decode(&self.verifying_program_id).expect("hex"),
            &hex::decode(&self.receiver_id).expect("hex"),
            &hex::decode(&self.kms_context_id).expect("hex"),
            &hex::decode(&self.kms_epoch_id).expect("hex"),
            handles.iter().map(|handle| handle.as_slice()),
            &file.transport_key_bytes(self),
        )
    }

    fn link_bytes(&self) -> Vec<u8> {
        hex::decode(
            self.link
                .as_ref()
                .unwrap_or_else(|| panic!("{} has no link, but one was asked for", self.name)),
        )
        .expect("a hex link")
    }

    fn chain_id(&self) -> u64 {
        self.chain_id_decimal
            .parse()
            .unwrap_or_else(|_| panic!("{} has an unparseable chain id", self.name))
    }
}

/// Whether the binding's error is the one the record's rule names.
///
/// The dictionary is coarser than the error enum on purpose — `identity-width` covers all four
/// identities, as it does in the permit set — so this maps one rule onto the variants it admits.
fn rejection_matches(rule: &str, error: &SolanaUserDecryptBindingError) -> bool {
    use SolanaUserDecryptBindingError as Error;

    match rule {
        rule::EMPTY_HANDLE_LIST => matches!(error, Error::EmptyHandles),
        rule::HANDLE_WIDTH => matches!(error, Error::InvalidHandleLength { .. }),
        rule::HANDLE_CHAIN_KIND_BIT => matches!(error, Error::InvalidHandleChainId { .. }),
        rule::MIXED_EMBEDDED_CHAIN_IDS => matches!(error, Error::MixedChainIds { .. }),
        rule::DECLARED_CHAIN_ID_MISMATCH => matches!(
            error,
            Error::DeclaredChainIdMismatch { .. } | Error::InvalidDeclaredChainId { .. }
        ),
        rule::IDENTITY_WIDTH => matches!(
            error,
            Error::InvalidProgramIdLength { .. }
                | Error::InvalidReceiverLength { .. }
                | Error::InvalidContextIdLength { .. }
                | Error::InvalidEpochIdLength { .. }
        ),
        _ => false,
    }
}

fn records_of(file: &VectorFile, class: VectorClass) -> Vec<&Record> {
    file.records
        .iter()
        .filter(|record| record.class == class)
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn the_committed_set_is_what_the_canonical_function_produces() {
    // The whole point of generator-equals-runner: no committed byte may exist that this tree does
    // not reproduce, and the failure is a readable JSON diff rather than a digest mismatch.
    assert_eq!(
        committed_json(),
        rendered(&build()),
        "the committed set no longer matches the tree. If the change is intended, regenerate with \
         {UPDATE_ENV}=1 and remember that these bytes are frozen: a layout change is a version bump \
         in the scheme tag, not an edit.",
    );
}

#[test]
fn the_committed_digest_matches_the_set() {
    // The cross-repository mechanism: the digest file is what another repository's copy is
    // compared against, so it has to be right here before it can mean anything there.
    assert_eq!(committed_digest(), digest_line(&committed_json()));
}

#[test]
fn the_digest_file_is_a_single_sha256sum_line() {
    // Format is part of the contract: `sha256sum -c` must accept it unmodified.
    let line = committed_digest();
    let (digest, name) = line
        .trim_end_matches('\n')
        .split_once("  ")
        .expect("digest and file name, separated by two spaces");

    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
    );
    assert_eq!(name, VECTOR_FILE);
    assert_eq!(line.matches('\n').count(), 1);
}

#[test]
fn the_header_pins_the_frozen_constants() {
    // The scheme tag and the separator are frozen by this set, so the set has to say which
    // values it was frozen at — a consumer reading the JSON alone gets them from here.
    let file = committed();

    assert_eq!(file.schema, SCHEMA);
    assert_eq!(file.scheme_tag, "SolanaUserDecryptionLinker:v1");
    assert_eq!(file.dsep, "SOLLNK01");
    assert_eq!(file.dsep_list, "HASH_LST");
    assert_eq!(file.chain_id_derivation, CHAIN_ID_DERIVATION_TAG);
    assert_eq!(file.scheme_tag.len(), 29);
}

#[test]
fn every_valid_record_builds_and_carries_the_link_the_binding_computes() {
    // The positive half: `valid` means the canonical constructor accepts these fields and the
    // recorded 32 bytes are what a conforming response must carry.
    let file = committed();
    let valid = records_of(&file, VectorClass::Valid);
    assert!(valid.len() >= 4, "the set lost its positive records");

    for record in valid {
        assert_eq!(record.result, VectorResult::Valid, "{}", record.name);
        let binding = record
            .try_build(&file)
            .unwrap_or_else(|error| panic!("{} must validate, got {error}", record.name));

        assert_eq!(
            binding.compute_link(),
            record.link_bytes(),
            "{}",
            record.name
        );
        assert_eq!(record.link_bytes().len(), LINK_LEN, "{}", record.name);
        binding
            .validate_declared_chain_id(record.chain_id())
            .unwrap_or_else(|error| {
                panic!(
                    "{}: the record's declared chain id must match its handles: {error}",
                    record.name
                )
            });
    }
}

#[test]
fn every_link_divergence_record_builds_and_differs_from_its_base() {
    // Rule l3: these records are well-formed requests whose link is not the base's, which is the
    // property that makes response substitution detectable rather than silent.
    let file = committed();
    let divergences = records_of(&file, VectorClass::LinkDivergence);
    assert!(
        !divergences.is_empty(),
        "the set lost its divergence records"
    );

    for record in divergences {
        assert_eq!(record.result, VectorResult::Invalid, "{}", record.name);
        let binding = record.try_build(&file).unwrap_or_else(|error| {
            panic!(
                "{} must be constructible — its rejection is a link mismatch, not a validation \
                 failure — got {error}",
                record.name,
            )
        });
        assert_eq!(
            binding.compute_link(),
            record.link_bytes(),
            "{}",
            record.name
        );

        let base = file.record(record.derived_from.as_ref().expect("a base"));
        assert_ne!(
            record.link_bytes(),
            base.link_bytes(),
            "{} shares a link with its base {}",
            record.name,
            base.name,
        );
    }
}

#[test]
fn no_two_records_that_have_a_link_share_one() {
    // Pairwise, not just against the reference: two mutated requests colliding with each other is
    // the same failure as either colliding with the original. The one deliberate exception is the
    // declared-chain-id record, whose mutation is by construction not hashed.
    let file = committed();
    let linked: Vec<&Record> = file
        .records
        .iter()
        .filter(|record| {
            record.link.is_some()
                && record.rule.as_deref() != Some(rule::DECLARED_CHAIN_ID_MISMATCH)
        })
        .collect();

    for (index, left) in linked.iter().enumerate() {
        for right in &linked[index + 1..] {
            assert_ne!(
                left.link, right.link,
                "{} and {} share a link",
                left.name, right.name,
            );
        }
    }
}

#[test]
fn every_construction_reject_record_is_refused_by_the_rule_it_names() {
    // A negative that fails "somehow" tests nothing: the rule name says *which* check must fire,
    // and an implementation rejecting for another reason is not conforming.
    let file = committed();
    let rejects = records_of(&file, VectorClass::ConstructionReject);
    assert!(!rejects.is_empty(), "the set lost its rejection records");

    for record in rejects {
        assert_eq!(record.result, VectorResult::Invalid, "{}", record.name);
        let named = record.rule.as_deref().expect("a rule");

        match record.rejected_by.expect("a rejecting check") {
            RejectedBy::Constructor => {
                assert!(record.link.is_none(), "{} must have no link", record.name);
                assert!(
                    record.linker_hasher_input.is_none(),
                    "{} must have no hasher input",
                    record.name,
                );
                let error = record
                    .try_build(&file)
                    .expect_err(&format!("{} must be refused", record.name));
                assert!(
                    rejection_matches(named, &error),
                    "{} names rule {named} but the binding answered {error}",
                    record.name,
                );
            }
            RejectedBy::DeclaredChainIdCheck => {
                // Constructible: the declared value is not part of the request the constructor
                // sees, so this rejection can only come from the caller's own second check.
                let binding = record
                    .try_build(&file)
                    .unwrap_or_else(|error| panic!("{} must build, got {error}", record.name));
                let declared: u64 = record
                    .declared_chain_id_decimal
                    .as_ref()
                    .expect("a declared chain id")
                    .parse()
                    .expect("a decimal chain id");

                let error = binding
                    .validate_declared_chain_id(declared)
                    .expect_err(&format!("{} must be refused", record.name));
                assert!(
                    rejection_matches(named, &error),
                    "{} names rule {named} but the binding answered {error}",
                    record.name,
                );
            }
        }
    }
}

#[test]
fn every_foreign_scheme_record_is_not_the_v1_link_for_its_fields() {
    // Cross-version replay needs no rule of its own — a foreign-tag value fails l3 byte
    // equality. The assertion is inequality with the link the canonical function computes for
    // exactly these fields, which is the strongest form the claim can take.
    let file = committed();
    let foreign = records_of(&file, VectorClass::ForeignSchemeLink);
    assert!(
        !foreign.is_empty(),
        "the set lost its foreign-scheme records"
    );

    for record in foreign {
        assert_eq!(record.result, VectorResult::Invalid, "{}", record.name);
        assert_ne!(record.scheme_tag, file.scheme_tag, "{}", record.name);

        let binding = record
            .try_build(&file)
            .unwrap_or_else(|error| panic!("{} must build, got {error}", record.name));

        assert_eq!(record.link_bytes().len(), LINK_LEN, "{}", record.name);
        assert_ne!(
            record.link_bytes(),
            binding.compute_link(),
            "{} equals the v1 link for its own fields",
            record.name,
        );
    }
}

#[test]
fn the_hasher_input_of_every_v1_record_is_the_canonical_functions_input() {
    // The published "hasher input" field is the byte sequence the digest is actually taken over,
    // so a consumer that reproduces the input and gets a different digest knows the disagreement
    // is in the hash, not in the layout.
    let file = committed();
    let mut checked = 0;

    for record in &file.records {
        let Some(expected) = &record.linker_hasher_input else {
            continue;
        };
        if record.scheme_tag != file.scheme_tag {
            continue;
        }

        let binding = record
            .try_build(&file)
            .unwrap_or_else(|error| panic!("{} must build, got {error}", record.name));
        assert_eq!(
            &hex::encode(binding.linker_hasher_input()),
            expected,
            "{}",
            record.name,
        );
        checked += 1;
    }

    assert!(
        checked >= 15,
        "only {checked} records carried a hasher input"
    );
}

#[test]
fn every_rejecting_record_isolates_exactly_one_violation() {
    // `derived_from` is a claim that the base is accepted and one thing was changed. If the base
    // did not validate, the record would prove nothing about the mutation it names.
    let file = committed();

    for record in &file.records {
        let Some(base_name) = &record.derived_from else {
            assert_eq!(record.result, VectorResult::Valid, "{}", record.name);
            continue;
        };

        assert!(
            record.mutation.is_some(),
            "{} names no mutation",
            record.name
        );
        assert!(record.rule.is_some(), "{} names no rule", record.name);

        let base = file.record(base_name);
        assert_eq!(
            base.result,
            VectorResult::Valid,
            "{} derives from {base_name}, which is not an accepted record",
            record.name,
        );
        base.try_build(&file)
            .unwrap_or_else(|error| panic!("base {base_name} must validate, got {error}"));
    }
}

#[test]
fn record_names_are_unique_and_every_reference_resolves() {
    let file = committed();
    let names: BTreeSet<&str> = file.records.iter().map(|r| r.name.as_str()).collect();

    assert_eq!(names.len(), file.records.len(), "duplicate record names");
    for record in &file.records {
        if let Some(base) = &record.derived_from {
            assert!(
                names.contains(base.as_str()),
                "{} names a missing base",
                record.name
            );
        }
    }
}

#[test]
fn the_rule_dictionary_is_covered_in_both_directions() {
    // A dictionary with unexercised names promises coverage the set does not have; a record with an
    // unknown name is a rule no other implementation can map onto its own errors.
    let file = committed();
    let used: BTreeSet<&str> = file
        .records
        .iter()
        .filter_map(|record| record.rule.as_deref())
        .collect();
    let declared: BTreeSet<&str> = rule::ALL.iter().copied().collect();

    assert_eq!(
        declared.len(),
        rule::ALL.len(),
        "the dictionary repeats a name"
    );
    let unknown: Vec<_> = used.difference(&declared).collect();
    let unexercised: Vec<_> = declared.difference(&used).collect();

    assert!(
        unknown.is_empty(),
        "records name rules outside the dictionary: {unknown:?}"
    );
    assert!(
        unexercised.is_empty(),
        "dictionary rules no record exercises: {unexercised:?}"
    );
}

#[test]
fn the_set_contains_no_json_numbers() {
    // Every 64-bit value is a decimal string. A JSON number reaches a TypeScript consumer as a
    // double, and every chain id here is above 2^53, so the rounding would be silent.
    fn numbers(value: &Value, path: &str, found: &mut Vec<String>) {
        match value {
            Value::Number(number) => found.push(format!("{path} = {number}")),
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    numbers(item, &format!("{path}[{index}]"), found);
                }
            }
            Value::Object(fields) => {
                for (key, item) in fields {
                    numbers(item, &format!("{path}.{key}"), found);
                }
            }
            _ => {}
        }
    }

    let raw: Value = serde_json::from_str(&committed_json()).expect("valid JSON");
    let mut found = Vec::new();
    numbers(&raw, "$", &mut found);

    assert!(found.is_empty(), "JSON numbers in the set: {found:#?}");
}

#[test]
fn every_chain_id_exceeds_the_javascript_safe_integer() {
    // Not an accident to be preserved by luck: the chain-kind bit is bit 63, so a Solana chain id
    // is always above 2^53. The canary is the whole set, not one record.
    let file = committed();

    for record in &file.records {
        assert!(
            record.chain_id() > JAVASCRIPT_SAFE_INTEGER,
            "{} has a chain id a JavaScript number would survive",
            record.name,
        );
    }
}

#[test]
fn the_three_chain_id_forms_agree_with_the_rule_recomputed_in_test() {
    // The shared fixture format requires three forms; three forms that disagree are worse than one.
    // The rule is recomputed here from the record's own genesis hash rather than trusted from the
    // file.
    let file = committed();
    assert_eq!(file.chain_id_derivation, CHAIN_ID_DERIVATION_TAG);

    for record in &file.records {
        let decimal: u64 = record.chain_id();
        let hex_form = u64::from_str_radix(
            record.chain_id_hex.strip_prefix("0x").expect("0x-prefixed"),
            16,
        )
        .expect("hex chain id");
        let be_bytes = hex::decode(&record.chain_id_be_bytes).expect("hex");

        assert_eq!(decimal, hex_form, "{}", record.name);
        assert_eq!(be_bytes, decimal.to_be_bytes(), "{}", record.name);
        assert_eq!(
            decimal,
            derive_chain_id(&record.genesis_hash),
            "{} records a chain id that is not the rule applied to its genesis hash",
            record.name,
        );
        assert_eq!(
            hex::decode(&record.genesis_hash_bytes).expect("hex"),
            base58_decode(&record.genesis_hash).expect("base58"),
            "{} records two disagreeing forms of its genesis hash",
            record.name,
        );
        assert_ne!(decimal & CHAIN_KIND_BIT, 0, "{}", record.name);
    }
}

#[test]
fn the_reference_cluster_is_the_permit_sets_cluster() {
    // The shared-input alignment, as an assertion rather than a claim in prose: both halves of the
    // fixture set are about the same deployment. What the two sets do *not* agree on today is the
    // derived chain id — the permit set still records a stand-in derivation and is due for
    // regeneration under the settled rule; the genesis bytes below are what makes that comparable.
    assert_eq!(
        hex::encode(base58_decode(REFERENCE_GENESIS).expect("base58")),
        PERMIT_GENESIS_HASH_HEX,
    );

    let file = committed();
    let reference = file.record("reference-two-handles");
    assert_eq!(reference.genesis_hash_bytes, PERMIT_GENESIS_HASH_HEX);
    assert_eq!(reference.receiver_id, RECEIVER_ID_HEX);
    assert_eq!(reference.verifying_program_id, VERIFYING_PROGRAM_ID_HEX);
    assert_eq!(reference.kms_context_id, KMS_CONTEXT_ID_HEX);
    assert_eq!(reference.kms_epoch_id, KMS_EPOCH_ID_HEX);
    assert_eq!(reference.transport_key, TRANSPORT_REFERENCE);
    assert_eq!(
        file.transport_keys
            .get(TRANSPORT_REFERENCE)
            .expect("the canonical key"),
        REFERENCE_CONTAINER_MLKEM_512_HEX,
    );
    // The permit set's current reference key, byte-identical, demoted here to its one negative
    // record. This is the pin that keeps "the permit set regenerates to the container" checkable:
    // until it does, the bytes it still calls reference-mlkem-512 are exactly these.
    assert_eq!(
        file.transport_keys
            .get(TRANSPORT_BARE)
            .expect("the demoted permit-width key"),
        BARE_MLKEM_512_HEX,
    );
}

#[test]
fn the_reference_key_is_the_committed_869_byte_container() {
    // The width is normative — a KMS request carries exactly this container — and the *structure*
    // is what makes the reference a request a consumer could have sent. This side of the tree can
    // only check the width and the bytes — kms-grpc cannot deserialize a container — so the
    // structural half is `core/service/tests/solana_vector_container.rs`, reading these same
    // committed bytes.
    let file = committed();
    let key = file
        .transport_keys
        .get(TRANSPORT_REFERENCE)
        .expect("the canonical key");

    assert_eq!(key, REFERENCE_CONTAINER_MLKEM_512_HEX);
    assert_eq!(hex::decode(key).expect("hex").len(), 869);

    let bare = file
        .transport_keys
        .get(TRANSPORT_BARE)
        .expect("the bare key");
    assert_eq!(hex::decode(bare).expect("hex").len(), 800);
    assert_eq!(
        file.record("bare-encapsulation-key-width").transport_key,
        TRANSPORT_BARE,
    );
}

#[test]
fn base58_round_trips_known_solana_values() {
    // The decoder is written out in this file, so it needs its own evidence: two real genesis
    // hashes and the leading-zero case the long division cannot represent on its own.
    assert_eq!(
        hex::encode(base58_decode(OTHER_GENESIS).expect("base58")),
        "45296998a6f8e2a784db5d9f95e18fc23f70441a1039446801089879b08c7ef0",
        "Solana mainnet-beta's genesis hash",
    );
    assert_eq!(base58_decode(REFERENCE_GENESIS).expect("base58").len(), 32);
    assert_eq!(base58_decode("1").expect("base58"), vec![0u8]);
    assert_eq!(base58_decode("11").expect("base58"), vec![0u8, 0]);
    assert_eq!(base58_decode("112").expect("base58"), vec![0u8, 0, 1]);
    assert_eq!(base58_decode("2").expect("base58"), vec![1u8]);
    assert_eq!(base58_decode("0"), None, "0 is not in the alphabet");
}

/// The rule, spelled out a second time from the specification rather than by calling
/// [`derive_chain_id`].
///
/// An assertion of the form `derive_chain_id(x) == derive_chain_id(x)` would hold for any rule at
/// all, including a wrong one. This is the independent reading the derived values are checked
/// against — the tag is written as a literal here on purpose, not taken from the constant the
/// generator uses — and it is shared so that the record check and the registry check compare
/// against the same second opinion.
fn recomputed_chain_id(genesis_hash_base58: &str) -> u64 {
    let genesis = base58_decode(genesis_hash_base58).expect("base58");

    let mut hasher = Sha256::new();
    hasher.update(b"zama-solana-chain-id-v1");
    hasher.update(&genesis);
    let digest = hasher.finalize();

    0x8000_0000_0000_0000u64
        | (u64::from_be_bytes(digest[..8].try_into().expect("eight")) & 0x7fff_ffff_ffff_ffff)
}

#[test]
fn the_cluster_registry_is_the_rule_applied_to_each_public_genesis_hash() {
    // This table is what a deployment review checks a cluster configuration against, so it has to
    // be right *and* has to be visibly the same rule the records use. Every id is recomputed
    // here from the entry's own base58 genesis hash by the independent reading above; nothing in
    // the entry is taken on trust, including the hex form of the genesis hash.
    let file = committed();

    assert_eq!(
        file.cluster_registry
            .keys()
            .map(String::as_str)
            .collect::<Vec<&str>>(),
        vec!["devnet", "mainnet-beta", "testnet"],
        "the registry no longer covers exactly the three public clusters",
    );
    assert!(!file.cluster_registry_note.is_empty());

    let mut seen_ids = BTreeSet::new();

    for (cluster, entry) in &file.cluster_registry {
        let decimal: u64 = entry
            .chain_id_decimal
            .parse()
            .unwrap_or_else(|_| panic!("{cluster} has an unparseable chain id"));
        let hex_form = u64::from_str_radix(
            entry.chain_id_hex.strip_prefix("0x").expect("0x-prefixed"),
            16,
        )
        .expect("hex chain id");

        assert_eq!(decimal, hex_form, "{cluster}");
        assert_eq!(
            hex::decode(&entry.chain_id_be_bytes).expect("hex"),
            decimal.to_be_bytes(),
            "{cluster}",
        );
        assert_eq!(
            decimal,
            recomputed_chain_id(&entry.genesis_hash),
            "{cluster} records a chain id that is not the rule applied to its genesis hash",
        );

        let genesis = base58_decode(&entry.genesis_hash).expect("base58");
        assert_eq!(genesis.len(), 32, "{cluster}");
        assert_eq!(
            hex::decode(&entry.genesis_hash_bytes).expect("hex"),
            genesis,
            "{cluster} records two disagreeing forms of its genesis hash",
        );

        assert_ne!(
            decimal & CHAIN_KIND_BIT,
            0,
            "{cluster} is a Solana-kind chain and must carry bit 63",
        );
        assert!(
            seen_ids.insert(decimal),
            "{cluster} collides with another cluster's chain id",
        );
    }
}

#[test]
fn the_registrys_mainnet_entry_is_the_wrong_chain_id_records_cluster() {
    // The registry and the records are not two tables that happen to agree: mainnet-beta appears in
    // both, so an error in the derivation would have to be made twice, identically, to hide.
    let file = committed();
    let mainnet = file
        .cluster_registry
        .get("mainnet-beta")
        .expect("the registry carries mainnet-beta");
    let record = file.record("wrong-chain-id");

    assert_eq!(mainnet.genesis_hash, OTHER_GENESIS);
    assert_eq!(mainnet.genesis_hash, record.genesis_hash);
    assert_eq!(mainnet.chain_id_decimal, record.chain_id_decimal);
    assert_eq!(mainnet.chain_id_hex, record.chain_id_hex);
    assert_eq!(mainnet.chain_id_be_bytes, record.chain_id_be_bytes);
}

#[test]
fn the_derivation_rule_sets_the_chain_kind_bit_and_keeps_the_rest() {
    // The rule is two operations: take the leading 63 bits of the digest, force bit 63. Checked
    // against a digest computed here rather than against another call to the same function.
    let expected = recomputed_chain_id(REFERENCE_GENESIS);

    assert_eq!(derive_chain_id(REFERENCE_GENESIS), expected);
    assert_ne!(
        derive_chain_id(REFERENCE_GENESIS),
        derive_chain_id(OTHER_GENESIS),
        "two clusters must not derive one chain id",
    );
}
