//! The normative Solana linker vectors (v2), and the runner that consumes them.
//!
//! One code path builds the set and checks it: `cargo test` builds every record in memory from
//! the canonical binding and compares byte-for-byte with the committed
//! `core/grpc/test-vectors/solana_linker_v2.json`; `make generate-solana-linker-vectors` runs the
//! same binary with `ZAMA_UPDATE_SOLANA_LINKER_VECTORS=1` set to rewrite that file and its digest
//! instead. There is no second generator to drift from the runner.
//!
//! The vectors are shared across repositories (SDK TypeScript, relayer, Connector Rust, KMS Core
//! Rust, KMS client/WASM), so the set carries its own SHA-256 in `solana_linker_v2.sha256`
//! (`sha256sum` line format); each repository commits the same two files and CI compares digests,
//! catching both locally edited and stale copies.
//!
//! Conventions: every 64-bit value is a decimal string, because every host chain id has type byte
//! `0x01` and a JSON number would be silently rounded by a TypeScript consumer. Every rejecting
//! record names its rule and derives from a named accepted base with exactly one mutation. Every
//! record that has a link carries the Gateway domain it was computed under. `cluster_registry` is
//! the reviewed registry of public-cluster chain ids, derived by the same code as every record's
//! chain id. The file deliberately does not use `tests/common`: a published reference must not
//! move because a shared test helper was edited.
//!
//! The type string, its keccak-256 type hash and the EIP-712 encoding of every field are frozen by
//! this set and pinned independently by `solana_frozen_constants.rs`; changing any of those bytes
//! is a new type name, not an edit.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::LazyLock;

use alloy_primitives::{Address, U256, address, keccak256};
use alloy_sol_types::{Eip712Domain, SolStruct};
use hashing::{DomainSep, unsafe_hash_list_w_size};
use kms_grpc::solana_binding::{SolanaUserDecryptBinding, SolanaUserDecryptBindingError};
use kms_grpc::solidity_types::SolanaUserDecryptionLinker;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Identity of the set
// ---------------------------------------------------------------------------

/// Schema identifier. A consumer that does not recognize it must refuse the file rather than guess.
const SCHEMA: &str = "zama-solana-linker-vectors/v2";

/// Which generator produced the set, so a diverging copy can be traced to its source.
const GENERATOR: &str = "kms:core/grpc/tests/solana_linker_vectors.rs";

const VECTOR_FILE: &str = "solana_linker_v2.json";
const DIGEST_FILE: &str = "solana_linker_v2.sha256";

/// Set to any value to rewrite the committed set instead of checking it.
const UPDATE_ENV: &str = "ZAMA_UPDATE_SOLANA_LINKER_VECTORS";

/// The EIP-712 type string of the linker: the versioned name of the construction. Written as a
/// literal here — the runner requires the library's own encoding of the type to agree with it.
const TYPE_STRING: &str = "SolanaUserDecryptionLinker(bytes publicKey,bytes32[] handles,bytes32 userPubkey,bytes32 verifyingProgramId)";

/// The EIP-712 domain type the Gateway `Decryption` contract's domain is hashed as: name, version,
/// chain id and verifying contract, no salt.
const DOMAIN_TYPE_STRING: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// The construction, in prose, for non-Rust consumers.
const CONSTRUCTION_RULE: &str = concat!(
    "link = keccak256(0x19 || 0x01 || domainSeparator || hashStruct); ",
    "hashStruct = keccak256(type_hash || keccak256(publicKey) || keccak256(handles[0] || ... || ",
    "handles[n-1]) || userPubkey || verifyingProgramId), one 32-byte word per field, publicKey being ",
    "the transport key bytes exactly as the request carries them and the handles in request order ",
    "with duplicates preserved; domainSeparator = keccak256(keccak256(domain_type_string) || ",
    "keccak256(name) || keccak256(version) || uint256(chainId) || uint256(uint160(verifyingContract))). ",
    "extra_data is not an input; the host chain id is not a separate input, it enters through bytes ",
    "22..30 of every handle.",
);

/// Per-record `construction` values.
const CONSTRUCTION_EIP712: &str = "eip712";
const CONSTRUCTION_RETIRED_LIST_HASH: &str = "shake256-list-hash-v1";

/// Prose form of the deployment-time encoding, written into the file for non-Rust consumers.
///
/// Test-side only. Production KMS never derives a chain id — it reads the one the handles embed.
const CHAIN_ID_DERIVATION_RULE: &str =
    "chain_id = be_u64(0x01 || base58_decode(genesis_hash)[0..7])";

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

/// The permit set's signed `extra_data`, verbatim: the kms-routing envelope — version byte `0x02`,
/// then the KMS context id and the KMS epoch id, 32 bytes each.
///
/// Not a linker input: the external response signature is what authenticates it. It survives in
/// this file for one record, `cross-version-replay`, because the retired list-hash linker bound it
/// and that record reproduces the retired link over these very bytes.
const REFERENCE_EXTRA_DATA_HEX: &str = concat!(
    "02",
    "bb801121e2ea198af189c9331dfc57f675802c35206f96a5964deeac39f79d18",
    "7772d6a5c7fc28db485c51abbe18cba52b775baf1015b59ac363e5bf5827a3f2",
);

/// The Gateway `Decryption` contract's EIP-712 domain the reference records are hashed under: the
/// contract's name and version as `Decryption.sol` declares them, the chain id of the Gateway the
/// contract is deployed on, and the contract's address. The chain id here is the local test
/// gateway's; a deployment substitutes its own, and its links then differ from these by design —
/// the link is specific to the Gateway that answers.
const REFERENCE_DOMAIN_NAME: &str = "Decryption";
const REFERENCE_DOMAIN_VERSION: &str = "1";
const REFERENCE_GATEWAY_CHAIN_ID: u64 = 54_321;
const REFERENCE_VERIFYING_CONTRACT: Address = address!("66f9664f97F2b50F62D13eA064982f936dE76657");

/// What the domain is, written into the file for non-Rust consumers.
const DOMAIN_NOTE: &str = concat!(
    "Every record with a link carries the EIP-712 domain it was hashed under: the Gateway ",
    "Decryption contract's domain (name and version as the contract declares them, the Gateway ",
    "chain id, the contract address; no salt). The reference records use the local test gateway's ",
    "chain id and a fixed contract address; a consumer recomputing a record's link uses the ",
    "record's domain, never its own deployment's. A request without a domain has no link ",
    "(record missing-domain).",
);

/// Derivation of the handle filler, so a regenerating implementation reproduces these bytes.
///
/// Handles are the one input the permit layer does not carry, so there is nothing to align them to.
/// A hash-derived filler is used rather than a repeated byte so that no accidental structure —
/// a run of zeros, an ascending pattern — can make a layout bug look correct. The tag is the v1
/// set's on purpose: the handle bytes of every record are the ones v1 published, so that only the
/// hash over them changed between the two sets.
const HANDLE_DERIVATION_TAG: &str = "zama-solana-linker-vectors/v1 handle ";

/// Name of the canonical transport key: the 869-byte safe-serialized `UnifiedPublicEncKey::MlKem512`
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

/// The canonical reference transport key: a genuine safe-serialized `UnifiedPublicEncKey::MlKem512`
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
/// The linker itself is indifferent: it hashes the transport key as `bytes` and enforces no
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

/// Reviewed public-cluster ids, hard-coded so a registry test cannot prove `f(g) == f(g)`.
const PUBLIC_CLUSTER_CHAIN_IDS: &[(&str, u64)] = &[
    ("mainnet-beta", 0x0145_2969_98a6_f8e2),
    ("devnet", 0x01ce_59db_5080_fc2c),
    ("testnet", 0x013a_132e_ce10_305e),
];

/// Chain id of [`REFERENCE_GENESIS`]: type byte `0x01` and that hash's first seven bytes.
const REFERENCE_CHAIN_ID: u64 = 0x0145_39cf_79f6_6704;

/// What the registry is for, written into the file for non-Rust consumers.
const CLUSTER_REGISTRY_NOTE: &str = concat!(
    "The reviewed registry of public-cluster chain ids, published here rather than in a ",
    "second document so that the deployment procedure and this fixture set cannot disagree: a ",
    "cluster configuration is correct exactly when its chain id equals the entry below, and each ",
    "entry is the chain_id_derivation_rule applied to the genesis hash beside it. Genesis hashes ",
    "were read from each cluster's public RPC (getGenesisHash), not transcribed from ",
    "documentation. Registering a further cluster means adding it here and regenerating; these ",
    "three are the ones a deployment review is expected to check against. The seven-byte tag is a ",
    "label, not evidence of cluster identity: KMS never derives a chain id or checks one against ",
    "configuration — a party reads the one the handles embed — so this section is a deployment-time ",
    "and SDK-side surface, not an input to the linker.",
);

/// Provenance of the shared inputs, written into the file so a reader of the JSON alone can tell
/// which values are supposed to match the permit set and which are this layer's own.
const SHARED_INPUTS: &str = concat!(
    "Recipient, verifying program id and the reference cluster are the fhevm permit set's ",
    "(test-fixtures/permit/permit_v1.json, record reference-permit-two-domains): the two halves of ",
    "the specification's fixture set bind the same objects. Handles are this layer's own — the ",
    "permit carries none — and their filler bytes are the v1 set's; only the embedded chain id ",
    "and the hash over them changed. The permit's signed extra_data is not a linker input in this ",
    "version; it appears in one record only, cross-version-replay, which reproduces the retired ",
    "v1 link over it. Two deliberate divergences from the permit set as it stands today: (1) chain ",
    "ids here are be_u64(0x01 || genesis[0..7]), while the permit set still records a stand-in ",
    "derivation, so the same genesis hash yields a different id there and that set is due for ",
    "regeneration; (2) the canonical transport key here is the 869-byte safe-serialized ",
    "UnifiedPublicEncKey::MlKem512 container a KMS request actually carries — the selected ",
    "permit-v1 representation, which the permit signs as well — while the permit set still ",
    "records the bare 800-byte encapsulation key under the shared name reference-mlkem-512 and ",
    "regenerates to this container. The bare key survives here only as bare-mlkem-512-800, in a ",
    "negative record: production request validation rejects that width, and the linker's ",
    "indifference to it is the one thing the record shows.",
);

// ---------------------------------------------------------------------------
// The retired construction and the type this version did not adopt
// ---------------------------------------------------------------------------

/// The retired list-hash linker's scheme tag and call separator. Gone from the implementation,
/// they appear here only as the thing a response must not be believed for.
const RETIRED_SCHEME_TAG: &str = "SolanaUserDecryptionLinker:v1";
const RETIRED_DSEP: DomainSep = *b"SOLLNK01";

/// The layout this specification considered and did not adopt: an explicit host chain id field
/// after the program id. Hashed as the type it would be, it is a different type string and so a
/// different link — the type string is the version boundary, and this is the record that shows
/// it. No consumer defines this type; the record's only normative content is inequality.
const UNKNOWN_TYPE_STRING: &str = "SolanaUserDecryptionLinker(bytes publicKey,bytes32[] handles,bytes32 userPubkey,bytes32 verifyingProgramId,uint64 hostChainId)";

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
    /// different request, and the client's byte-equality rule rejects it.
    LinkDivergence,
    /// No link exists for these fields: the canonical constructor refuses them, the declared chain
    /// id disagrees with the handles, or there is no domain to hash under.
    ConstructionReject,
    /// A 32-byte value that is not this version's link for the same fields — computed under a type
    /// string this version does not define, or by the retired list-hash construction. Byte
    /// inequality alone must reject it: no consumer may parse a version out of a response to decide.
    ForeignLink,
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
    /// The caller: the fields validate, but without a Gateway domain there is nothing to hash
    /// under, and `compute_link` cannot be called. A consumer must refuse to produce a link.
    DomainRequired,
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
    /// The EIP-712 type string every `eip712` record under this version's type is computed with.
    type_string: String,
    /// `keccak256(type_string)`, hex — the first word of every `hashStruct` preimage.
    type_hash: String,
    /// The EIP-712 domain type the Gateway domain is hashed as.
    domain_type_string: String,
    /// The construction, in prose.
    construction_rule: String,
    /// What the per-record domain is, in prose.
    domain_note: String,
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
    /// Transport keys by name. Kept out of the records because one key is 1738 hex characters and
    /// would make every diff unreadable.
    transport_keys: BTreeMap<String, String>,
    /// The records, in a fixed order: valid, then link divergences, then construction rejects, then
    /// foreign links.
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
    /// Chain id as the eight big-endian bytes the handles embed, hex.
    chain_id_be_bytes: String,
}

/// The Gateway `Decryption` domain a record was hashed under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DomainEntry {
    /// `EIP712Domain.name`.
    name: String,
    /// `EIP712Domain.version`.
    version: String,
    /// `EIP712Domain.chainId`, decimal string — the Gateway chain, not the Solana host chain.
    chain_id_decimal: String,
    /// `EIP712Domain.verifyingContract`, EIP-55.
    verifying_contract: String,
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
    /// Host chain id, decimal string.
    chain_id_decimal: String,
    /// Host chain id, `0x`-prefixed hex.
    chain_id_hex: String,
    /// Host chain id as the eight big-endian bytes the handles embed, hex.
    chain_id_be_bytes: String,
    /// A chain id declared separately from the request, decimal string. Present only where a record
    /// exists to exercise that check; the linker does not hash it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    declared_chain_id_decimal: Option<String>,
    /// The recipient, hex. A conforming request carries 32 bytes; wrong-width records do not.
    receiver_id: String,
    /// The verifying program id, hex.
    verifying_program_id: String,
    /// The ciphertext handles in request order, hex, duplicates preserved.
    handles: Vec<String>,
    /// Name of this record's transport key in the file's `transport_keys` table.
    transport_key: String,
    /// The Gateway domain this record is hashed under. `null` exactly for the record that has none.
    domain: Option<DomainEntry>,
    /// Which construction produced `link`: `eip712` for this version's, or the retired list hash.
    construction: String,
    /// For an `eip712` record: the type string it was hashed with — the file's for every record of
    /// this version, a foreign one for the unknown-type record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    type_string: Option<String>,
    /// Only for the retired-construction record: the `extra_data` the retired linker bound, hex.
    /// Not an input to this version's link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extra_data: Option<String>,
    /// `hashStruct(EIP712Domain)` of `domain`, hex. Present for every `eip712` record with a domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    domain_separator: Option<String>,
    /// `hashStruct(linker)`, hex. Present exactly when an `eip712` link exists, so that five
    /// implementations can compare their struct hash before comparing the link, which is where a
    /// one-word disagreement is actually diagnosable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hash_struct: Option<String>,
    /// The link, 32 bytes, hex. Absent exactly when no link exists for the record.
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
    pub const WRONG_CHAIN_ID: &str = "wrong-chain-id";
    pub const DUPLICATED_HANDLE: &str = "duplicated-handle";
    pub const WRONG_GATEWAY_DOMAIN: &str = "wrong-gateway-domain";

    // construction-reject
    pub const EMPTY_HANDLE_LIST: &str = "empty-handle-list";
    pub const HANDLE_WIDTH: &str = "handle-width";
    pub const HANDLE_CHAIN_TYPE_BYTE: &str = "handle-chain-type-byte";
    pub const MIXED_EMBEDDED_CHAIN_IDS: &str = "mixed-embedded-chain-ids";
    pub const DECLARED_CHAIN_ID_MISMATCH: &str = "declared-chain-id-mismatch";
    pub const IDENTITY_WIDTH: &str = "identity-width";
    pub const MISSING_DOMAIN: &str = "missing-domain";

    // foreign-link
    pub const UNKNOWN_TYPE_STRING: &str = "unknown-type-string";
    pub const CROSS_VERSION_REPLAY: &str = "cross-version-replay";

    /// Every rule name, for coverage checks in both directions.
    pub const ALL: &[&str] = &[
        CHANGED_HANDLE,
        CHANGED_HANDLE_ORDER,
        WRONG_TRANSPORT_KEY,
        WRONG_RECIPIENT,
        WRONG_VERIFYING_PROGRAM_ID,
        WRONG_CHAIN_ID,
        DUPLICATED_HANDLE,
        WRONG_GATEWAY_DOMAIN,
        EMPTY_HANDLE_LIST,
        HANDLE_WIDTH,
        HANDLE_CHAIN_TYPE_BYTE,
        MIXED_EMBEDDED_CHAIN_IDS,
        DECLARED_CHAIN_ID_MISMATCH,
        IDENTITY_WIDTH,
        MISSING_DOMAIN,
        UNKNOWN_TYPE_STRING,
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

/// The settled deployment-time rule: `be_u64(0x01 || genesis[0..7])`.
///
/// Test-side only. Production KMS never derives a chain id — it reads the one the handles embed —
/// which is why this lives in the vector generator and not in the crate.
fn derive_chain_id(genesis_hash_base58: &str) -> u64 {
    let genesis = base58_decode(genesis_hash_base58).expect("a base58 genesis hash");
    assert!(
        genesis.len() >= 7,
        "a Solana genesis hash is 32 bytes; need seven for the cluster tag",
    );

    let mut bytes = [0u8; 8];
    bytes[0] = kms_grpc::solana_binding::SOLANA_CHAIN_TYPE;
    bytes[1..8].copy_from_slice(&genesis[..7]);
    u64::from_be_bytes(bytes)
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
    // A real safe-serialized UnifiedPublicEncKey::MlKem512, not a filler of the right width: see
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

/// The Gateway domain of one record, before it is rendered.
#[derive(Clone, Debug)]
struct DomainInputs {
    name: &'static str,
    version: &'static str,
    chain_id: u64,
    verifying_contract: Address,
}

impl DomainInputs {
    fn reference() -> Self {
        Self {
            name: REFERENCE_DOMAIN_NAME,
            version: REFERENCE_DOMAIN_VERSION,
            chain_id: REFERENCE_GATEWAY_CHAIN_ID,
            verifying_contract: REFERENCE_VERIFYING_CONTRACT,
        }
    }

    fn to_alloy(&self) -> Eip712Domain {
        Eip712Domain::new(
            Some(self.name.into()),
            Some(self.version.into()),
            Some(U256::from(self.chain_id)),
            Some(self.verifying_contract),
            None,
        )
    }

    fn separator(&self) -> [u8; 32] {
        self.to_alloy().separator().0
    }

    fn entry(&self) -> DomainEntry {
        DomainEntry {
            name: self.name.to_string(),
            version: self.version.to_string(),
            chain_id_decimal: self.chain_id.to_string(),
            verifying_contract: self.verifying_contract.to_checksum(None),
        }
    }
}

/// The request fields of one record, before they are rendered as hex.
#[derive(Clone, Debug)]
struct Inputs {
    genesis: &'static str,
    verifying_program_id: Vec<u8>,
    receiver_id: Vec<u8>,
    handles: Vec<Vec<u8>>,
    transport_key: &'static str,
    declared_chain_id: Option<u64>,
    domain: Option<DomainInputs>,
}

impl Inputs {
    /// The reference request: the permit set's identities, two handles, the shared transport key,
    /// the reference Gateway domain.
    fn reference() -> Self {
        let chain_id = derive_chain_id(REFERENCE_GENESIS);
        Self {
            genesis: REFERENCE_GENESIS,
            verifying_program_id: bytes(VERIFYING_PROGRAM_ID_HEX),
            receiver_id: bytes(RECEIVER_ID_HEX),
            handles: vec![handle(chain_id, 1), handle(chain_id, 2)],
            transport_key: TRANSPORT_REFERENCE,
            declared_chain_id: None,
            domain: Some(DomainInputs::reference()),
        }
    }

    fn chain_id(&self) -> u64 {
        derive_chain_id(self.genesis)
    }

    fn with_handles(mut self, handles: Vec<Vec<u8>>) -> Self {
        self.handles = handles;
        self
    }

    fn with_domain(mut self, domain: DomainInputs) -> Self {
        self.domain = Some(domain);
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
            self.handles.iter().map(|handle| handle.as_slice()),
            &self.transport_key_bytes(),
        )
    }
}

// ---------------------------------------------------------------------------
// Building the set
// ---------------------------------------------------------------------------

/// Which construction a record's link comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinkSource {
    /// This version's construction, through the canonical binding.
    Canonical,
    /// This version's construction under [`UNKNOWN_TYPE_STRING`], assembled by hand: no library
    /// path knows that type.
    UnknownType,
    /// The retired list hash, assembled by hand from the retired specification.
    RetiredListHash,
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
    link_source: LinkSource,
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
            link_source: LinkSource::Canonical,
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
            link_source: LinkSource::Canonical,
            inputs,
        }
    }

    fn rejected_by(mut self, rejected_by: RejectedBy) -> Self {
        self.rejected_by = Some(rejected_by);
        self
    }

    fn with_source(mut self, link_source: LinkSource) -> Self {
        self.link_source = link_source;
        self
    }
}

/// `encodeData` for the fields under `type_string`, written out field by field: the type hash,
/// then one 32-byte word per field — `bytes` and `bytes32[]` as the keccak-256 of their contents,
/// `bytes32` as itself.
fn encode_data(inputs: &Inputs, type_string: &str) -> Vec<u8> {
    let handles: Vec<u8> = inputs.handles.concat();

    let mut encoded = Vec::with_capacity(5 * 32);
    encoded.extend_from_slice(keccak256(type_string.as_bytes()).as_slice());
    encoded.extend_from_slice(keccak256(inputs.transport_key_bytes()).as_slice());
    encoded.extend_from_slice(keccak256(&handles).as_slice());
    encoded.extend_from_slice(&inputs.receiver_id);
    encoded.extend_from_slice(&inputs.verifying_program_id);
    encoded
}

/// `hashStruct` of the canonical type, through the library's own EIP-712 implementation of the
/// very struct `compute_link` hashes.
fn canonical_hash_struct(inputs: &Inputs) -> [u8; 32] {
    let linker = SolanaUserDecryptionLinker {
        publicKey: inputs.transport_key_bytes().into(),
        handles: inputs
            .handles
            .iter()
            .map(|handle| {
                alloy_primitives::FixedBytes::<32>::try_from(handle.as_slice())
                    .expect("a constructible record has 32-byte handles")
            })
            .collect(),
        userPubkey: alloy_primitives::FixedBytes::<32>::try_from(inputs.receiver_id.as_slice())
            .expect("a constructible record has a 32-byte recipient"),
        verifyingProgramId: alloy_primitives::FixedBytes::<32>::try_from(
            inputs.verifying_program_id.as_slice(),
        )
        .expect("a constructible record has a 32-byte program id"),
    };
    linker.eip712_hash_struct().0
}

/// `hashStruct` under the type this version did not adopt: the four words of the canonical type,
/// then the host chain id as a `uint64` word.
fn unknown_type_hash_struct(inputs: &Inputs) -> [u8; 32] {
    let mut encoded = encode_data(inputs, UNKNOWN_TYPE_STRING);
    encoded.extend_from_slice(&U256::from(inputs.chain_id()).to_be_bytes::<32>());
    keccak256(encoded).0
}

/// `keccak256(0x1901 ‖ domainSeparator ‖ hashStruct)`.
fn eip712_link(domain_separator: &[u8; 32], hash_struct: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(66);
    preimage.extend_from_slice(&[0x19, 0x01]);
    preimage.extend_from_slice(domain_separator);
    preimage.extend_from_slice(hash_struct);
    keccak256(preimage).0
}

/// The retired list-hash linker over the same fields, assembled from its specification:
/// `SHAKE256("HASH_LST" ‖ "SOLLNK01" ‖ u64le(6 + n) ‖ tag ‖ program ‖ chain_id_be ‖ recipient ‖
/// handles… ‖ transport key ‖ extra_data, 32)`. The list hash itself is the codebase's helper; the
/// element list is written out here because no production code knows it any more.
fn retired_list_hash_link(inputs: &Inputs, extra_data: &[u8]) -> Vec<u8> {
    let chain_id = inputs.chain_id().to_be_bytes();
    let transport_key = inputs.transport_key_bytes();

    let mut elements: Vec<&[u8]> = vec![
        RETIRED_SCHEME_TAG.as_bytes(),
        &inputs.verifying_program_id,
        &chain_id,
        &inputs.receiver_id,
    ];
    elements.extend(inputs.handles.iter().map(|handle| handle.as_slice()));
    elements.push(&transport_key);
    elements.push(extra_data);

    unsafe_hash_list_w_size(&RETIRED_DSEP, &elements, LINK_LEN)
}

fn finish(draft: Draft) -> Record {
    let chain_id = draft.inputs.chain_id();
    let buildable = draft.inputs.try_build();
    let domain = draft.inputs.domain.as_ref();

    let (construction, type_string, extra_data, hash_struct, link) =
        match (draft.link_source, &buildable, domain) {
            // The fields do not form a request, or there is no domain to hash under: no link exists
            // for them. That absence is the record.
            (_, Err(_), _) | (LinkSource::Canonical, Ok(_), None) => {
                (CONSTRUCTION_EIP712, Some(TYPE_STRING), None, None, None)
            }
            (LinkSource::Canonical, Ok(binding), Some(domain)) => (
                CONSTRUCTION_EIP712,
                Some(TYPE_STRING),
                None,
                Some(hex::encode(canonical_hash_struct(&draft.inputs))),
                Some(hex::encode(binding.compute_link(&domain.to_alloy()))),
            ),
            (LinkSource::UnknownType, Ok(_), Some(domain)) => {
                let hash_struct = unknown_type_hash_struct(&draft.inputs);
                (
                    CONSTRUCTION_EIP712,
                    Some(UNKNOWN_TYPE_STRING),
                    None,
                    Some(hex::encode(hash_struct)),
                    Some(hex::encode(eip712_link(&domain.separator(), &hash_struct))),
                )
            }
            (LinkSource::UnknownType, Ok(_), None) => {
                panic!("{}: a foreign-type record needs a domain", draft.name)
            }
            (LinkSource::RetiredListHash, Ok(_), _) => {
                let extra_data = bytes(REFERENCE_EXTRA_DATA_HEX);
                let link = retired_list_hash_link(&draft.inputs, &extra_data);
                (
                    CONSTRUCTION_RETIRED_LIST_HASH,
                    None,
                    Some(hex::encode(extra_data)),
                    None,
                    Some(hex::encode(link)),
                )
            }
        };

    // The separator is a fact about the domain alone, so every eip712 record with a domain carries
    // it — a consumer diagnosing a link mismatch checks it before the struct hash.
    let domain_separator = match (construction, domain) {
        (CONSTRUCTION_EIP712, Some(domain)) => Some(hex::encode(domain.separator())),
        _ => None,
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
        handles: draft.inputs.handles.iter().map(hex::encode).collect(),
        transport_key: draft.inputs.transport_key.to_string(),
        domain: domain.map(DomainInputs::entry),
        construction: construction.to_string(),
        type_string: type_string.map(str::to_string),
        extra_data,
        domain_separator,
        hash_struct,
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
            "The reference request: the permit set's recipient and program id, two handles on the \
             permit set's cluster, the canonical transport key — the 869-byte safe-serialized \
             UnifiedPublicEncKey::MlKem512 container a KMS request actually carries — and the \
             reference Gateway domain. Every record below that names a base names this one unless \
             it says otherwise.",
            Inputs::reference(),
        ),
        Draft::valid(
            "single-handle",
            "One handle. Base for the duplication record, and the smallest handle list the \
             construction admits.",
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
            "A batch of eight: the handles word is keccak256 over 256 bytes of concatenated \
             handles, so a consumer that hashed the handles one at a time, or the array's ABI \
             encoding with its length word, disagrees here.",
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
            "The host program is bound explicitly: the same handles under a different program are \
             a different deployment, even on the same cluster.",
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
            "wrong-chain-id",
            "The host chain does not travel as its own field: it is read out of the handles, so a \
             second cluster necessarily changes the handles too. One program id deployed to two \
             clusters yields two distinct links. The cluster here is Solana mainnet-beta, so the \
             derived id is a value other implementations can check against their own \
             configuration.",
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
        Draft::invalid(
            "wrong-gateway-domain-name",
            "The Gateway domain is a link input, field by field. A response computed under a \
             domain with another contract name answers a different request.",
            VectorClass::LinkDivergence,
            rule::WRONG_GATEWAY_DOMAIN,
            "reference-two-handles",
            "the domain's name replaced",
            Inputs::reference().with_domain(DomainInputs {
                name: "NotDecryption",
                ..DomainInputs::reference()
            }),
        ),
        Draft::invalid(
            "wrong-gateway-domain-version",
            "The same domain with another version string.",
            VectorClass::LinkDivergence,
            rule::WRONG_GATEWAY_DOMAIN,
            "reference-two-handles",
            "the domain's version replaced",
            Inputs::reference().with_domain(DomainInputs {
                version: "2",
                ..DomainInputs::reference()
            }),
        ),
        Draft::invalid(
            "wrong-gateway-chain-id",
            "The same contract on another Gateway chain. This is the domain's chain id — the \
             Gateway's — not the Solana host chain id the handles carry; the two are different \
             inputs and this record moves only the first.",
            VectorClass::LinkDivergence,
            rule::WRONG_GATEWAY_DOMAIN,
            "reference-two-handles",
            "the domain's chain id incremented",
            Inputs::reference().with_domain(DomainInputs {
                chain_id: REFERENCE_GATEWAY_CHAIN_ID + 1,
                ..DomainInputs::reference()
            }),
        ),
        Draft::invalid(
            "wrong-gateway-verifying-contract",
            "Another Decryption contract address on the same Gateway chain: a second deployment of \
             the Gateway is a second domain.",
            VectorClass::LinkDivergence,
            rule::WRONG_GATEWAY_DOMAIN,
            "reference-two-handles",
            "the domain's verifying contract replaced",
            Inputs::reference().with_domain(DomainInputs {
                verifying_contract: Address::repeat_byte(0x11),
                ..DomainInputs::reference()
            }),
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
            "A 31-byte handle. keccak256 over the concatenated handles would accept it, which is \
             exactly why the width is checked before the hash: a short handle would shift every \
             byte after it and still produce a 32-byte link.",
            VectorClass::ConstructionReject,
            rule::HANDLE_WIDTH,
            "reference-two-handles",
            "the second handle truncated to 31 bytes",
            Inputs::reference().with_handles(vec![h(1), h(2)[..31].to_vec()]),
        ),
        Draft::invalid(
            "handle-without-the-solana-type-byte",
            "An EVM-kind handle mixed into a Solana batch, at index 1 rather than 0 so that a \
             check which trusts the first handle fails here. The type byte is the only \
             structural separator between the two request families.",
            VectorClass::ConstructionReject,
            rule::HANDLE_CHAIN_TYPE_BYTE,
            "reference-two-handles",
            "the second handle's embedded chain id stripped of type byte 0x01",
            Inputs::reference().with_handles(vec![
                h(1),
                handle(
                    reference_chain_id & kms_grpc::solana_binding::CLUSTER_TAG_MASK,
                    2,
                ),
            ]),
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
            "missing-domain",
            "The reference fields with no Gateway domain. The fields validate, but the domain is \
             an input of the link, so there is nothing to hash under: a consumer must refuse to \
             produce a link rather than substitute a default or empty domain. The check is the \
             caller's — a KMS party rejects a request without a domain before it builds the \
             binding, the WASM entry points throw, and a client has no expected link.",
            VectorClass::ConstructionReject,
            rule::MISSING_DOMAIN,
            "reference-two-handles",
            "the domain removed",
            Inputs {
                domain: None,
                ..Inputs::reference()
            },
        )
        .rejected_by(RejectedBy::DomainRequired),
        // --- foreign link --------------------------------------------------
        Draft::invalid(
            "unknown-type-string",
            "The reference fields hashed under the layout this specification considered and did \
             not adopt — an explicit uint64 hostChainId after the program id — as the EIP-712 type \
             it would be. The host chain is bound through the handles instead, and this record is \
             the version boundary made concrete: another type string is another type hash is \
             another link. A consumer must reject it on byte inequality with its own recomputed \
             link and must not parse a type out of a response to decide — the embedded link is \
             never a source of any value.",
            VectorClass::ForeignLink,
            rule::UNKNOWN_TYPE_STRING,
            "reference-two-handles",
            "the type string replaced by one with an explicit host chain id field, and that field \
             appended to encodeData",
            Inputs::reference(),
        )
        .with_source(LinkSource::UnknownType),
        Draft::invalid(
            "cross-version-replay",
            "A response built by a party still on the retired list-hash linker, replayed against \
             this version's request: the same fields under SHAKE256(\"HASH_LST\" || \"SOLLNK01\" \
             || u64le(count) || tag || program || chain id || recipient || handles || transport \
             key || extra_data). This is the mixed-version window during a rollout, and what the \
             client rule that discards a share whose link is not the recomputed one is for. The \
             record carries the extra_data the retired linker bound so that the value is \
             reproducible; the normative content is only that it is not equal to this version's \
             link.",
            VectorClass::ForeignLink,
            rule::CROSS_VERSION_REPLAY,
            "reference-two-handles",
            "the link replaced by the retired list-hash construction over the same fields",
            Inputs::reference(),
        )
        .with_source(LinkSource::RetiredListHash),
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
        VectorClass::ForeignLink => 3,
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
            "Normative vectors for the Solana user-decryption linker: the EIP-712 typed struct \
             SolanaUserDecryptionLinker hashed under the Gateway Decryption domain, the fields the \
             linker binds, and the negatives that must not share a link with them. Authorization \
             rules — the wallet permit, its validity window, delegation, ACL and lineage \
             resolution — are a separate layer and are not covered here; so is extra_data, which \
             the external response signature authenticates and the linker does not bind."
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
        type_string: TYPE_STRING.to_string(),
        type_hash: hex::encode(keccak256(TYPE_STRING.as_bytes())),
        domain_type_string: DOMAIN_TYPE_STRING.to_string(),
        construction_rule: CONSTRUCTION_RULE.to_string(),
        domain_note: DOMAIN_NOTE.to_string(),
        chain_id_derivation_rule: CHAIN_ID_DERIVATION_RULE.to_string(),
        cluster_registry_note: CLUSTER_REGISTRY_NOTE.to_string(),
        cluster_registry: cluster_registry(),
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

impl DomainEntry {
    /// The domain as the library takes it — the path every consuming implementation takes.
    fn to_alloy(&self) -> Eip712Domain {
        Eip712Domain::new(
            Some(self.name.clone().into()),
            Some(self.version.clone().into()),
            Some(U256::from(
                self.chain_id_decimal
                    .parse::<u64>()
                    .expect("a decimal gateway chain id"),
            )),
            Some(
                Address::parse_checksummed(&self.verifying_contract, None)
                    .expect("an EIP-55 verifying contract"),
            ),
            None,
        )
    }

    /// `hashStruct(EIP712Domain)`, spelled out from the specification rather than through the
    /// library: the domain type hash, the keccak-256 of the two strings, the chain id as a 32-byte
    /// big-endian word, the address left-padded to 32 bytes.
    fn hand_assembled_separator(&self) -> [u8; 32] {
        let chain_id: u64 = self
            .chain_id_decimal
            .parse()
            .expect("a decimal gateway chain id");
        let verifying_contract = Address::parse_checksummed(&self.verifying_contract, None)
            .expect("an EIP-55 verifying contract");

        let mut encoded = Vec::with_capacity(5 * 32);
        encoded.extend_from_slice(keccak256(DOMAIN_TYPE_STRING.as_bytes()).as_slice());
        encoded.extend_from_slice(keccak256(self.name.as_bytes()).as_slice());
        encoded.extend_from_slice(keccak256(self.version.as_bytes()).as_slice());
        encoded.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
        encoded.extend_from_slice(&[0u8; 12]);
        encoded.extend_from_slice(verifying_contract.as_slice());
        keccak256(encoded).0
    }
}

impl Record {
    /// Rebuilds the binding from the record alone — the path every consuming implementation takes.
    fn try_build(
        &self,
        file: &VectorFile,
    ) -> Result<SolanaUserDecryptBinding, SolanaUserDecryptBindingError> {
        let handles: Vec<Vec<u8>> = self.handle_bytes();

        SolanaUserDecryptBinding::new(
            &hex::decode(&self.verifying_program_id).expect("hex"),
            &hex::decode(&self.receiver_id).expect("hex"),
            handles.iter().map(|handle| handle.as_slice()),
            &file.transport_key_bytes(self),
        )
    }

    fn handle_bytes(&self) -> Vec<Vec<u8>> {
        self.handles
            .iter()
            .map(|handle| hex::decode(handle).expect("a hex handle"))
            .collect()
    }

    fn domain(&self) -> &DomainEntry {
        self.domain
            .as_ref()
            .unwrap_or_else(|| panic!("{} has no domain, but one was asked for", self.name))
    }

    fn link_bytes(&self) -> Vec<u8> {
        hex::decode(
            self.link
                .as_ref()
                .unwrap_or_else(|| panic!("{} has no link, but one was asked for", self.name)),
        )
        .expect("a hex link")
    }

    fn word(&self, field: &Option<String>, what: &str) -> [u8; 32] {
        hex::decode(
            field
                .as_ref()
                .unwrap_or_else(|| panic!("{} has no {what}, but one was asked for", self.name)),
        )
        .expect("hex")
        .try_into()
        .unwrap_or_else(|_| panic!("{}: {what} is not 32 bytes", self.name))
    }

    fn chain_id(&self) -> u64 {
        self.chain_id_decimal
            .parse()
            .unwrap_or_else(|_| panic!("{} has an unparseable chain id", self.name))
    }

    /// `encodeData` of this record's fields under its own type string, spelled out from the
    /// specification rather than through the library. Only for records of the file's type: a
    /// foreign type's layout is that record's own business.
    fn hand_assembled_encode_data(&self, file: &VectorFile) -> Vec<u8> {
        let handles: Vec<u8> = self.handle_bytes().concat();

        let mut encoded = Vec::with_capacity(5 * 32);
        encoded.extend_from_slice(keccak256(file.type_string.as_bytes()).as_slice());
        encoded.extend_from_slice(keccak256(file.transport_key_bytes(self)).as_slice());
        encoded.extend_from_slice(keccak256(&handles).as_slice());
        encoded.extend_from_slice(&hex::decode(&self.receiver_id).expect("hex"));
        encoded.extend_from_slice(&hex::decode(&self.verifying_program_id).expect("hex"));
        encoded
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
        rule::HANDLE_CHAIN_TYPE_BYTE => matches!(error, Error::InvalidHandleChainId { .. }),
        rule::MIXED_EMBEDDED_CHAIN_IDS => matches!(error, Error::MixedChainIds { .. }),
        rule::DECLARED_CHAIN_ID_MISMATCH => matches!(
            error,
            Error::DeclaredChainIdMismatch { .. } | Error::InvalidDeclaredChainId { .. }
        ),
        rule::IDENTITY_WIDTH => matches!(
            error,
            Error::InvalidProgramIdLength { .. } | Error::InvalidReceiverLength { .. }
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
fn committed_set_matches_canonical_output() {
    // The whole point of generator-equals-runner: no committed byte may exist that this tree does
    // not reproduce, and the failure is a readable JSON diff rather than a digest mismatch.
    assert_eq!(
        committed_json(),
        rendered(&build()),
        "the committed set no longer matches the tree. If the change is intended, regenerate with \
         {UPDATE_ENV}=1 and remember that these bytes are frozen: a layout change is a new type \
         name, not an edit.",
    );
}

#[test]
fn committed_digest_matches_set() {
    // The cross-repository mechanism: the digest file is what another repository's copy is
    // compared against, so it has to be right here before it can mean anything there.
    assert_eq!(committed_digest(), digest_line(&committed_json()));
}

#[test]
fn digest_file_is_single_sha256sum_line() {
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
fn header_pins_frozen_constants() {
    // The type string and its hash are frozen by this set, so the set has to say which values it
    // was frozen at — a consumer reading the JSON alone gets them from here. The library's own
    // encoding of the type must agree with the literal, and so must the frozen-constants gate.
    let file = committed();

    assert_eq!(file.schema, SCHEMA);
    assert_eq!(file.type_string, TYPE_STRING);
    assert_eq!(
        file.type_string,
        SolanaUserDecryptionLinker::eip712_encode_type(),
        "the library encodes the type differently from the published string",
    );
    assert_eq!(
        file.type_hash,
        hex::encode(keccak256(file.type_string.as_bytes()))
    );
    assert_eq!(file.domain_type_string, DOMAIN_TYPE_STRING);
    assert!(!file.construction_rule.is_empty());
    assert!(!file.domain_note.is_empty());
}

#[test]
fn valid_records_carry_binding_computed_link() {
    // The positive half: `valid` means the canonical constructor accepts these fields and the
    // recorded 32 bytes are what a conforming response must carry, under the record's own domain.
    let file = committed();
    let valid = records_of(&file, VectorClass::Valid);
    assert!(valid.len() >= 4, "the set lost its positive records");

    for record in valid {
        assert_eq!(record.result, VectorResult::Valid, "{}", record.name);
        assert_eq!(record.construction, CONSTRUCTION_EIP712, "{}", record.name);
        assert_eq!(
            record.type_string.as_deref(),
            Some(file.type_string.as_str()),
            "{}",
            record.name
        );
        let binding = record
            .try_build(&file)
            .unwrap_or_else(|error| panic!("{} must validate, got {error}", record.name));

        assert_eq!(
            binding.compute_link(&record.domain().to_alloy()),
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
fn link_divergence_records_differ_from_base() {
    // These records are well-formed requests whose link is not the base's, which is the property
    // that makes response substitution detectable rather than silent.
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
            binding.compute_link(&record.domain().to_alloy()),
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
fn gateway_domain_records_move_one_domain_field_each() {
    // The four domain records are the four fields of the domain, one at a time; the domain
    // separator moves with each, and the request fields do not.
    let file = committed();
    let reference = file.record("reference-two-handles");
    let domain_records: Vec<&Record> = file
        .records
        .iter()
        .filter(|record| record.rule.as_deref() == Some(rule::WRONG_GATEWAY_DOMAIN))
        .collect();
    assert_eq!(domain_records.len(), 4, "one record per domain field");

    for record in domain_records {
        let base_domain = reference.domain();
        let domain = record.domain();
        let changed = [
            domain.name != base_domain.name,
            domain.version != base_domain.version,
            domain.chain_id_decimal != base_domain.chain_id_decimal,
            domain.verifying_contract != base_domain.verifying_contract,
        ]
        .iter()
        .filter(|changed| **changed)
        .count();
        assert_eq!(
            changed, 1,
            "{} changes more than one domain field",
            record.name
        );

        assert_ne!(
            record.domain_separator, reference.domain_separator,
            "{} keeps the reference domain separator",
            record.name
        );
        assert_eq!(
            record.hash_struct, reference.hash_struct,
            "{} changes the struct hash, but only the domain moved",
            record.name
        );
        assert_eq!(record.handles, reference.handles, "{}", record.name);
        assert_eq!(record.receiver_id, reference.receiver_id, "{}", record.name);
    }
}

#[test]
fn record_links_are_unique() {
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
fn construction_reject_records_refused_by_named_rule() {
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
                    record.hash_struct.is_none(),
                    "{} must have no struct hash",
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
            RejectedBy::DomainRequired => {
                // Constructible, and there is nothing wrong with the fields: the record has no
                // domain, so `compute_link` has nothing to be called with. The refusal is the
                // caller's, and the record pins that no link, struct hash or separator exists.
                assert_eq!(named, rule::MISSING_DOMAIN, "{}", record.name);
                assert!(
                    record.domain.is_none(),
                    "{} must have no domain",
                    record.name
                );
                assert!(record.link.is_none(), "{} must have no link", record.name);
                assert!(record.hash_struct.is_none(), "{}", record.name);
                assert!(record.domain_separator.is_none(), "{}", record.name);
                record
                    .try_build(&file)
                    .unwrap_or_else(|error| panic!("{} must build, got {error}", record.name));
            }
        }
    }
}

#[test]
fn foreign_link_records_never_match_this_versions_link() {
    // Cross-version replay and an undefined type need no rule of their own — a foreign value fails
    // byte equality with the recomputed link. The assertion is inequality with the link the
    // canonical function computes for exactly these fields under the record's own domain.
    let file = committed();
    let foreign = records_of(&file, VectorClass::ForeignLink);
    assert!(!foreign.is_empty(), "the set lost its foreign-link records");

    for record in foreign {
        assert_eq!(record.result, VectorResult::Invalid, "{}", record.name);
        let binding = record
            .try_build(&file)
            .unwrap_or_else(|error| panic!("{} must build, got {error}", record.name));

        assert_eq!(record.link_bytes().len(), LINK_LEN, "{}", record.name);
        assert_ne!(
            record.link_bytes(),
            binding.compute_link(&record.domain().to_alloy()),
            "{} equals this version's link for its own fields",
            record.name,
        );

        match record.construction.as_str() {
            CONSTRUCTION_EIP712 => assert_ne!(
                record.type_string.as_deref(),
                Some(file.type_string.as_str()),
                "{} is an eip712 record under the file's own type",
                record.name,
            ),
            CONSTRUCTION_RETIRED_LIST_HASH => assert!(
                record.type_string.is_none() && record.extra_data.is_some(),
                "{} must carry the retired linker's extra_data and no type string",
                record.name,
            ),
            other => panic!("{}: unknown construction {other}", record.name),
        }
    }
}

#[test]
fn cross_version_replay_record_is_the_retired_link() {
    // Reproducible, not just different: the retired construction is spelled out here from its
    // specification, over the record's own fields and the extra_data it carries, and must yield
    // exactly the published value. A consumer that still had the retired linker would compute
    // this; the client rule discards it.
    let file = committed();
    let record = file.record("cross-version-replay");
    let extra_data = hex::decode(record.extra_data.as_ref().expect("the bound extra_data"))
        .expect("hex extra_data");
    let chain_id = record.chain_id().to_be_bytes();
    let transport_key = file.transport_key_bytes(record);
    let receiver = hex::decode(&record.receiver_id).expect("hex");
    let program = hex::decode(&record.verifying_program_id).expect("hex");
    let handles = record.handle_bytes();

    let mut elements: Vec<&[u8]> = vec![
        RETIRED_SCHEME_TAG.as_bytes(),
        &program,
        &chain_id,
        &receiver,
    ];
    elements.extend(handles.iter().map(|handle| handle.as_slice()));
    elements.push(&transport_key);
    elements.push(&extra_data);

    assert_eq!(
        unsafe_hash_list_w_size(&RETIRED_DSEP, &elements, LINK_LEN),
        record.link_bytes(),
    );
    assert_eq!(record.construction, CONSTRUCTION_RETIRED_LIST_HASH);
}

#[test]
fn struct_hashes_and_links_match_hand_assembly() {
    // The published `hash_struct` and `domain_separator` are the two halves of the preimage, so a
    // consumer that reproduces them and gets a different link knows the disagreement is in the
    // final hash, not in the layout. Both are recomputed here from the specification, not from
    // the library; the link must then be keccak256 over `0x1901`, the separator and the struct hash.
    let file = committed();
    let mut checked = 0;

    for record in &file.records {
        let Some(link) = &record.link else {
            continue;
        };
        if record.construction != CONSTRUCTION_EIP712 {
            continue;
        }

        let separator = record.word(&record.domain_separator, "domain separator");
        assert_eq!(
            separator,
            record.domain().hand_assembled_separator(),
            "{}: the published domain separator is not hashStruct(EIP712Domain) of its domain",
            record.name,
        );
        assert_eq!(
            separator,
            record.domain().to_alloy().separator().0,
            "{}: the library's separator disagrees with the specification",
            record.name,
        );

        let hash_struct = record.word(&record.hash_struct, "struct hash");
        if record.type_string.as_deref() == Some(file.type_string.as_str()) {
            assert_eq!(
                hash_struct,
                keccak256(record.hand_assembled_encode_data(&file)).0,
                "{}: the published struct hash is not keccak256(encodeData) of its fields",
                record.name,
            );
        }

        assert_eq!(
            hex::encode(eip712_link(&separator, &hash_struct)),
            *link,
            "{}: the link is not keccak256(0x1901 || domainSeparator || hashStruct)",
            record.name,
        );
        checked += 1;
    }

    assert!(
        checked >= 15,
        "only {checked} records carried an eip712 struct hash"
    );
}

#[test]
fn every_linked_record_carries_its_domain() {
    // "Every record carries the domain it was computed under" is a rule of the file, not a habit
    // of the reference records: a consumer must never have to guess a domain to reproduce a link.
    let file = committed();

    for record in &file.records {
        if record.link.is_none() {
            continue;
        }
        assert!(
            record.domain.is_some(),
            "{} has a link but no domain",
            record.name
        );
        if record.construction == CONSTRUCTION_EIP712 {
            assert!(
                record.domain_separator.is_some() && record.hash_struct.is_some(),
                "{} is an eip712 record without both halves of its preimage",
                record.name,
            );
        }
    }
}

#[test]
fn rejecting_records_isolate_exactly_one_violation() {
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
fn rule_dictionary_is_covered_in_both_directions() {
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
fn set_contains_no_json_numbers() {
    // Every 64-bit value is a decimal string. A JSON number reaches a TypeScript consumer as a
    // double, and every host chain id here is above 2^53, so the rounding would be silent. The
    // gateway chain id is small today; it is a string anyway, so one parser serves both.
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
fn chain_ids_exceed_javascript_safe_integer() {
    // Not an accident to be preserved by luck: type byte 0x01 puts every Solana chain id
    // above 2^53. The canary is the whole set, not one record.
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
fn three_chain_id_forms_agree_with_recomputed_rule() {
    // The shared fixture format requires three forms; three forms that disagree are worse than one.
    // The rule is recomputed here from the record's own genesis hash rather than trusted from the
    // file.
    let file = committed();

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
        assert!(
            kms_grpc::solana_binding::is_solana_host_chain_id(decimal),
            "{} must have Solana type byte 0x01",
            record.name,
        );
    }
}

#[test]
fn reference_cluster_matches_permit_set() {
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
    // The permit's signed extra_data is bound by the retired linker only, and the one record that
    // reproduces that linker carries exactly the permit set's bytes.
    assert_eq!(
        file.record("cross-version-replay").extra_data.as_deref(),
        Some(REFERENCE_EXTRA_DATA_HEX),
    );
}

#[test]
fn reference_domain_is_the_gateway_decryption_domain() {
    // The domain is the Gateway Decryption contract's, not one built from the Solana host chain:
    // the contract's declared name and version, a Gateway chain id, a contract address.
    let file = committed();
    let domain = file.record("reference-two-handles").domain();

    assert_eq!(domain.name, REFERENCE_DOMAIN_NAME);
    assert_eq!(domain.version, REFERENCE_DOMAIN_VERSION);
    assert_eq!(
        domain.chain_id_decimal,
        REFERENCE_GATEWAY_CHAIN_ID.to_string()
    );
    assert_eq!(
        domain.verifying_contract,
        REFERENCE_VERIFYING_CONTRACT.to_checksum(None)
    );
    assert_ne!(
        domain.chain_id_decimal,
        file.record("reference-two-handles").chain_id_decimal,
        "the Gateway chain id and the Solana host chain id are different inputs",
    );
}

#[test]
fn reference_key_is_committed_869_byte_container() {
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

#[test]
fn cluster_registry_matches_rule_on_each_genesis_hash() {
    // This table is what a deployment review checks a cluster configuration against. Each id is
    // pinned to a reviewed constant, not recomputed by the same function that filled the table.
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
        let reviewed = PUBLIC_CLUSTER_CHAIN_IDS
            .iter()
            .find(|(name, _)| *name == cluster.as_str())
            .map(|(_, id)| *id)
            .unwrap_or_else(|| panic!("{cluster} is not a reviewed public cluster"));

        assert_eq!(decimal, hex_form, "{cluster}");
        assert_eq!(
            hex::decode(&entry.chain_id_be_bytes).expect("hex"),
            decimal.to_be_bytes(),
            "{cluster}",
        );
        assert_eq!(
            decimal, reviewed,
            "{cluster} records a chain id that is not the reviewed public-cluster id",
        );
        assert_eq!(
            decimal,
            derive_chain_id(&entry.genesis_hash),
            "{cluster} records a chain id that is not the rule applied to its genesis hash",
        );

        let genesis = base58_decode(&entry.genesis_hash).expect("base58");
        assert_eq!(genesis.len(), 32, "{cluster}");
        assert_eq!(
            hex::decode(&entry.genesis_hash_bytes).expect("hex"),
            genesis,
            "{cluster} records two disagreeing forms of its genesis hash",
        );

        assert!(
            kms_grpc::solana_binding::is_solana_host_chain_id(decimal),
            "{cluster} is a Solana-kind chain and must have type byte 0x01",
        );
        assert!(
            seen_ids.insert(decimal),
            "{cluster} collides with another cluster's chain id",
        );
    }
}

#[test]
fn registry_mainnet_entry_matches_wrong_chain_id_record() {
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
fn derivation_rule_sets_type_byte_and_keeps_genesis_prefix() {
    // The rule is two operations: type byte 0x01, then the first seven genesis bytes. The expected
    // id is a reviewed constant, not a second copy of `derive_chain_id`.
    assert_eq!(derive_chain_id(REFERENCE_GENESIS), REFERENCE_CHAIN_ID);
    assert_eq!(
        kms_grpc::solana_binding::chain_type_byte(REFERENCE_CHAIN_ID),
        0x01,
    );
    let genesis = base58_decode(REFERENCE_GENESIS).expect("base58");
    assert_eq!(&REFERENCE_CHAIN_ID.to_be_bytes()[1..], &genesis[..7]);
    assert_ne!(
        derive_chain_id(REFERENCE_GENESIS),
        derive_chain_id(OTHER_GENESIS),
        "two clusters must not derive one chain id",
    );
}
