use super::traits::BaseKms;
use crate::consts::ID_LENGTH;
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::decompression;
use crate::cryptography::internal_crypto_types::WrappedDKGParams;
use crate::cryptography::signatures::internal_sign;
use crate::cryptography::signatures::{PrivateSigKey, PublicSigKey, Signature};
use crate::cryptography::signing::SigningSchemeType;
use crate::engine::traits::PrivateKeyMaterialMetadata;
use crate::util::key_setup::FhePrivateKey;
use aes_prng::AesRng;
use alloy_dyn_abi::DynSolValue;
use alloy_primitives::U256;
use alloy_primitives::{Address, B256, Bytes, FixedBytes, Uint};
use alloy_sol_types::Eip712Domain;
use alloy_sol_types::SolStruct;
use hashing::{DomainSep, hash_element, hash_versioned, serialize_hash_element};
use kms_grpc::RequestId;
use kms_grpc::kms::v1::{
    CiphertextFormat, FheParameter, PublicDecryptionResponsePayload, TypedPlaintext,
    TypedSignature, UserDecryptionResponsePayload,
};
use kms_grpc::rpc_types::CrsGenMetadataV0;
use kms_grpc::rpc_types::KMSType;
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::rpc_types::SignedPubDataHandleInternal;
use kms_grpc::rpc_types::abi_encode_plaintexts;
use kms_grpc::solidity_types::{
    CrsgenVerification, FheDecompressionUpgradeKey, KeygenVerification, PrepKeygenVerification,
    PublicDecryptVerification,
};
use kms_grpc::utils::tonic_result::BoxedStatus;
use rand::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use tfhe::FheUint80;
use tfhe::integer::BooleanBlock;
use tfhe::integer::compression_keys::DecompressionKey;
use tfhe::named::Named;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::xof_key_set::CompressedXofKeySet;
use tfhe::zk::CompactPkeCrs;
use tfhe::{
    FheBool, FheUint4, FheUint8, FheUint16, FheUint32, FheUint64, FheUint128, FheUint160,
    FheUint256, FheUint512, FheUint1024, FheUint2048,
};
use tfhe::{FheTypes, Versionize};
use tfhe_versionable::Upgrade;
use tfhe_versionable::Version;
use tfhe_versionable::VersionsDispatch;
use threshold_execution::endpoints::decryption::RadixOrBoolCiphertext;
use threshold_execution::endpoints::decryption::{LowLevelCiphertext, SnsRadixOrBoolCiphertext};
use threshold_execution::tfhe_internals::parameters::DKGParams;
use threshold_execution::tfhe_internals::public_keysets::FhePubKeySet;
use threshold_execution::zk::ceremony::max_num_bits_from_crs;
use tokio::sync::Mutex;
use tracing::error;

// Domain separators for cryptographic operations to ensure domain separation

/// Domain separator for request ID hashing
pub(crate) const DSEP_REQUEST_ID: DomainSep = *b"REQST_ID";
/// Domain separator for handle generation
pub(crate) const DSEP_HANDLE: DomainSep = *b"_HANDLE_";
/// Domain separator for public key data
pub const DSEP_PUBDATA_KEY: DomainSep = *b"PDAT_KEY";
/// Domain separator for CRS (Common Reference String) data
pub const DSEP_PUBDATA_CRS: DomainSep = *b"PDAT_CRS";

pub static INSECURE_PREPROCESSING_ID: LazyLock<RequestId> =
    LazyLock::new(|| crate::engine::base::derive_request_id("INSECURE_PREPROCESSING_ID").unwrap());

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
#[expect(clippy::large_enum_variant)]
pub enum KmsFheKeyHandlesVersions {
    V0(KmsFheKeyHandlesV0),
    V1(KmsFheKeyHandles),
}

impl Upgrade<KmsFheKeyHandles> for KmsFheKeyHandlesV0 {
    type Error = std::convert::Infallible;
    fn upgrade(self) -> Result<KmsFheKeyHandles, Self::Error> {
        Ok(KmsFheKeyHandles {
            client_key: self.client_key,
            decompression_key: self.decompression_key,
            public_key_info: KeyGenMetadata::LegacyV0(self.public_key_info),
        })
    }
}

/// Centralized KMS private key material storage
///
/// This structure securely holds sensitive key material used by the KMS,
/// including the client key, optional decompression key, and public key metadata.
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(KmsFheKeyHandlesVersions)]
pub struct KmsFheKeyHandles {
    /// Client's private key for FHE operations
    pub client_key: FhePrivateKey,

    /// Optional key for ciphertext decompression
    pub decompression_key: Option<DecompressionKey>,

    /// Maps public key types to their corresponding signed handles and metadata
    pub public_key_info: KeyGenMetadata,
}

impl PrivateKeyMaterialMetadata for KmsFheKeyHandles {
    fn get_metadata(&self) -> &KeyGenMetadata {
        &self.public_key_info
    }
}

impl Named for KmsFheKeyHandles {
    /// Returns the type name for versioning and serialization
    const NAME: &'static str = "KmsFheKeyHandles";
}

impl KmsFheKeyHandles {
    /// Computes key handles for public key materials with signatures.
    ///
    /// # Important
    /// - Only use with freshly generated keys
    /// - Not suitable for existing keys due to versioning constraints
    /// - Version upgrades will invalidate signatures
    ///
    /// # Security Note
    /// Signatures are computed over versionized keys to ensure consistency.
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        sig_key: &PrivateSigKey,
        schemes: &[SigningSchemeType],
        client_key: FhePrivateKey,
        key_id: &RequestId,
        preproc_id: &RequestId,
        keyset: &FhePubKeySet,
        decompression_key: Option<DecompressionKey>,
        eip712_domain: &alloy_sol_types::Eip712Domain,
        extra_data: Vec<u8>,
    ) -> anyhow::Result<Self> {
        let public_key_info = compute_info_uncompressed_keygen(
            sig_key,
            schemes,
            &crate::engine::base::DSEP_PUBDATA_KEY,
            preproc_id,
            key_id,
            keyset,
            eip712_domain,
            extra_data,
        )?;

        Ok(KmsFheKeyHandles {
            client_key,
            decompression_key,
            public_key_info,
        })
    }

    /// Computes key handles for compressed public key materials with signatures.
    ///
    /// This is similar to [`Self::new`] but for compressed keys using
    /// [`CompressedXofKeySet`] instead of [`FhePubKeySet`].
    ///
    /// # Important
    /// - Only use with freshly generated compressed keys
    /// - Not suitable for existing keys due to versioning constraints
    /// - Version upgrades will invalidate signatures
    #[expect(clippy::too_many_arguments)]
    pub fn new_compressed(
        sig_key: &PrivateSigKey,
        schemes: &[SigningSchemeType],
        client_key: FhePrivateKey,
        key_id: &RequestId,
        preproc_id: &RequestId,
        compressed_keyset: &CompressedXofKeySet,
        compact_public_key: &tfhe::CompactPublicKey,
        decompression_key: Option<DecompressionKey>,
        eip712_domain: &alloy_sol_types::Eip712Domain,
        extra_data: Vec<u8>,
    ) -> anyhow::Result<Self> {
        let public_key_info = compute_info_compressed_keygen(
            sig_key,
            schemes,
            &crate::engine::base::DSEP_PUBDATA_KEY,
            preproc_id,
            key_id,
            compressed_keyset,
            compact_public_key,
            eip712_domain,
            extra_data,
        )?;

        Ok(KmsFheKeyHandles {
            client_key,
            decompression_key,
            public_key_info,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, Version)]
pub struct KmsFheKeyHandlesV0 {
    /// Client's private key for FHE operations
    pub client_key: FhePrivateKey,

    /// Optional key for ciphertext decompression
    pub decompression_key: Option<DecompressionKey>,

    /// Maps public key types to their corresponding signed handles and metadata
    pub public_key_info: HashMap<PubDataType, SignedPubDataHandleInternal>,
}

/// Derives a deterministic request ID from an input string.
///
/// # Usage
/// Primarily for testing and internal purposes (e.g., PRSS IDs).
/// In production, request IDs should be derived by the smart contract.
///
/// # Arguments
/// * `name` - Input string to derive ID from
///
/// # Returns
/// - `Ok(RequestId)` on success
/// - `Err` if hashing fails
pub fn derive_request_id(name: &str) -> anyhow::Result<RequestId> {
    let mut digest = serialize_hash_element(&DSEP_REQUEST_ID, &name.to_string())?;
    if digest.len() < ID_LENGTH {
        anyhow::bail!(
            "derived request ID should have at least length {ID_LENGTH}, but only got {}",
            digest.len()
        )
    }
    // Truncate and convert to hex
    digest.truncate(ID_LENGTH);
    let res_hex = hex::encode(digest);
    Ok(RequestId::from_str(&res_hex)?)
}

/// A single KMS signature together with the scheme that produced it, in the
/// form persisted inside result metadata.
///
/// This is the stored twin of the gRPC [`TypedSignature`].
#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum StoredTypedSignatureVersions {
    V0(StoredTypedSignature),
}

/// A single KMS signature together with the scheme that produced it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(StoredTypedSignatureVersions)]
pub struct StoredTypedSignature {
    pub scheme: SigningSchemeType,
    pub signature: Vec<u8>,
}

impl From<&StoredTypedSignature> for TypedSignature {
    fn from(value: &StoredTypedSignature) -> Self {
        TypedSignature {
            scheme: kms_grpc::kms::v1::SigningSchemeType::from(value.scheme) as i32,
            signature: value.signature.clone(),
        }
    }
}

/// The result payload that every non-ECDSA scheme signs for a preprocessing
/// result.
#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum PrepKeygenSignedPayloadVersions {
    V0(PrepKeygenSignedPayload),
}

/// The preprocessing result, in the form non-ECDSA schemes sign it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(PrepKeygenSignedPayloadVersions)]
pub struct PrepKeygenSignedPayload {
    pub prep_id: RequestId,
    pub extra_data: Vec<u8>,
}

impl Named for PrepKeygenSignedPayload {
    const NAME: &'static str = "PrepKeygenSignedPayload";
}

/// The result payload that every non-ECDSA scheme signs for a keygen result.
#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum KeygenSignedPayloadVersions {
    V0(KeygenSignedPayload),
}

/// The keygen result, in the form non-ECDSA schemes sign it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(KeygenSignedPayloadVersions)]
pub struct KeygenSignedPayload {
    pub prep_id: RequestId,
    pub key_id: RequestId,
    /// Ordered by key type, so the serialization is deterministic.
    pub key_digests: BTreeMap<PubDataType, Vec<u8>>,
    pub extra_data: Vec<u8>,
}

impl Named for KeygenSignedPayload {
    const NAME: &'static str = "KeygenSignedPayload";
}

/// The result payload that every non-ECDSA scheme signs for a CRS result.
#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum CrsSignedPayloadVersions {
    V0(CrsSignedPayload),
}

/// The CRS generation result, in the form non-ECDSA schemes sign it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CrsSignedPayloadVersions)]
pub struct CrsSignedPayload {
    pub crs_id: RequestId,
    pub max_num_bits: u32,
    pub crs_digest: Vec<u8>,
    pub extra_data: Vec<u8>,
}

impl Named for CrsSignedPayload {
    const NAME: &'static str = "CrsSignedPayload";
}

/// The canonical bytes a non-ECDSA scheme signs for a public result.
///
/// Serialized with `safe_serialize`, so the type name and version are part of
/// what gets signed: changing a payload's layout later produces a new version
/// tag rather than silently making old signatures unverifiable against the new
/// reconstruction.
///
/// Decryption is the exception — it signs `bc2wrap::serialize` of the gRPC
/// response payload, because those exact bytes are also what the deprecated
/// scalar `signature` field covers and are already part of the released wire
/// contract. TODO(0.16): once that field is gone, decryption can move onto this
/// helper too.
fn signed_payload_bytes<T>(payload: &T) -> anyhow::Result<Vec<u8>>
where
    T: Serialize + Versionize + Named,
{
    let mut buf = Vec::new();
    safe_serialize(payload, &mut buf, SAFE_SER_SIZE_LIMIT)?;
    Ok(buf)
}

/// The canonical bytes a non-ECDSA scheme signs for a keygen result.
///
/// Shared between signing and after-the-fact verification (see
/// [`crate::engine::public_material_verification`]) so there is exactly one definition of
/// what was signed.
pub(crate) fn keygen_payload_bytes(
    prep_id: &RequestId,
    key_id: &RequestId,
    key_digests: &BTreeMap<PubDataType, Vec<u8>>,
    extra_data: &[u8],
) -> anyhow::Result<Vec<u8>> {
    signed_payload_bytes(&KeygenSignedPayload {
        prep_id: *prep_id,
        key_id: *key_id,
        key_digests: key_digests.clone(),
        extra_data: extra_data.to_vec(),
    })
}

/// The canonical bytes a non-ECDSA scheme signs for a CRS result.
///
/// Shared between signing and after-the-fact verification (see
/// [`crate::engine::public_material_verification`]) so there is exactly one definition of
/// what was signed.
pub(crate) fn crs_payload_bytes(
    crs_id: &RequestId,
    max_num_bits: u32,
    crs_digest: &[u8],
    extra_data: &[u8],
) -> anyhow::Result<Vec<u8>> {
    signed_payload_bytes(&CrsSignedPayload {
        crs_id: *crs_id,
        max_num_bits,
        crs_digest: crs_digest.to_vec(),
        extra_data: extra_data.to_vec(),
    })
}

/// Convert stored per-scheme signatures into their gRPC representation.
pub(crate) fn stored_scheme_signatures_to_proto(
    signatures: &[StoredTypedSignature],
) -> Vec<TypedSignature> {
    signatures.iter().map(TypedSignature::from).collect()
}

/// One scheme's contribution to a result's `signatures` list: the message that
/// scheme signs.
struct SchemeSigningJob {
    pub scheme: SigningSchemeType,
    pub message: Vec<u8>,
}

/// Sign a result under each requested `(scheme, message)` job, returning the
/// per-scheme signatures to persist in result metadata.
fn compute_result_signatures(
    sk: &PrivateSigKey,
    dsep: &DomainSep,
    jobs: &[SchemeSigningJob],
) -> anyhow::Result<Vec<StoredTypedSignature>> {
    jobs.iter()
        .map(|job| {
            let signature = match job.scheme {
                SigningSchemeType::Ecdsa256k1 => {
                    let hash =
                        alloy_primitives::B256::try_from(job.message.as_slice()).map_err(|_| {
                            anyhow::anyhow!(
                                "EIP-712 signing hash must be 32 bytes, got {}",
                                job.message.len()
                            )
                        })?;
                    crate::cryptography::signatures::eip712_sign_hash(sk, &hash)?
                }
                // Raw primitive signature over `dsep ‖ message`.
                scheme @ (SigningSchemeType::Ed25519
                | SigningSchemeType::MlDsa44
                | SigningSchemeType::MlDsa65
                | SigningSchemeType::MlDsa87) => {
                    sk.unified_sign_with(scheme, dsep, &job.message)?.to_bytes()
                }
            };
            Ok(StoredTypedSignature {
                scheme: job.scheme,
                signature,
            })
        })
        .collect()
}

/// Build the per-scheme signing jobs for a result's `signatures` list.
///
/// ECDSA signs `eip712_hash`, producing the same on-chain-verifiable signature
/// the fhevm contracts verify — byte-identical to the result's
/// `external_signature` — so that once the deprecated `external_signature` field
/// goes away, `signatures` still carries it.
///
/// Every other scheme signs `payload_bytes`, the serialized result payload:
/// EIP-712 is an EVM/secp256k1 construction, and a post-quantum scheme has no
/// reason to be bound to it. Each job carries its own message, so a
/// scheme-specific serialization can be introduced here without touching callers
/// or [`compute_result_signatures`].
fn scheme_signing_jobs(
    schemes: &[SigningSchemeType],
    eip712_hash: &[u8],
    payload_bytes: &[u8],
) -> Vec<SchemeSigningJob> {
    schemes
        .iter()
        .map(|&scheme| SchemeSigningJob {
            scheme,
            message: if scheme == SigningSchemeType::Ecdsa256k1 {
                eip712_hash.to_vec()
            } else {
                payload_bytes.to_vec()
            },
        })
        .collect()
}

/// Sign a public result: the canonical ECDSA/EIP-712 `external_signature`, and —
/// independently — the per-scheme `signatures` for exactly the schemes the
/// client requested.
fn sign_result<D: SolStruct>(
    sk: &PrivateSigKey,
    schemes: &[SigningSchemeType],
    payload_bytes: &[u8],
    sol_type: &D,
    domain: &Eip712Domain,
    dsep: &DomainSep,
) -> anyhow::Result<(Vec<u8>, Vec<StoredTypedSignature>)> {
    let eip712_hash = sol_type.eip712_signing_hash(domain);
    let external_signature = crate::cryptography::signatures::eip712_sign_hash(sk, &eip712_hash)?;
    let jobs = scheme_signing_jobs(schemes, eip712_hash.as_slice(), payload_bytes);
    let signatures = compute_result_signatures(sk, dsep, &jobs)?;
    Ok((external_signature, signatures))
}

pub(crate) fn compute_info_crs(
    sk: &PrivateSigKey,
    schemes: &[SigningSchemeType],
    domain_separator: &DomainSep,
    crs_id: &RequestId,
    pp: &CompactPkeCrs,
    domain: &alloy_sol_types::Eip712Domain,
    extra_data: Vec<u8>,
) -> anyhow::Result<CrsGenMetadata> {
    let crs_digest = hash_versioned(domain_separator, pp)?;
    let max_num_bits = max_num_bits_from_crs(pp);
    compute_info_crs_from_digest(
        sk,
        schemes,
        crs_id,
        crs_digest,
        max_num_bits,
        domain,
        extra_data,
    )
}

/// Sign a CRS using a precomputed digest, under each requested scheme.
pub(crate) fn compute_info_crs_from_digest(
    sk: &PrivateSigKey,
    schemes: &[SigningSchemeType],
    crs_id: &RequestId,
    crs_digest: Vec<u8>,
    max_num_bits: usize,
    domain: &alloy_sol_types::Eip712Domain,
    extra_data: Vec<u8>,
) -> anyhow::Result<CrsGenMetadata> {
    let sol_type =
        CrsgenVerification::new(crs_id, max_num_bits, crs_digest.clone(), extra_data.clone());
    let payload_bytes = crs_payload_bytes(crs_id, max_num_bits as u32, &crs_digest, &extra_data)?;
    let (external_signature, signatures) = sign_result(
        sk,
        schemes,
        &payload_bytes,
        &sol_type,
        domain,
        &DSEP_PUBDATA_CRS,
    )?;

    Ok(CrsGenMetadata::new(
        *crs_id,
        crs_digest,
        max_num_bits as u32,
        domain,
        external_signature,
        signatures,
        extra_data,
    ))
}

/// Sign a preprocessing result: the always-present ECDSA/EIP-712
/// `external_signature`, plus the per-scheme `signatures` for exactly the
/// requested schemes.
pub(crate) fn compute_preprocessing_signatures(
    sk: &PrivateSigKey,
    schemes: &[SigningSchemeType],
    prep_id: &RequestId,
    domain: &alloy_sol_types::Eip712Domain,
    extra_data: Vec<u8>,
) -> anyhow::Result<(Vec<u8>, Vec<StoredTypedSignature>)> {
    let payload_bytes = signed_payload_bytes(&PrepKeygenSignedPayload {
        prep_id: *prep_id,
        extra_data: extra_data.clone(),
    })?;
    let sol_type = PrepKeygenVerification::new(prep_id, extra_data);
    sign_result(
        sk,
        schemes,
        &payload_bytes,
        &sol_type,
        domain,
        &DSEP_PUBDATA_KEY,
    )
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn compute_info_uncompressed_keygen(
    sk: &PrivateSigKey,
    schemes: &[SigningSchemeType],
    domain_separator: &DomainSep,
    prep_id: &RequestId,
    key_id: &RequestId,
    keyset: &FhePubKeySet,
    domain: &alloy_sol_types::Eip712Domain,
    extra_data: Vec<u8>,
) -> anyhow::Result<KeyGenMetadata> {
    let (server_key_digest, public_key_digest) = compute_keygen_digests(domain_separator, keyset)?;
    compute_info_standard_keygen_from_digests(
        sk,
        schemes,
        prep_id,
        key_id,
        server_key_digest,
        public_key_digest,
        domain,
        extra_data,
    )
}

/// Hash the server key and public key for handle/signature derivation.
pub(crate) fn compute_keygen_digests(
    domain_separator: &DomainSep,
    keyset: &FhePubKeySet,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let server_key_digest = hash_versioned(domain_separator, &keyset.server_key)?;
    let public_key_digest = hash_versioned(domain_separator, &keyset.public_key)?;

    tracing::info!(
        "Computed server key digest: {} and public key digest: {}",
        hex::encode(&server_key_digest),
        hex::encode(&public_key_digest)
    );

    Ok((server_key_digest, public_key_digest))
}

/// Sign an uncompressed keygen using precomputed digests.
#[expect(clippy::too_many_arguments)]
pub(crate) fn compute_info_standard_keygen_from_digests(
    sk: &PrivateSigKey,
    schemes: &[SigningSchemeType],
    prep_id: &RequestId,
    key_id: &RequestId,
    server_key_digest: Vec<u8>,
    public_key_digest: Vec<u8>,
    domain: &alloy_sol_types::Eip712Domain,
    extra_data: Vec<u8>,
) -> anyhow::Result<KeyGenMetadata> {
    let sol_type = KeygenVerification::new_uncompressed(
        prep_id,
        key_id,
        server_key_digest.clone(),
        public_key_digest.clone(),
        extra_data.clone(),
    );
    let key_digests = BTreeMap::from([
        (PubDataType::ServerKey, server_key_digest),
        (PubDataType::PublicKey, public_key_digest),
    ]);
    let payload_bytes = keygen_payload_bytes(prep_id, key_id, &key_digests, &extra_data)?;
    let (external_signature, signatures) = sign_result(
        sk,
        schemes,
        &payload_bytes,
        &sol_type,
        domain,
        &DSEP_PUBDATA_KEY,
    )?;

    Ok(KeyGenMetadata::new(
        *key_id,
        *prep_id,
        key_digests,
        domain,
        external_signature,
        signatures,
        extra_data,
    ))
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn compute_info_decompression_keygen(
    sk: &PrivateSigKey,
    schemes: &[SigningSchemeType],
    domain_separator: &DomainSep,
    prep_id: &RequestId,
    key_id: &RequestId,
    decompression_key: &DecompressionKey,
    domain: &alloy_sol_types::Eip712Domain,
    extra_data: Vec<u8>,
) -> anyhow::Result<KeyGenMetadata> {
    let key_digest = hash_versioned(domain_separator, decompression_key)?;

    let sol_type = FheDecompressionUpgradeKey {
        decompressionUpgradeKeyDigest: key_digest.to_vec().into(),
        extraData: extra_data.clone().into(),
    };
    let key_digests = BTreeMap::from([(PubDataType::DecompressionKey, key_digest)]);
    let payload_bytes = keygen_payload_bytes(prep_id, key_id, &key_digests, &extra_data)?;
    let (external_signature, signatures) = sign_result(
        sk,
        schemes,
        &payload_bytes,
        &sol_type,
        domain,
        &DSEP_PUBDATA_KEY,
    )?;

    Ok(KeyGenMetadata::new(
        *key_id,
        *prep_id,
        key_digests,
        domain,
        external_signature,
        signatures,
        extra_data,
    ))
}

/// Computes key generation metadata for compressed keygen.
/// This is similar to compute_info_standard_keygen but for CompressedXofKeySet.
#[expect(clippy::too_many_arguments)]
pub(crate) fn compute_info_compressed_keygen(
    sk: &PrivateSigKey,
    schemes: &[SigningSchemeType],
    domain_separator: &DomainSep,
    prep_id: &RequestId,
    key_id: &RequestId,
    compressed_keyset: &CompressedXofKeySet,
    compact_public_key: &tfhe::CompactPublicKey,
    domain: &alloy_sol_types::Eip712Domain,
    extra_data: Vec<u8>,
) -> anyhow::Result<KeyGenMetadata> {
    let compressed_keyset_digest = hash_versioned(domain_separator, compressed_keyset)?;
    let public_key_digest = hash_versioned(domain_separator, compact_public_key)?;
    compute_info_compressed_keygen_from_digests(
        sk,
        schemes,
        prep_id,
        key_id,
        compressed_keyset_digest,
        public_key_digest,
        domain,
        extra_data,
    )
}

/// Sign a compressed keygen using precomputed digests.
#[expect(clippy::too_many_arguments)]
pub(crate) fn compute_info_compressed_keygen_from_digests(
    sk: &PrivateSigKey,
    schemes: &[SigningSchemeType],
    prep_id: &RequestId,
    key_id: &RequestId,
    compressed_keyset_digest: Vec<u8>,
    public_key_digest: Vec<u8>,
    domain: &alloy_sol_types::Eip712Domain,
    extra_data: Vec<u8>,
) -> anyhow::Result<KeyGenMetadata> {
    tracing::debug!(
        "Computed xof keyset digest: {} and public key digest: {}",
        hex::encode(&compressed_keyset_digest),
        hex::encode(&public_key_digest),
    );

    let sol_type = KeygenVerification::new_compressed(
        prep_id,
        key_id,
        compressed_keyset_digest.clone(),
        public_key_digest.clone(),
        extra_data.clone(),
    );
    let key_digests = BTreeMap::from([
        (PubDataType::CompressedXofKeySet, compressed_keyset_digest),
        (PubDataType::PublicKey, public_key_digest),
    ]);
    let payload_bytes = keygen_payload_bytes(prep_id, key_id, &key_digests, &extra_data)?;
    let (external_signature, signatures) = sign_result(
        sk,
        schemes,
        &payload_bytes,
        &sol_type,
        domain,
        &DSEP_PUBDATA_KEY,
    )?;

    Ok(KeyGenMetadata::new(
        *key_id,
        *prep_id,
        key_digests,
        domain,
        external_signature,
        signatures,
        extra_data,
    ))
}

/// Computes a unique handle for an element using its hash digest.
///
/// # Process
/// 1. Hashes the element with domain separation
/// 2. Truncates the hash
/// 3. Converts to hex string
///
/// # Returns
/// - `Ok(String)` with hex-encoded handle
/// - `Err` if hashing fails
pub fn compute_handle<S>(element: &S) -> anyhow::Result<String>
where
    S: Serialize + Versionize + Named,
{
    let mut digest = hash_versioned(&DSEP_HANDLE, element)?;
    // Truncate and convert to hex
    digest.truncate(ID_LENGTH);
    Ok(hex::encode(digest))
}

macro_rules! deserialize_to_low_level_helper {
    ($rust_type:ty,$ct_format:expr,$serialized_high_level:expr,$decompression_key:expr) => {{
        match $ct_format {
            CiphertextFormat::SmallCompressed => {
                let hl_ct: $rust_type =
                    decompression::tfhe_safe_deserialize_and_uncompress::<$rust_type>(
                        $decompression_key
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("missing decompression key"))?,
                        $serialized_high_level,
                    )?;
                let (radix_ct, _id, _tag, _rerand_metadata) = hl_ct.into_raw_parts();
                LowLevelCiphertext::Small(RadixOrBoolCiphertext::Radix(radix_ct))
            }
            CiphertextFormat::SmallExpanded => {
                let hl_ct: $rust_type =
                    decompression::tfhe_safe_deserialize::<$rust_type>($serialized_high_level)?;
                let (radix_ct, _id, _tag, _rerand_metadata) = hl_ct.into_raw_parts();
                LowLevelCiphertext::Small(RadixOrBoolCiphertext::Radix(radix_ct))
            }
            CiphertextFormat::BigCompressed => {
                let ct_list = safe_deserialize::<tfhe::CompressedSquashedNoiseCiphertextList>(
                    std::io::Cursor::new($serialized_high_level),
                    SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let ct: tfhe::SquashedNoiseFheUint = ct_list.get(0)?.ok_or_else(|| {
                    anyhow::anyhow!("expected at least one ciphertext in the compressed list")
                })?;
                let radix_ct = ct.underlying_squashed_noise_ciphertext().clone();
                LowLevelCiphertext::BigCompressed(SnsRadixOrBoolCiphertext::Radix(radix_ct))
            }
            CiphertextFormat::BigExpanded => {
                let r = safe_deserialize::<tfhe::SquashedNoiseFheUint>(
                    std::io::Cursor::new($serialized_high_level),
                    SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let radix_ct = r.underlying_squashed_noise_ciphertext().clone();
                LowLevelCiphertext::BigStandard(SnsRadixOrBoolCiphertext::Radix(radix_ct))
            }
        }
    }};
}

pub fn deserialize_to_low_level(
    fhe_type: FheTypes,
    ct_format: CiphertextFormat,
    serialized_high_level: &[u8],
    decompression_key: Option<&DecompressionKey>,
) -> anyhow::Result<LowLevelCiphertext> {
    let radix_ct = match fhe_type {
        FheTypes::Bool => match ct_format {
            CiphertextFormat::SmallCompressed => {
                let hl_ct: FheBool = decompression::tfhe_safe_deserialize_and_uncompress::<FheBool>(
                    decompression_key
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("missing decompression key"))?,
                    serialized_high_level,
                )?;
                let radix_ct = hl_ct.into_raw_parts();
                LowLevelCiphertext::Small(RadixOrBoolCiphertext::Bool(BooleanBlock::new_unchecked(
                    radix_ct,
                )))
            }
            CiphertextFormat::SmallExpanded => {
                let hl_ct: FheBool =
                    decompression::tfhe_safe_deserialize::<FheBool>(serialized_high_level)?;
                let radix_ct = hl_ct.into_raw_parts();
                LowLevelCiphertext::Small(RadixOrBoolCiphertext::Bool(BooleanBlock::new_unchecked(
                    radix_ct,
                )))
            }
            CiphertextFormat::BigCompressed => {
                let ct_list = safe_deserialize::<tfhe::CompressedSquashedNoiseCiphertextList>(
                    std::io::Cursor::new(serialized_high_level),
                    SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let ct: tfhe::SquashedNoiseFheBool = ct_list.get(0)?.ok_or_else(|| {
                    anyhow::anyhow!("expected at least one ciphertext in the compressed list")
                })?;
                let radix_ct = ct.underlying_squashed_noise_ciphertext().clone();
                LowLevelCiphertext::BigCompressed(SnsRadixOrBoolCiphertext::Bool(radix_ct))
            }
            CiphertextFormat::BigExpanded => {
                let r = safe_deserialize::<tfhe::SquashedNoiseFheBool>(
                    std::io::Cursor::new(serialized_high_level),
                    SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let radix_ct = r.underlying_squashed_noise_ciphertext().clone();
                LowLevelCiphertext::BigStandard(SnsRadixOrBoolCiphertext::Bool(radix_ct))
            }
        },
        FheTypes::Uint4 => {
            deserialize_to_low_level_helper!(
                FheUint4,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint8 => {
            deserialize_to_low_level_helper!(
                FheUint8,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint16 => {
            deserialize_to_low_level_helper!(
                FheUint16,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint32 => {
            deserialize_to_low_level_helper!(
                FheUint32,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint64 => {
            deserialize_to_low_level_helper!(
                FheUint64,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint80 => {
            deserialize_to_low_level_helper!(
                FheUint80,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint128 => {
            deserialize_to_low_level_helper!(
                FheUint128,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint160 => {
            deserialize_to_low_level_helper!(
                FheUint160,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint256 => {
            deserialize_to_low_level_helper!(
                FheUint256,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint512 => {
            deserialize_to_low_level_helper!(
                FheUint512,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint1024 => {
            deserialize_to_low_level_helper!(
                FheUint1024,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint2048 => {
            deserialize_to_low_level_helper!(
                FheUint2048,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        unsupported_fhe_type => {
            anyhow::bail!("Unsupported fhe_type: {:?}", unsupported_fhe_type);
        }
    };
    Ok(radix_ct)
}

/// Sign a public decryption result under every requested scheme.
pub(crate) fn sign_public_decryption_result(
    server_sk: &PrivateSigKey,
    schemes: &[SigningSchemeType],
    payload: PublicDecryptionResponsePayload,
    ext_handles_bytes: &[Vec<u8>],
    extra_data: Vec<u8>,
    eip712_domain: &Eip712Domain,
) -> anyhow::Result<PubDecCallValues> {
    tracing::info!(
        "Signing public decryption result for {} plaintexts and {} external handles",
        payload.plaintexts.len(),
        ext_handles_bytes.len()
    );
    let sol_type =
        compute_public_decryption_message(ext_handles_bytes, &payload.plaintexts, &extra_data)?;
    sign_decryption_result(
        server_sk,
        schemes,
        payload,
        extra_data,
        &sol_type,
        eip712_domain,
        &crate::engine::validation::DSEP_PUBLIC_DECRYPTION,
    )
}

/// Sign a user decryption result under every requested scheme.
pub(crate) fn sign_user_decryption_result(
    server_sk: &PrivateSigKey,
    schemes: &[SigningSchemeType],
    payload: UserDecryptionResponsePayload,
    user_pk_buf: &[u8],
    extra_data: Vec<u8>,
    eip712_domain: &Eip712Domain,
) -> anyhow::Result<UserDecryptCallValues> {
    tracing::debug!("Signing UserDecryptResponseVerification");
    let sol_type =
        crate::cryptography::compute_user_decrypt_message(&payload, user_pk_buf, &extra_data)?;
    sign_decryption_result(
        server_sk,
        schemes,
        payload,
        extra_data,
        &sol_type,
        eip712_domain,
        &crate::engine::validation::DSEP_USER_DECRYPTION,
    )
}

/// Shared body of [`sign_public_decryption_result`] and
/// [`sign_user_decryption_result`].
///
/// Adds the deprecated scalar `signature` to what [`sign_result`] produces. The
/// payload bytes are `bc2wrap::serialize` rather than [`signed_payload_bytes`]
/// because that scalar signature covers exactly these bytes and they are part of
/// the released wire contract. TODO(0.16): once the deprecated fields are gone,
/// this can use [`signed_payload_bytes`] like every other result.
fn sign_decryption_result<P: Serialize, D: SolStruct>(
    server_sk: &PrivateSigKey,
    schemes: &[SigningSchemeType],
    payload: P,
    extra_data: Vec<u8>,
    sol_type: &D,
    eip712_domain: &Eip712Domain,
    dsep: &DomainSep,
) -> anyhow::Result<DecryptionCallValues<P>> {
    let payload_bytes = bc2wrap::serialize(&payload)?;
    let signature = internal_sign(dsep, &payload_bytes, server_sk)?.to_bytes();
    let (external_signature, stored) = sign_result(
        server_sk,
        schemes,
        &payload_bytes,
        sol_type,
        eip712_domain,
        dsep,
    )?;
    Ok(DecryptionCallValues {
        payload,
        signature,
        external_signature,
        extra_data,
        signatures: stored_scheme_signatures_to_proto(&stored),
    })
}

pub struct BaseKmsStruct {
    kms_type: KMSType,
    sig_key: Option<Arc<PrivateSigKey>>,
    verf_key: Arc<PublicSigKey>,
    rng: Arc<Mutex<AesRng>>,
}

impl BaseKmsStruct {
    pub fn new(kms_type: KMSType, sig_key: PrivateSigKey) -> anyhow::Result<Self> {
        Ok(BaseKmsStruct {
            kms_type,
            verf_key: Arc::new(sig_key.verf_key()),
            sig_key: Some(Arc::new(sig_key)),
            rng: Arc::new(Mutex::new(AesRng::from_entropy())),
        })
    }

    pub fn new_no_signing_key(kms_type: KMSType, verf_key: PublicSigKey) -> Self {
        tracing::warn!(
            "Initializing KMS without a signing key. ONLY BACKUP RECOVERY OPERATIONS WILL BE POSSIBLE."
        );
        BaseKmsStruct {
            kms_type,
            sig_key: None,
            verf_key: Arc::new(verf_key),
            rng: Arc::new(Mutex::new(AesRng::from_entropy())),
        }
    }

    pub fn kms_type(&self) -> KMSType {
        self.kms_type
    }

    pub fn sig_key(&self) -> anyhow::Result<Arc<PrivateSigKey>> {
        match &self.sig_key {
            Some(sk) => Ok(Arc::clone(sk)),
            None => anyhow::bail!("No signing key available"),
        }
    }

    pub fn verf_key(&self) -> Arc<PublicSigKey> {
        Arc::clone(&self.verf_key)
    }

    /// Make a clone of this struct with a newly initialized RNG s.t. that both the new and old struct are safe to use.
    pub async fn new_instance(&self) -> Self {
        let sig_key = match &self.sig_key {
            Some(sk) => Some(Arc::clone(sk)),
            None => None,
        };
        Self {
            kms_type: self.kms_type,
            verf_key: Arc::clone(&self.verf_key),
            sig_key,
            rng: Arc::new(Mutex::new(self.new_rng().await)),
        }
    }

    pub async fn new_rng(&self) -> AesRng {
        let mut seed = [0u8; crate::consts::RND_SIZE];
        // Make a seperate scope for the rng so that it is dropped before the lock is released
        {
            let mut base_rng = self.rng.lock().await;
            base_rng.fill_bytes(seed.as_mut());
        }
        AesRng::from_seed(seed)
    }
}

impl BaseKms for BaseKmsStruct {
    /// sign `msg` using the KMS' private signing key
    fn sign<T>(&self, dsep: &DomainSep, msg: &T) -> anyhow::Result<Signature>
    where
        T: Serialize + AsRef<[u8]>,
    {
        match self.sig_key.as_ref() {
            None => anyhow::bail!("KMS has no signing key"),
            Some(sk) => internal_sign(dsep, msg, sk),
        }
    }

    fn digest<T>(domain_separator: &DomainSep, msg: &T) -> anyhow::Result<Vec<u8>>
    where
        T: ?Sized + AsRef<[u8]>,
    {
        Ok(hash_element(domain_separator, msg))
    }
}

/// ABI encodes a list of typed plaintexts into a single byte vector for Ethereum compatibility.
/// This follows the encoding pattern used in the JavaScript version for decrypted results and also supports `ebytes`.
/// This function is NOT compatible with fhevm v0.9.0 and is only intended for future use with fhevm supporting `ebytes`.
pub fn abi_encode_plaintexts_ebytes(ptxts: &[TypedPlaintext]) -> Bytes {
    let mut results: Vec<DynSolValue> = Vec::new();
    results.push(DynSolValue::Uint(U256::from(42), 256)); // requestID placeholder

    for clear_text in ptxts.iter() {
        if let Ok(fhe_type) = clear_text.fhe_type() {
            match fhe_type {
                FheTypes::Uint512 => {
                    if clear_text.bytes.len() != 64 {
                        error!(
                            "Invalid length for Euint512: expected 64, got {}",
                            clear_text.bytes.len()
                        );
                        results.push(DynSolValue::Bytes(vec![0u8; 64]));
                    } else {
                        let arr: [u8; 64] = match clear_text.bytes.as_slice().try_into() {
                            Ok(arr) => arr,
                            Err(e) => {
                                error!("Failed to convert bytes to array for Euint512: {}", e);
                                [0u8; 64]
                            }
                        };
                        let value = Uint::<512, 8>::from_le_bytes(arr);
                        let bytes: [u8; 64] = value.to_be_bytes();
                        results.push(DynSolValue::Bytes(bytes.to_vec()));
                    }
                }
                FheTypes::Uint1024 => {
                    if clear_text.bytes.len() != 128 {
                        error!(
                            "Invalid length for Euint1024: expected 128, got {}",
                            clear_text.bytes.len()
                        );
                        results.push(DynSolValue::Bytes(vec![0u8; 128]));
                    } else {
                        let arr: [u8; 128] = match clear_text.bytes.as_slice().try_into() {
                            Ok(arr) => arr,
                            Err(e) => {
                                error!("Failed to convert bytes to array for Euint1024: {}", e);
                                [0u8; 128]
                            }
                        };
                        let value = Uint::<1024, 16>::from_le_bytes(arr);
                        let bytes: [u8; 128] = value.to_be_bytes();
                        results.push(DynSolValue::Bytes(bytes.to_vec()));
                    }
                }
                FheTypes::Uint2048 => {
                    if clear_text.bytes.len() != 256 {
                        error!(
                            "Invalid length for Euint2048: expected 256, got {}",
                            clear_text.bytes.len()
                        );
                        results.push(DynSolValue::Bytes(vec![0u8; 256]));
                    } else {
                        let arr: [u8; 256] = match clear_text.bytes.as_slice().try_into() {
                            Ok(arr) => arr,
                            Err(e) => {
                                error!("Failed to convert bytes to array for Euint2048: {}", e);
                                [0u8; 256]
                            }
                        };
                        let value = Uint::<2048, 32>::from_le_bytes(arr);
                        let bytes: [u8; 256] = value.to_be_bytes();
                        results.push(DynSolValue::Bytes(bytes.to_vec()));
                    }
                }
                _ => {
                    // For other types, convert to U256
                    if clear_text.bytes.len() > 32 {
                        error!(
                            "Byte length too large for U256: got {}, max is 32",
                            clear_text.bytes.len()
                        );
                        results.push(DynSolValue::Uint(U256::from(0), 256));
                    } else {
                        // Pad the bytes to 32 bytes for U256 (assuming little-endian input)
                        let mut padded = [0u8; 32];
                        padded[..clear_text.bytes.len()].copy_from_slice(&clear_text.bytes);
                        let value = U256::from_le_bytes(padded);
                        results.push(DynSolValue::Uint(value, 256));
                    }
                }
            }
        }
    }

    results.push(DynSolValue::Array(vec![])); // signatures placeholder

    let data = DynSolValue::Tuple(results).abi_encode_params();
    let decrypted_result = data[32..data.len() - 32].to_vec(); // remove placeholder corresponding to requestID and signatures
    Bytes::from(decrypted_result)
}

pub fn compute_public_decryption_message(
    ext_handles_bytes: &[Vec<u8>],
    pts: &[TypedPlaintext],
    extra_data: &[u8],
) -> anyhow::Result<PublicDecryptVerification> {
    // convert external_handles back to U256 to be signed
    let external_handles_bytes32: Vec<_> = ext_handles_bytes
        .iter()
        .enumerate()
        .map(|(idx, h)| {
            if h.as_slice().len() > 32 {
                anyhow::bail!(
                    "external_handle at index {idx} too long: {} bytes (max 32)",
                    h.as_slice().len()
                );
            }
            Ok(FixedBytes::<32>::left_padding_from(h.as_slice()))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let pt_bytes = abi_encode_plaintexts(pts)?;

    tracing::info!(
        "Computed PublicDecryptVerification for handles {:?} with extra_data \"{}\".",
        external_handles_bytes32,
        hex::encode(extra_data)
    );

    // the solidity structure to sign with EIP-712
    Ok(PublicDecryptVerification {
        ctHandles: external_handles_bytes32.clone(),
        decryptedResult: pt_bytes.clone(),
        extraData: extra_data.to_vec().into(),
    })
}

/// Attempt to find the concrete parameters from an enum variant defined by
/// [kms_grpc::kms::v1::FheParameter].
///
/// Since this function is normally used by the grpc service, we return the error code
/// InvalidArgument if the concrete parameter does not exist.
/// The default DKG parameters are returned if None is provided.
pub(crate) fn retrieve_parameters(fhe_parameter: Option<i32>) -> Result<DKGParams, BoxedStatus> {
    let params = match fhe_parameter {
        Some(inner) => {
            let fhe_parameter: WrappedDKGParams = FheParameter::try_from(inner)
                .map_err(|e| {
                    tonic::Status::invalid_argument(format!("DKG parameter not found: {e}"))
                })?
                .into();
            *fhe_parameter
        }
        None => *WrappedDKGParams::from(FheParameter::default()),
    };
    // Validate the KMS-level invariants at the parameter-entry boundary so a
    // malformed parameter set fails fast here with a clear error, instead of
    // panicking deep inside an accessor (e.g. `classic_pbs`) later on.
    params
        .check_conformance()
        .map_err(|e| tonic::Status::invalid_argument(format!("Invalid DKG parameters: {e}")))?;
    Ok(params)
}

/// Version dispatch for [`StoredEip712Domain`].
#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum StoredEip712DomainVersions {
    /// Initial canonical domain representation.
    V0(StoredEip712Domain),
}

/// Canonical persisted representation of an EIP-712 domain.
///
/// Alloy and protobuf domain types are kept out of persisted metadata so dependency or wire
/// representation changes cannot silently alter the on-disk format.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(StoredEip712DomainVersions)]
pub struct StoredEip712Domain {
    name: Option<String>,
    version: Option<String>,
    chain_id: Option<[u8; 32]>,
    verifying_contract: Option<[u8; 20]>,
    salt: Option<[u8; 32]>,
}

impl From<&Eip712Domain> for StoredEip712Domain {
    fn from(domain: &Eip712Domain) -> Self {
        Self {
            name: domain.name.as_ref().map(ToString::to_string),
            version: domain.version.as_ref().map(ToString::to_string),
            chain_id: domain.chain_id.map(|chain_id| chain_id.to_be_bytes()),
            verifying_contract: domain
                .verifying_contract
                .map(alloy_primitives::Address::into_array),
            salt: domain.salt.map(|salt| salt.0),
        }
    }
}

impl From<&StoredEip712Domain> for Eip712Domain {
    fn from(domain: &StoredEip712Domain) -> Self {
        Eip712Domain::new(
            domain.name.clone().map(Into::into),
            domain.version.clone().map(Into::into),
            domain.chain_id.map(U256::from_be_bytes),
            domain.verifying_contract.map(Address::from),
            domain.salt.map(B256::from),
        )
    }
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum KeyGenMetadataInnerVersions {
    V0(KeyGenMetadataInnerV0),
    V1(KeyGenMetadataInnerV1),
    V2(KeyGenMetadataInnerV2),
    V3(KeyGenMetadataInnerV3),
    V4(KeyGenMetadataInner),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(KeyGenMetadataInnerVersions)]
pub struct KeyGenMetadataInner {
    pub key_id: RequestId,
    pub preprocessing_id: RequestId,
    pub key_digest_map: BTreeMap<PubDataType, Vec<u8>>,
    pub extra_data: Option<Vec<u8>>,
    pub eip712_domain: Option<StoredEip712Domain>,
    pub external_signature: Vec<u8>,
    pub signatures: Vec<StoredTypedSignature>,
}

#[derive(Clone, Serialize, Deserialize, Version)]
pub struct KeyGenMetadataInnerV3 {
    pub key_id: RequestId,
    pub preprocessing_id: RequestId,
    pub key_digest_map: BTreeMap<PubDataType, Vec<u8>>,
    pub extra_data: Option<Vec<u8>>,
    pub external_signature: Vec<u8>,
    pub signatures: Vec<StoredTypedSignature>,
}

#[derive(Clone, Serialize, Deserialize, Version)]
pub struct KeyGenMetadataInnerV2 {
    pub key_id: RequestId,
    pub preprocessing_id: RequestId,
    pub key_digest_map: BTreeMap<PubDataType, Vec<u8>>,
    pub extra_data: Option<Vec<u8>>,
    pub external_signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Version)]
pub struct KeyGenMetadataInnerV1 {
    pub key_id: RequestId,
    pub preprocessing_id: RequestId,
    pub key_digest_map: HashMap<PubDataType, Vec<u8>>,
    pub extra_data: Option<Vec<u8>>,
    pub external_signature: Vec<u8>,
}

impl Upgrade<KeyGenMetadataInnerV1> for KeyGenMetadataInnerV0 {
    type Error = std::convert::Infallible;

    fn upgrade(self) -> Result<KeyGenMetadataInnerV1, Self::Error> {
        Ok(KeyGenMetadataInnerV1 {
            key_id: self.key_id,
            preprocessing_id: self.preprocessing_id,
            key_digest_map: self.key_digest_map,
            external_signature: self.external_signature,
            extra_data: None, // extra_data was not present in the Q126 version, so we set it to None
        })
    }
}

impl Upgrade<KeyGenMetadataInnerV2> for KeyGenMetadataInnerV1 {
    type Error = std::convert::Infallible;

    fn upgrade(self) -> Result<KeyGenMetadataInnerV2, Self::Error> {
        Ok(KeyGenMetadataInnerV2 {
            key_id: self.key_id,
            preprocessing_id: self.preprocessing_id,
            key_digest_map: self.key_digest_map.into_iter().collect(),
            extra_data: self.extra_data,
            external_signature: self.external_signature,
        })
    }
}

impl Upgrade<KeyGenMetadataInnerV3> for KeyGenMetadataInnerV2 {
    type Error = std::convert::Infallible;

    fn upgrade(self) -> Result<KeyGenMetadataInnerV3, Self::Error> {
        Ok(KeyGenMetadataInnerV3 {
            key_id: self.key_id,
            preprocessing_id: self.preprocessing_id,
            key_digest_map: self.key_digest_map,
            extra_data: self.extra_data,
            // The ECDSA/EIP-712 signature is preserved in `external_signature`;
            // `signatures` is an opt-in per-scheme, so stays empty here.
            external_signature: self.external_signature,
            signatures: Vec::new(),
        })
    }
}

impl Upgrade<KeyGenMetadataInner> for KeyGenMetadataInnerV3 {
    type Error = std::convert::Infallible;

    fn upgrade(self) -> Result<KeyGenMetadataInner, Self::Error> {
        Ok(KeyGenMetadataInner {
            key_id: self.key_id,
            preprocessing_id: self.preprocessing_id,
            key_digest_map: self.key_digest_map,
            extra_data: self.extra_data,
            eip712_domain: None,
            external_signature: self.external_signature,
            signatures: self.signatures,
        })
    }
}

/// Previously called KeyGenMetadataInnerQ126 - quater 1, 2026
#[derive(Clone, Serialize, Deserialize, Version)]
pub struct KeyGenMetadataInnerV0 {
    pub key_id: RequestId,
    pub preprocessing_id: RequestId,
    pub key_digest_map: HashMap<PubDataType, Vec<u8>>,
    pub external_signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum KeyGenMetadataVersions {
    V0(KeyGenMetadata),
}

// Values that need to be stored temporarily as part of an async key generation call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(KeyGenMetadataVersions)]
#[expect(clippy::large_enum_variant)]
pub enum KeyGenMetadata {
    Current(KeyGenMetadataInner),
    LegacyV0(HashMap<PubDataType, SignedPubDataHandleInternal>),
}

impl Named for KeyGenMetadata {
    /// Returns the type name for versioning and serialization
    const NAME: &'static str = "KeyGenMetadata";
}

impl KeyGenMetadata {
    /// Create a new KeyGenMetadata instance with the provided parameters and EIP-712 domain.
    pub fn new(
        key_id: RequestId,
        preprocessing_id: RequestId,
        key_digest_map: BTreeMap<PubDataType, Vec<u8>>,
        eip712_domain: &Eip712Domain,
        external_signature: Vec<u8>,
        signatures: Vec<StoredTypedSignature>,
        extra_data: Vec<u8>,
    ) -> Self {
        let parsed_extra_data = if extra_data.is_empty() {
            None
        } else {
            Some(extra_data)
        };
        KeyGenMetadata::Current(KeyGenMetadataInner {
            key_id,
            preprocessing_id,
            key_digest_map,
            eip712_domain: Some(eip712_domain.into()),
            external_signature,
            signatures,
            extra_data: parsed_extra_data,
        })
    }

    /// The preprocessing ID that was signed and stored when the key was generated.
    ///
    /// Returns `None` for [`KeyGenMetadata::LegacyV0`].
    pub fn preprocessing_id(&self) -> Option<&RequestId> {
        match self {
            KeyGenMetadata::Current(inner) => Some(&inner.preprocessing_id),
            KeyGenMetadata::LegacyV0(_inner) => None,
        }
    }

    #[cfg(test)]
    pub fn external_signature(&self) -> &[u8] {
        match self {
            KeyGenMetadata::Current(inner) => &inner.external_signature,
            KeyGenMetadata::LegacyV0(_inner) => {
                // we cannot return a single external signature because there might be multiple
                &[]
            }
        }
    }

    /// Returns the set of public data types that are present in this metadata.
    pub fn pub_data_types(&self) -> HashSet<PubDataType> {
        match self {
            KeyGenMetadata::Current(key_gen_metadata_inner) => key_gen_metadata_inner
                .key_digest_map
                .keys()
                .cloned()
                .collect(),
            KeyGenMetadata::LegacyV0(hash_map) => hash_map.keys().cloned().collect(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum CrsGenMetadataInnerVersions {
    V0(CrsGenMetadataInnerV0),
    V1(CrsGenMetadataInnerV1),
    V2(CrsGenMetadataInnerV2),
    V3(CrsGenMetadataInner),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(CrsGenMetadataInnerVersions)]
pub struct CrsGenMetadataInner {
    pub(crate) crs_id: RequestId,
    pub(crate) crs_digest: Vec<u8>,
    pub(crate) max_num_bits: u32,
    pub(crate) extra_data: Option<Vec<u8>>,
    pub(crate) eip712_domain: Option<StoredEip712Domain>,
    pub(crate) external_signature: Vec<u8>,
    pub(crate) signatures: Vec<StoredTypedSignature>,
}

#[derive(Clone, Serialize, Deserialize, Version)]
/// Previous current CRS metadata layout, before retaining the EIP-712 domain.
pub struct CrsGenMetadataInnerV2 {
    pub crs_id: RequestId,
    pub crs_digest: Vec<u8>,
    pub max_num_bits: u32,
    pub extra_data: Option<Vec<u8>>,
    pub external_signature: Vec<u8>,
    pub signatures: Vec<StoredTypedSignature>,
}

#[derive(Clone, Serialize, Deserialize, Version)]
pub struct CrsGenMetadataInnerV1 {
    pub crs_id: RequestId,
    pub crs_digest: Vec<u8>,
    pub max_num_bits: u32,
    pub extra_data: Option<Vec<u8>>,
    pub external_signature: Vec<u8>,
}

impl Upgrade<CrsGenMetadataInnerV1> for CrsGenMetadataInnerV0 {
    type Error = std::convert::Infallible;

    fn upgrade(self) -> Result<CrsGenMetadataInnerV1, Self::Error> {
        Ok(CrsGenMetadataInnerV1 {
            crs_id: self.crs_id,
            crs_digest: self.crs_digest,
            max_num_bits: self.max_num_bits,
            extra_data: None, // extra_data was not present in the Q126 version, so we set it to None
            external_signature: self.external_signature,
        })
    }
}

impl Upgrade<CrsGenMetadataInnerV2> for CrsGenMetadataInnerV1 {
    type Error = std::convert::Infallible;

    fn upgrade(self) -> Result<CrsGenMetadataInnerV2, Self::Error> {
        Ok(CrsGenMetadataInnerV2 {
            crs_id: self.crs_id,
            crs_digest: self.crs_digest,
            max_num_bits: self.max_num_bits,
            extra_data: self.extra_data,
            // The ECDSA/EIP-712 signature is preserved in `external_signature`;
            // `signatures` is an opt-in per-scheme set that pre-#3078 data never
            // populated, so it upgrades to empty.
            external_signature: self.external_signature,
            signatures: Vec::new(),
        })
    }
}

impl Upgrade<CrsGenMetadataInner> for CrsGenMetadataInnerV2 {
    type Error = std::convert::Infallible;

    fn upgrade(self) -> Result<CrsGenMetadataInner, Self::Error> {
        Ok(CrsGenMetadataInner {
            crs_id: self.crs_id,
            crs_digest: self.crs_digest,
            max_num_bits: self.max_num_bits,
            extra_data: self.extra_data,
            eip712_domain: None,
            external_signature: self.external_signature,
            signatures: self.signatures,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, Version)]
pub struct CrsGenMetadataInnerV0 {
    pub crs_id: RequestId,
    pub crs_digest: Vec<u8>,
    pub max_num_bits: u32,
    pub external_signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
#[expect(clippy::large_enum_variant)]
pub enum CrsGenMetadataVersions {
    V0(CrsGenMetadataV0),
    V1(CrsGenMetadata),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(CrsGenMetadataVersions)]
#[expect(clippy::large_enum_variant)]
pub enum CrsGenMetadata {
    Current(CrsGenMetadataInner),
    LegacyV0(SignedPubDataHandleInternal),
}

impl Upgrade<CrsGenMetadata> for CrsGenMetadataV0 {
    type Error = std::convert::Infallible;
    fn upgrade(self) -> Result<CrsGenMetadata, Self::Error> {
        Ok(CrsGenMetadata::LegacyV0(self.0))
    }
}

impl CrsGenMetadata {
    /// Create a new CRS metadata value with the provided EIP-712 domain.
    pub fn new(
        crs_id: RequestId,
        crs_digest: Vec<u8>,
        max_num_bits: u32,
        eip712_domain: &Eip712Domain,
        external_signature: Vec<u8>,
        signatures: Vec<StoredTypedSignature>,
        extra_data: Vec<u8>,
    ) -> Self {
        let parsed_extra_data = if extra_data.is_empty() {
            None
        } else {
            Some(extra_data)
        };
        CrsGenMetadata::Current(CrsGenMetadataInner {
            crs_id,
            crs_digest,
            max_num_bits,
            extra_data: parsed_extra_data,
            eip712_domain: Some(eip712_domain.into()),
            external_signature,
            signatures,
        })
    }

    pub fn digest(&self) -> &[u8] {
        match self {
            CrsGenMetadata::Current(inner) => &inner.crs_digest,
            CrsGenMetadata::LegacyV0(_inner) => &[],
        }
    }

    #[cfg(test)]
    pub fn external_signature(&self) -> &[u8] {
        match self {
            CrsGenMetadata::Current(inner) => &inner.external_signature,
            CrsGenMetadata::LegacyV0(_) => &[],
        }
    }
}

impl Named for CrsGenMetadata {
    /// Returns the type name for versioning and serialization
    const NAME: &'static str = "CrsGenMetadata";
}

/// A finished decryption response, stored while the async decryption call is in
/// flight.
#[derive(Clone)]
pub struct DecryptionCallValues<P> {
    /// The response payload, exactly as it was signed.
    pub payload: P,
    /// The raw internal ECDSA signature over the serialized payload.
    /// Deprecated, to be removed in 0.16 TODO(0.16)
    pub signature: Vec<u8>,
    /// The ECDSA/EIP-712 signature for the external (on-chain) recipient.
    /// Deprecated, to be removed in 0.16 TODO(0.16): superseded by the ECDSA
    /// entry of `signatures`, which holds the same bytes.
    pub external_signature: Vec<u8>,
    /// The extra data the request carried, echoed back in the response.
    pub extra_data: Vec<u8>,
    /// One signature per scheme the request asked for.
    pub signatures: Vec<TypedSignature>,
}

/// The finished public decryption response; see [`DecryptionCallValues`].
pub type PubDecCallValues = DecryptionCallValues<PublicDecryptionResponsePayload>;

/// The finished user decryption response; see [`DecryptionCallValues`].
pub type UserDecryptCallValues = DecryptionCallValues<UserDecryptionResponsePayload>;

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        CrsGenMetadata, CrsGenMetadataInner, CrsGenMetadataInnerV0, KeyGenMetadata,
        KeyGenMetadataInner, KeyGenMetadataInnerV0, KeyGenMetadataInnerV1, StoredEip712Domain,
    };
    use super::{TypedPlaintext, deserialize_to_low_level};
    use crate::cryptography::signatures::compute_eip712_signature;
    use crate::cryptography::signatures::internal_sign;
    use crate::cryptography::signing::{Signature, SigningSchemeType, unified_verify};
    use crate::{
        consts::{SAFE_SER_SIZE_LIMIT, TEST_PARAM},
        cryptography::signatures::{gen_sig_keys, recover_address_from_ext_signature},
        dummy_domain,
        engine::{
            base::{
                DSEP_PUBDATA_CRS, DSEP_PUBDATA_KEY, compute_info_uncompressed_keygen,
                compute_preprocessing_signatures, compute_public_decryption_message,
                hash_versioned,
            },
            centralized::central_kms::{
                gen_centralized_crs, generate_client_fhe_key, generate_uncompressed_fhe_keys,
            },
        },
        util::key_setup::FhePublicKey,
    };
    use aes_prng::AesRng;
    use alloy_sol_types::SolStruct;
    use kms_grpc::rpc_types::PubDataType;
    use kms_grpc::solidity_types::{CrsgenVerificationQ126, KeygenVerificationQ126};
    use kms_grpc::{
        RequestId,
        kms::v1::CiphertextFormat,
        solidity_types::{CrsgenVerification, KeygenVerification, PrepKeygenVerification},
    };
    use rand::{RngCore, SeedableRng};
    use std::collections::BTreeMap;
    use std::collections::HashMap;
    use tfhe::{
        FheTypes, FheUint32, Seed, prelude::SquashNoise, safe_serialization::safe_serialize,
    };
    use tfhe_versionable::{Unversionize, Upgrade, VersionizeOwned};
    use threshold_execution::{
        keyset_config::StandardKeySetConfig,
        tfhe_internals::{public_keysets::FhePubKeySet, utils::expanded_encrypt},
    };

    #[test]
    fn stored_eip712_domain_roundtrip_preserves_all_fields() {
        let domain = alloy_sol_types::Eip712Domain::new(
            Some("KMS domain".to_owned().into()),
            Some("42".to_owned().into()),
            Some(alloy_primitives::U256::from(8006)),
            Some(alloy_primitives::address!(
                "66f9664f97F2b50F62D13eA064982f936dE76657"
            )),
            Some(alloy_primitives::B256::from([0xA5; 32])),
        );
        let stored = StoredEip712Domain::from(&domain);
        let versioned = stored.clone().versionize_owned();
        let bytes = bc2wrap::serialize(&versioned).unwrap();
        let decoded_versioned: <StoredEip712Domain as VersionizeOwned>::VersionedOwned =
            bc2wrap::deserialize_slice(&bytes).unwrap();
        let decoded = StoredEip712Domain::unversionize(decoded_versioned).unwrap();

        assert_eq!(decoded, stored);
        assert_eq!(alloy_sol_types::Eip712Domain::from(&decoded), domain);
    }

    /// Round-trip test for every signature on a decryption response, as the
    /// async decryption job produces them:
    /// - the deprecated scalar `signature` is the raw signature over the payload,
    /// - `external_signature` is the EIP-712 signature the fhevm contracts verify,
    /// - the ECDSA entry of `signatures` is byte-identical to `external_signature`,
    /// - every other scheme signs the raw payload.
    ///
    /// The split is deliberate — EIP-712 is an EVM/secp256k1 construction, so
    /// post-quantum schemes are not bound to it.
    /// TODO(0.16): remove the deprecated fields and unify the ECDSA entry of `signatures` with `external_signature`.
    #[test]
    fn decryption_scheme_signatures_round_trip() {
        use crate::engine::validation::DSEP_PUBLIC_DECRYPTION;
        use kms_grpc::kms::v1::PublicDecryptionResponsePayload;

        let mut rng = AesRng::seed_from_u64(0xABCD);
        let (pk, sk) = gen_sig_keys(&mut rng);
        let domain = dummy_domain();
        let handles = vec![vec![0xAAu8; 32]];
        let extra_data = b"extra";

        let payload = PublicDecryptionResponsePayload {
            verification_key: bc2wrap::serialize(&pk).unwrap(),
            plaintexts: vec![TypedPlaintext::from_u32(42)],
            request_id: Some(RequestId::new_random(&mut rng).into()),
        };
        let payload_bytes = bc2wrap::serialize(&payload).unwrap();
        let sol_type =
            compute_public_decryption_message(&handles, &payload.plaintexts, extra_data).unwrap();

        // Several choices of schemes, including a classic + post-quantum hybrid.
        let choices: Vec<Vec<SigningSchemeType>> = vec![
            vec![SigningSchemeType::Ecdsa256k1],
            vec![SigningSchemeType::Ed25519],
            vec![SigningSchemeType::MlDsa65],
            vec![SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa65],
            vec![
                SigningSchemeType::Ecdsa256k1,
                SigningSchemeType::Ed25519,
                SigningSchemeType::MlDsa87,
            ],
        ];

        for schemes in choices {
            let sigs = super::sign_public_decryption_result(
                &sk,
                &schemes,
                payload.clone(),
                &handles,
                extra_data.to_vec(),
                &domain,
            )
            .unwrap();
            assert_eq!(sigs.signatures.len(), schemes.len());
            // The payload is carried through untouched, so what was signed is what is returned.
            assert_eq!(sigs.payload, payload);
            assert_eq!(sigs.extra_data, extra_data);

            // The deprecated scalar field is the raw signature over the payload.
            let legacy = internal_sign(&DSEP_PUBLIC_DECRYPTION, &payload_bytes, &sk).unwrap();
            assert_eq!(sigs.signature, legacy.as_bytes());

            // `external_signature` recovers to the signer on-chain.
            let recovered =
                recover_address_from_ext_signature(&sol_type, &domain, &sigs.external_signature)
                    .unwrap();
            assert_eq!(recovered, sk.verf_key().address());

            for (scheme, scheme_sig) in schemes.iter().zip(&sigs.signatures) {
                // The wire tag matches the requested scheme, in order.
                assert_eq!(
                    SigningSchemeType::try_from(scheme_sig.scheme).unwrap(),
                    *scheme
                );

                if *scheme == SigningSchemeType::Ecdsa256k1 {
                    // The ECDSA entry is the on-chain-verifiable EIP-712
                    // signature, not a raw signature over the payload.
                    assert_eq!(scheme_sig.signature, sigs.external_signature);
                    assert_ne!(scheme_sig.signature, sigs.signature);
                } else {
                    // Every other scheme signs the raw payload.
                    let vk = sk.unified_verifying_key(*scheme).unwrap();
                    let sig = Signature::new(*scheme, scheme_sig.signature.clone());
                    unified_verify(&DSEP_PUBLIC_DECRYPTION, &payload_bytes, &sig, &vk)
                        .unwrap_or_else(|e| panic!("{scheme:?} signature should verify: {e}"));

                    // A tampered message must fail.
                    assert!(
                        unified_verify(&DSEP_PUBLIC_DECRYPTION, b"tampered", &sig, &vk).is_err()
                    );
                }
            }
        }
    }

    /// Each job carries its own message, so schemes can be given distinct
    /// serializations of the same result. This is what lets a future
    /// scheme-specific encoding be introduced in [`super::scheme_signing_jobs`]
    /// without changing [`super::compute_result_signatures`].
    #[test]
    fn scheme_signatures_honour_per_scheme_messages() {
        use super::SchemeSigningJob;

        let mut rng = AesRng::seed_from_u64(0x9E11);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        let dsep = b"PERSCHEM";

        let ed_msg = b"serialization chosen for ed25519".to_vec();
        let mldsa_msg = b"a different serialization chosen for ml-dsa".to_vec();

        let jobs = vec![
            SchemeSigningJob {
                scheme: SigningSchemeType::Ed25519,
                message: ed_msg.clone(),
            },
            SchemeSigningJob {
                scheme: SigningSchemeType::MlDsa65,
                message: mldsa_msg.clone(),
            },
        ];

        let sigs = super::compute_result_signatures(&sk, dsep, &jobs).unwrap();
        assert_eq!(sigs.len(), 2);

        for (job, scheme_sig) in jobs.iter().zip(&sigs) {
            let vk = sk.unified_verifying_key(job.scheme).unwrap();
            let sig = Signature::new(job.scheme, scheme_sig.signature.clone());

            // Each signature verifies against *its own* message...
            unified_verify(dsep, &job.message, &sig, &vk)
                .unwrap_or_else(|e| panic!("{:?} should verify its own message: {e}", job.scheme));

            // ...and not against the other job's message.
            let other = if job.message == ed_msg {
                &mldsa_msg
            } else {
                &ed_msg
            };
            assert!(unified_verify(dsep, other, &sig, &vk).is_err());
        }
    }

    /// `external_signature` is always the EIP-712 signature, independent of the
    /// requested schemes, while `signatures` is opt-in on exactly the schemes
    /// requested: ECDSA carries the EIP-712 signature verbatim and every other
    /// scheme signs the serialized CRS payload — the same split decryption uses.
    #[test]
    fn crs_result_signatures_multi_scheme() {
        let mut rng = AesRng::seed_from_u64(0x5C15);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        let domain = dummy_domain();

        let crs_id = RequestId::new_random(&mut rng);
        let crs_digest = vec![0x42u8; 32];
        let max_num_bits = 2048usize;
        let extra_data = vec![0x01u8, 0x02, 0x03];
        let sol_type = CrsgenVerification::new(
            &crs_id,
            max_num_bits,
            crs_digest.clone(),
            extra_data.clone(),
        );
        let expected_external = compute_eip712_signature(&sk, &sol_type, &domain).unwrap();
        let eip712_hash = sol_type.eip712_signing_hash(&domain);
        let payload_bytes = super::signed_payload_bytes(&super::CrsSignedPayload {
            crs_id,
            max_num_bits: max_num_bits as u32,
            crs_digest: crs_digest.clone(),
            extra_data: extra_data.clone(),
        })
        .unwrap();

        // Go through the production entry point, so the payload the signer builds
        // is the one asserted against here.
        let signatures_for = |schemes: &[SigningSchemeType]| {
            let meta = super::compute_info_crs_from_digest(
                &sk,
                schemes,
                &crs_id,
                crs_digest.clone(),
                max_num_bits,
                &domain,
                extra_data.clone(),
            )
            .unwrap();
            match meta {
                super::CrsGenMetadata::Current(inner) => {
                    (inner.external_signature, inner.signatures)
                }
                super::CrsGenMetadata::LegacyV0(_) => panic!("expected current metadata"),
            }
        };

        // Requesting no scheme: `external_signature` is still produced, `signatures` is empty.
        let (external_signature, sigs) = signatures_for(&[]);
        assert_eq!(external_signature, expected_external);
        assert!(sigs.is_empty(), "no schemes requested ⇒ empty signatures");

        // Requesting a classic + two post-quantum schemes: `signatures` reflects
        // exactly the request.
        let schemes = [
            SigningSchemeType::Ecdsa256k1,
            SigningSchemeType::Ed25519,
            SigningSchemeType::MlDsa65,
        ];
        let (external_signature, sigs) = signatures_for(&schemes);
        assert_eq!(external_signature, expected_external);
        assert_eq!(sigs.len(), schemes.len());

        for stored in &sigs {
            match stored.scheme {
                // ECDSA is the on-chain-verifiable EIP-712 signature verbatim.
                SigningSchemeType::Ecdsa256k1 => {
                    assert_eq!(stored.signature, expected_external);
                }
                // Every other scheme signs the serialized CRS payload.
                scheme => {
                    let vk = sk.unified_verifying_key(scheme).unwrap();
                    let sig = Signature::new(scheme, stored.signature.clone());
                    unified_verify(&DSEP_PUBDATA_CRS, &payload_bytes, &sig, &vk)
                        .unwrap_or_else(|e| panic!("{scheme:?} CRS signature should verify: {e}"));
                    // Specifically not the EIP-712 hash any more.
                    assert!(
                        unified_verify(&DSEP_PUBDATA_CRS, eip712_hash.as_slice(), &sig, &vk)
                            .is_err(),
                        "{scheme:?} must sign the payload, not the EIP-712 hash"
                    );
                    assert!(
                        unified_verify(&DSEP_PUBDATA_CRS, b"tampered", &sig, &vk).is_err(),
                        "{scheme:?} verified a tampered payload"
                    );
                }
            }
        }
    }

    /// The keygen counterpart of [`crs_result_signatures_multi_scheme`]: the
    /// non-ECDSA entries sign the serialized keygen payload, whose `key_digests`
    /// is what distinguishes the keygen shapes.
    #[test]
    fn keygen_result_signatures_sign_the_payload() {
        let mut rng = AesRng::seed_from_u64(0x4E67);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        let domain = dummy_domain();

        let prep_id = RequestId::new_random(&mut rng);
        let key_id = RequestId::new_random(&mut rng);
        let server_key_digest = vec![0xAAu8; 32];
        let public_key_digest = vec![0xBBu8; 32];
        let extra_data = vec![0x09u8, 0x08];
        let schemes = [SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa65];

        let meta = super::compute_info_standard_keygen_from_digests(
            &sk,
            &schemes,
            &prep_id,
            &key_id,
            server_key_digest.clone(),
            public_key_digest.clone(),
            &domain,
            extra_data.clone(),
        )
        .unwrap();
        let inner = match meta {
            KeyGenMetadata::Current(inner) => inner,
            KeyGenMetadata::LegacyV0(_) => panic!("expected current metadata"),
        };

        let expected_payload = super::keygen_payload_bytes(
            &prep_id,
            &key_id,
            &BTreeMap::from([
                (PubDataType::ServerKey, server_key_digest),
                (PubDataType::PublicKey, public_key_digest),
            ]),
            &extra_data,
        )
        .unwrap();

        assert_eq!(inner.signatures.len(), schemes.len());
        for stored in &inner.signatures {
            match stored.scheme {
                SigningSchemeType::Ecdsa256k1 => {
                    assert_eq!(stored.signature, inner.external_signature);
                }
                scheme => {
                    let vk = sk.unified_verifying_key(scheme).unwrap();
                    let sig = Signature::new(scheme, stored.signature.clone());
                    unified_verify(&DSEP_PUBDATA_KEY, &expected_payload, &sig, &vk).unwrap_or_else(
                        |e| panic!("{scheme:?} keygen signature should verify: {e}"),
                    );
                }
            }
        }
    }

    #[test]
    fn sunshine_plaintext_as_u256() {
        let mut rng = AesRng::seed_from_u64(1);
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);

        let plaintext = TypedPlaintext {
            bytes: bytes.to_vec(),
            fhe_type: FheTypes::Uint160 as i32,
        };
        // Check the value is greater than 2^128
        assert!(plaintext.as_u160() > tfhe::integer::U256::from((0, 1)));
        assert!(plaintext.as_u256() > tfhe::integer::U256::from((0, 1)));
        // Sanity check the internal values - at least one byte must be different from zero
        assert!(bytes.iter().any(|&b| b != 0));
        assert_eq!(plaintext.fhe_type().unwrap(), FheTypes::Uint160);
        // Check consistent representations
        assert!(bytes[0] % 2 == plaintext.as_bool() as u8);
        assert_eq!(plaintext.as_u4(), bytes[0] % 16);
        assert_eq!(plaintext.as_u8(), bytes[0]);
        let u16_ref = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
        assert_eq!(plaintext.as_u16(), u16_ref);
        let u32_ref = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(plaintext.as_u32(), u32_ref);
        let u64_ref = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        assert_eq!(plaintext.as_u64(), u64_ref);
        let u128_ref = u128::from_le_bytes(bytes[0..16].try_into().unwrap());
        assert_eq!(plaintext.as_u128(), u128_ref);
    }

    #[test]
    fn test_abi_encoding_fhevm_ebytes() {
        let u256_val = tfhe::integer::U256::from((1, 256));
        let u512_val = tfhe::integer::bigint::U512::from(512_u64);
        let u2048_val = tfhe::integer::bigint::U2048::from(257_u64);

        // a batch of multiple plaintexts of different types
        let pts_2048: Vec<TypedPlaintext> = vec![
            TypedPlaintext::from_u2048(u2048_val),
            TypedPlaintext::from_bool(true),
            TypedPlaintext::from_u4(4),
            TypedPlaintext::from_u4(5),
            TypedPlaintext::from_u2048(u2048_val),
            TypedPlaintext::from_u8(8),
            TypedPlaintext::from_u16(16),
            TypedPlaintext::from_u32(32),
            TypedPlaintext::from_u128(128),
            TypedPlaintext::from_u160_low_high((234, 255)),
            TypedPlaintext::from_u256(u256_val),
            TypedPlaintext::from_u2048(u2048_val),
        ];

        // encode plaintexts into a list of solidity bytes using `alloy`
        let bytes_2048 = super::abi_encode_plaintexts_ebytes(&pts_2048);
        let hexbytes_2048 = hex::encode(bytes_2048);

        // this is the encoding of the same list of plaintexts (pts_2048) using the outdated `ethers` crate.
        let reference_2048 = "00000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000002e00000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000ff000000000000000000000000000000ea000000000000000000000000000001000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000520000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101";

        assert_eq!(reference_2048, hexbytes_2048.as_str());

        // a batch of a single plaintext
        let pts_16: Vec<TypedPlaintext> = vec![TypedPlaintext::from_u16(16)];

        // encode plaintexts into a list of solidity bytes using `alloy`
        let bytes_16 = super::abi_encode_plaintexts_ebytes(&pts_16);
        let hexbytes_16 = hex::encode(bytes_16);

        // this is the encoding of the same list of plaintexts (pts_16) using the outdated `ethers` crate.
        let reference_16 = "00000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000060";

        assert_eq!(reference_16, hexbytes_16.as_str());

        // a batch of a two plaintext that are not of type Euint2048
        let pts_16_2: Vec<TypedPlaintext> =
            vec![TypedPlaintext::from_u16(16), TypedPlaintext::from_u16(16)];

        // encode plaintexts into a list of solidity bytes using `alloy`
        let bytes_16_2 = super::abi_encode_plaintexts_ebytes(&pts_16_2);
        let hexbytes_16_2 = hex::encode(bytes_16_2);

        // this is the encoding of the same list of plaintexts (pts_16_2) using the outdated `ethers` crate.
        let reference_16_2 = "000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000080";
        assert_eq!(reference_16_2, hexbytes_16_2.as_str());

        // test more versions of plaintext batches in the rest of this test in a similar fashion as above
        let pts_mix_2: Vec<TypedPlaintext> = vec![
            TypedPlaintext::from_u2048(u2048_val),
            TypedPlaintext::from_bool(true),
            TypedPlaintext::from_u4(4),
            TypedPlaintext::from_u4(5),
            TypedPlaintext::from_u2048(u2048_val),
            TypedPlaintext::from_u8(8),
            TypedPlaintext::from_u16(16),
            TypedPlaintext::from_u32(32),
            TypedPlaintext::from_u128(128),
            TypedPlaintext::from_u160_low_high((234, 255)),
            TypedPlaintext::from_u256(u256_val),
            TypedPlaintext::from_u2048(u2048_val),
            TypedPlaintext::from_u512(u512_val),
            TypedPlaintext::from_u32(32),
        ];

        let pts_mix_3: Vec<TypedPlaintext> = vec![
            TypedPlaintext::from_u2048(u2048_val),
            TypedPlaintext::from_u512(u512_val),
        ];

        let pts_double_u2048: Vec<TypedPlaintext> = vec![
            TypedPlaintext::from_u2048(u2048_val),
            TypedPlaintext::from_u2048(u2048_val),
        ];

        let pts_single_u2048: Vec<TypedPlaintext> = vec![TypedPlaintext::from_u2048(u2048_val)];

        let pts_single_u512: Vec<TypedPlaintext> = vec![TypedPlaintext::from_u512(u512_val)];

        let u512_val_mx = tfhe::integer::bigint::U512::from(18446744073709551600_u64);

        let pts_single_u512_mx: Vec<TypedPlaintext> = vec![TypedPlaintext::from_u512(u512_val_mx)];
        let pts_single_u512_mx_2 = vec![TypedPlaintext::from_u512(18446744073709551600_u64.into())];
        // check that both plaintext are identical, even if constructed from different input types
        assert_eq!(pts_single_u512_mx, pts_single_u512_mx_2);

        // reference encoding of the above plaintexts using the outdated `ethers` crate.
        let reference_mix_2 = "000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000003200000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000ff000000000000000000000000000000ea000000000000000000000000000001000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000004400000000000000000000000000000000000000000000000000000000000000560000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000005c0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200";
        let bytes_mix_2 = super::abi_encode_plaintexts_ebytes(&pts_mix_2);

        let hexbytes_mix_2 = hex::encode(bytes_mix_2);
        assert_eq!(reference_mix_2, hexbytes_mix_2.as_str());

        let reference_mix_3 = "000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001a00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200";
        let bytes_mix_3 = super::abi_encode_plaintexts_ebytes(&pts_mix_3);

        let hexbytes_mix_3 = hex::encode(bytes_mix_3);
        assert_eq!(reference_mix_3, hexbytes_mix_3.as_str());

        let reference_double_u2048 = "000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000002c0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101";
        let bytes_double_u2048 = super::abi_encode_plaintexts_ebytes(&pts_double_u2048);

        let hexbytes_double_u2048 = hex::encode(bytes_double_u2048);
        assert_eq!(reference_double_u2048, hexbytes_double_u2048.as_str());

        let reference_single_u2048 = "00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000180000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101";
        let bytes_single_u2048 = super::abi_encode_plaintexts_ebytes(&pts_single_u2048);

        let hexbytes_single_u2048 = hex::encode(bytes_single_u2048);
        assert_eq!(reference_single_u2048, hexbytes_single_u2048.as_str());

        let reference_single_u512 = "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200";
        let bytes_single_u512 = super::abi_encode_plaintexts_ebytes(&pts_single_u512);

        let hexbytes_single_u512 = hex::encode(bytes_single_u512);
        assert_eq!(reference_single_u512, hexbytes_single_u512.as_str());

        let reference_val_mx = "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fffffffffffffff0";
        let bytes_val_mx = super::abi_encode_plaintexts_ebytes(&pts_single_u512_mx);

        let hexbytes_val_mx = hex::encode(bytes_val_mx);
        assert_eq!(reference_val_mx, hexbytes_val_mx.as_str());
    }

    #[test]
    fn test_deserialize_ciphertext_wrong_type() {
        // we just use small ciphertexts for these tests
        let mut rng = AesRng::seed_from_u64(100);
        let (_sig_pk, sig_sk) = gen_sig_keys(&mut rng);
        let key_id = RequestId::new_random(&mut rng);
        let preproc_id = RequestId::new_random(&mut rng);
        let (pubkeyset, _sk) = generate_uncompressed_fhe_keys(
            &sig_sk,
            &[crate::cryptography::signing::SigningSchemeType::Ecdsa256k1],
            TEST_PARAM,
            StandardKeySetConfig::default().secret_key_config,
            &key_id,
            &preproc_id,
            None,
            &dummy_domain(),
            vec![],
        )
        .unwrap();

        let msg = 32u32;
        tfhe::set_server_key(pubkeyset.server_key);
        let ct: FheUint32 = expanded_encrypt(&pubkeyset.public_key, msg, 32).unwrap();

        let mut ct_buf = Vec::new();
        safe_serialize(&ct, &mut ct_buf, SAFE_SER_SIZE_LIMIT).unwrap();

        // use the wrong type
        assert!(
            deserialize_to_low_level(
                FheTypes::Bool,
                CiphertextFormat::SmallExpanded,
                &ct_buf,
                None,
            )
            .is_err()
        );

        // should pass with the correct type
        assert!(
            deserialize_to_low_level(
                FheTypes::Uint32,
                CiphertextFormat::SmallExpanded,
                &ct_buf,
                None,
            )
            .is_ok()
        );
    }

    #[test]
    fn test_deserialize_ciphertext_wrong_ct_format() {
        // we just use small ciphertexts for these tests
        let mut rng = AesRng::seed_from_u64(100);
        let (_sig_pk, sig_sk) = gen_sig_keys(&mut rng);
        let key_id = RequestId::new_random(&mut rng);
        let preproc_id = RequestId::new_random(&mut rng);
        let (pubkeyset, _sk) = generate_uncompressed_fhe_keys(
            &sig_sk,
            &[crate::cryptography::signing::SigningSchemeType::Ecdsa256k1],
            TEST_PARAM,
            StandardKeySetConfig::default().secret_key_config,
            &key_id,
            &preproc_id,
            None,
            &dummy_domain(),
            vec![],
        )
        .unwrap();

        let msg = 32u32;
        tfhe::set_server_key(pubkeyset.server_key);
        let ct: FheUint32 = expanded_encrypt(&pubkeyset.public_key, msg, 32).unwrap();

        // test SmallExpanded
        {
            let mut ct_buf = Vec::new();
            safe_serialize(&ct, &mut ct_buf, SAFE_SER_SIZE_LIMIT).unwrap();

            // use the wrong format
            assert!(
                deserialize_to_low_level(
                    FheTypes::Uint32,
                    CiphertextFormat::BigExpanded,
                    &ct_buf,
                    None,
                )
                .is_err()
            );

            // should pass with the correct format
            deserialize_to_low_level(
                FheTypes::Uint32,
                CiphertextFormat::SmallExpanded,
                &ct_buf,
                None,
            )
            .unwrap();
        }

        {
            let large_ct = ct.squash_noise().unwrap();
            let mut ct_buf = Vec::new();
            safe_serialize(&large_ct, &mut ct_buf, SAFE_SER_SIZE_LIMIT).unwrap();

            // use the wrong format
            assert!(
                deserialize_to_low_level(
                    FheTypes::Uint32,
                    CiphertextFormat::SmallExpanded,
                    &ct_buf,
                    None,
                )
                .is_err()
            );

            // should pass with the correct format
            deserialize_to_low_level(
                FheTypes::Uint32,
                CiphertextFormat::BigExpanded,
                &ct_buf,
                None,
            )
            .unwrap();
        }
    }

    #[test]
    fn test_deserialize_ciphertext_missing_decompression_key() {
        // we just use small ciphertexts for these tests
        let mut rng = AesRng::seed_from_u64(100);
        let (_sig_pk, sig_sk) = gen_sig_keys(&mut rng);
        let key_id = RequestId::new_random(&mut rng);
        let preproc_id = RequestId::new_random(&mut rng);
        let (pubkeyset, _sk) = generate_uncompressed_fhe_keys(
            &sig_sk,
            &[crate::cryptography::signing::SigningSchemeType::Ecdsa256k1],
            TEST_PARAM,
            StandardKeySetConfig::default().secret_key_config,
            &key_id,
            &preproc_id,
            None,
            &dummy_domain(),
            vec![],
        )
        .unwrap();

        let (
            _raw_server_key,
            _cpk_ksk,
            compression_key,
            decompression_key,
            _noise_squashing_key,
            _noise_squashing_compression_key,
            _rerand_key,
            _oprf_key,
            _tag,
        ) = pubkeyset.server_key.clone().into_raw_parts();
        assert!(compression_key.is_some());
        assert!(decompression_key.is_some());

        let msg = 32u32;
        tfhe::set_server_key(pubkeyset.server_key);
        let ct: FheUint32 = expanded_encrypt(&pubkeyset.public_key, msg, 32).unwrap();

        let ct_buf =
            crate::cryptography::decompression::test_tools::compress_serialize_versioned(ct);

        // setting decompression key to None should fail
        {
            assert!(
                deserialize_to_low_level(
                    FheTypes::Uint32,
                    CiphertextFormat::SmallCompressed,
                    &ct_buf,
                    None,
                )
                .is_err()
            );
        }

        // should pass with the correct decompression key
        {
            deserialize_to_low_level(
                FheTypes::Uint32,
                CiphertextFormat::SmallCompressed,
                &ct_buf,
                decompression_key.as_ref(),
            )
            .unwrap();
        }
    }

    #[test]
    fn test_compute_info_standard_keygen() {
        let mut rng = AesRng::seed_from_u64(123);
        let (pk, sk) = gen_sig_keys(&mut rng);
        let actual_address = pk.address();
        let prep_id = RequestId::new_random(&mut rng);
        let key_id = RequestId::new_random(&mut rng);
        let params = TEST_PARAM;
        let client_key = generate_client_fhe_key(params, key_id.into(), Some(Seed(1)));
        let server_key = client_key.generate_server_key();
        let public_key = FhePublicKey::new(&client_key);

        let server_key_digest = hash_versioned(&DSEP_PUBDATA_KEY, &server_key).unwrap();
        let public_key_digest = hash_versioned(&DSEP_PUBDATA_KEY, &public_key).unwrap();

        let keyset = FhePubKeySet {
            public_key,
            server_key,
        };
        let domain = dummy_domain();
        let extra_data = vec![0x01u8, 0x02, 0x03, 0x04];
        let meta_data = compute_info_uncompressed_keygen(
            &sk,
            &[crate::cryptography::signing::SigningSchemeType::Ecdsa256k1],
            &crate::engine::base::DSEP_PUBDATA_KEY,
            &prep_id,
            &key_id,
            &keyset,
            &domain,
            extra_data.clone(),
        )
        .unwrap();

        {
            // do the verification correctly
            let sol_struct = KeygenVerification::new_uncompressed(
                &prep_id,
                &key_id,
                server_key_digest.clone(),
                public_key_digest.clone(),
                extra_data.clone(),
            );

            assert_eq!(
                recover_address_from_ext_signature(
                    &sol_struct,
                    &domain,
                    meta_data.external_signature()
                )
                .unwrap(),
                actual_address
            );
        }
        {
            // wrong domain
            let bad_domain = alloy_sol_types::eip712_domain!(
                name: "Wrong name",
                version: "1",
                chain_id: 8006,
                verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
            );
            let sol_struct = KeygenVerification::new_uncompressed(
                &prep_id,
                &key_id,
                server_key_digest.clone(),
                public_key_digest.clone(),
                extra_data.clone(),
            );

            assert_ne!(
                recover_address_from_ext_signature(
                    &sol_struct,
                    &bad_domain,
                    meta_data.external_signature()
                )
                .unwrap(),
                actual_address
            );
        }
        {
            // should fail if we use a wrong prep_id
            let bad_prep_id = RequestId::new_random(&mut rng);
            let sol_struct = KeygenVerification::new_uncompressed(
                &bad_prep_id,
                &key_id,
                server_key_digest.clone(),
                public_key_digest.clone(),
                extra_data.clone(),
            );
            assert_ne!(
                recover_address_from_ext_signature(
                    &sol_struct,
                    &domain,
                    meta_data.external_signature()
                )
                .unwrap(),
                actual_address
            );
        }
        {
            // should fail if we use the wrong key_id
            let bad_key_id = RequestId::new_random(&mut rng);
            let sol_struct = KeygenVerification::new_uncompressed(
                &prep_id,
                &bad_key_id,
                server_key_digest.clone(),
                public_key_digest.clone(),
                extra_data.clone(),
            );
            assert_ne!(
                recover_address_from_ext_signature(
                    &sol_struct,
                    &domain,
                    meta_data.external_signature()
                )
                .unwrap(),
                actual_address
            );
        }
        {
            // should fail if we use the wrong digest
            let mut bad_server_key_digest = server_key_digest.clone();
            bad_server_key_digest[0] ^= 1;
            let sol_struct = KeygenVerification::new_uncompressed(
                &prep_id,
                &key_id,
                bad_server_key_digest.clone(),
                public_key_digest.clone(),
                extra_data.clone(),
            );
            assert_ne!(
                recover_address_from_ext_signature(
                    &sol_struct,
                    &domain,
                    meta_data.external_signature()
                )
                .unwrap(),
                actual_address
            );
        }
        {
            // should fail if we use the wrong signature

            let (_, bad_sk) = gen_sig_keys(&mut rng);
            let meta_data = compute_info_uncompressed_keygen(
                &bad_sk,
                &[crate::cryptography::signing::SigningSchemeType::Ecdsa256k1],
                &crate::engine::base::DSEP_PUBDATA_KEY,
                &prep_id,
                &key_id,
                &keyset,
                &domain,
                extra_data.clone(),
            )
            .unwrap();
            let bad_signature = meta_data.external_signature();
            let sol_struct = KeygenVerification::new_uncompressed(
                &prep_id,
                &key_id,
                server_key_digest.clone(),
                public_key_digest.clone(),
                extra_data.clone(),
            );
            assert_ne!(
                recover_address_from_ext_signature(&sol_struct, &domain, bad_signature).unwrap(),
                actual_address
            );
        }
        {
            // should fail if we use the wrong extra_data
            let bad_extra_data = vec![0x04u8, 0x03, 0x02, 0x01];
            let sol_struct = KeygenVerification::new_uncompressed(
                &prep_id,
                &key_id,
                server_key_digest.clone(),
                public_key_digest.clone(),
                bad_extra_data,
            );
            assert_ne!(
                recover_address_from_ext_signature(
                    &sol_struct,
                    &domain,
                    meta_data.external_signature()
                )
                .unwrap(),
                actual_address
            );
        }
    }

    #[test]
    fn test_compute_info_crs() {
        let mut rng = AesRng::seed_from_u64(123);
        let (pk, sk) = gen_sig_keys(&mut rng);
        let actual_address = pk.address();
        let crs_id = RequestId::new_random(&mut rng);
        let params = TEST_PARAM;
        let max_num_bits = 64;
        let domain = dummy_domain();
        let extra_data = vec![0x10u8, 0x20, 0x30];

        let (crs, meta_data) = gen_centralized_crs(
            &sk,
            &[SigningSchemeType::Ecdsa256k1],
            &params,
            Some(max_num_bits),
            &domain,
            extra_data.clone(),
            &crs_id,
            &mut rng,
        )
        .unwrap();

        let crs_digest = hash_versioned(&DSEP_PUBDATA_CRS, &crs).unwrap();

        {
            // do the verification correctly
            let sol_struct = CrsgenVerification::new(
                &crs_id,
                max_num_bits as usize,
                crs_digest.clone(),
                extra_data.clone(),
            );

            assert_eq!(
                recover_address_from_ext_signature(
                    &sol_struct,
                    &domain,
                    meta_data.external_signature()
                )
                .unwrap(),
                actual_address
            );
        }
        {
            // should fail if we use a wrong crs_id
            let bad_crs_id = RequestId::new_random(&mut rng);
            let sol_struct = CrsgenVerification::new(
                &bad_crs_id,
                max_num_bits as usize,
                crs_digest.clone(),
                extra_data.clone(),
            );

            assert_ne!(
                recover_address_from_ext_signature(
                    &sol_struct,
                    &domain,
                    meta_data.external_signature()
                )
                .unwrap(),
                actual_address
            );
        }
        {
            // wrong domain
            let bad_domain = alloy_sol_types::eip712_domain!(
                name: "Wrong name",
                version: "1",
                chain_id: 8006,
                verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
            );
            let sol_struct = CrsgenVerification::new(
                &crs_id,
                max_num_bits as usize,
                crs_digest.clone(),
                extra_data.clone(),
            );
            assert_ne!(
                recover_address_from_ext_signature(
                    &sol_struct,
                    &bad_domain,
                    meta_data.external_signature()
                )
                .unwrap(),
                actual_address
            );
        }
        {
            // should fail if we use the wrong max_num_bits
            let wrong_max_num_bits = 16;
            let sol_struct = CrsgenVerification::new(
                &crs_id,
                wrong_max_num_bits as usize,
                crs_digest.clone(),
                extra_data.clone(),
            );

            assert_ne!(
                recover_address_from_ext_signature(
                    &sol_struct,
                    &domain,
                    meta_data.external_signature()
                )
                .unwrap(),
                actual_address
            );
        }
        {
            // should fail if we use the wrong digest
            let mut wrong_digest = crs_digest.clone();
            wrong_digest[0] ^= 1;
            let sol_struct = CrsgenVerification::new(
                &crs_id,
                max_num_bits as usize,
                wrong_digest,
                extra_data.clone(),
            );

            assert_ne!(
                recover_address_from_ext_signature(
                    &sol_struct,
                    &domain,
                    meta_data.external_signature()
                )
                .unwrap(),
                actual_address
            );
        }
        {
            // shold fail if we use the wrong signature
            let (_, bad_sk) = gen_sig_keys(&mut rng);
            let (crs, meta_data) = gen_centralized_crs(
                &bad_sk, // using bad_sk
                &[SigningSchemeType::Ecdsa256k1],
                &params,
                Some(max_num_bits),
                &domain,
                extra_data.clone(),
                &crs_id,
                &mut rng,
            )
            .unwrap();
            let crs_digest = hash_versioned(&DSEP_PUBDATA_CRS, &crs).unwrap();

            let sol_struct = CrsgenVerification::new(
                &crs_id,
                max_num_bits as usize,
                crs_digest.clone(),
                extra_data.clone(),
            );

            assert_ne!(
                recover_address_from_ext_signature(
                    &sol_struct,
                    &domain,
                    meta_data.external_signature()
                )
                .unwrap(),
                actual_address
            );
        }
        {
            // should fail if we use the wrong extra_data
            let bad_extra_data = vec![0x30u8, 0x20, 0x10];
            let sol_struct = CrsgenVerification::new(
                &crs_id,
                max_num_bits as usize,
                crs_digest.clone(),
                bad_extra_data,
            );

            assert_ne!(
                recover_address_from_ext_signature(
                    &sol_struct,
                    &domain,
                    meta_data.external_signature()
                )
                .unwrap(),
                actual_address
            );
        }
    }

    #[test]
    fn test_compute_pt_message_hash() {
        let domain = dummy_domain();

        // Plaintexts to sign
        let pts: Vec<TypedPlaintext> = vec![
            TypedPlaintext::from_u16(16),
            TypedPlaintext::from_bool(true),
        ];

        // External handles (all 32 bytes long)
        let handles = vec![vec![0xAAu8; 32], vec![0xBBu8; 32]];

        // Extra data (empty for now)
        let extra_data: &[u8] = &[];

        // Determinism: same inputs -> same hash
        let m1 = compute_public_decryption_message(&handles, &pts, extra_data)
            .expect("msg computation should succeed");
        let h1 = m1.eip712_signing_hash(&domain);
        let m2 = compute_public_decryption_message(&handles, &pts, extra_data)
            .expect("msg computation should succeed");
        let h2 = m2.eip712_signing_hash(&domain);
        assert_eq!(h1, h2, "Hashes must be the same for identical inputs");

        // Changing a handle changes the message
        let mut mutated_handles = handles.clone();
        mutated_handles[1][0] ^= 0x23;
        let m_changed_handle =
            compute_public_decryption_message(&mutated_handles, &pts, extra_data)
                .expect("msg computation should succeed");
        let h_changed_handle = m_changed_handle.eip712_signing_hash(&domain);
        assert_ne!(
            h1, h_changed_handle,
            "Hash should change when a handle changes"
        );

        // Changing a plaintext value changes the hash
        let mut pts_modified = pts.clone();
        pts_modified[0] = TypedPlaintext::from_u16(69);
        let m_changed_pt = compute_public_decryption_message(&handles, &pts_modified, extra_data)
            .expect("msg computation should succeed");
        let h_changed_pt = m_changed_pt.eip712_signing_hash(&domain);
        assert_ne!(
            h1, h_changed_pt,
            "Hash should change when a plaintext changes"
        );

        // Changing extra data changes the hash
        let extra_data2 = vec![1u8, 2, 3, 5, 23];
        let m_changed_extra = compute_public_decryption_message(&handles, &pts, &extra_data2)
            .expect("msg computation should succeed");
        let h_changed_extra = m_changed_extra.eip712_signing_hash(&domain);
        assert_ne!(
            h1, h_changed_extra,
            "Hash should change when extra_data changes"
        );

        // Error path: a handle longer than 32 bytes should fail
        let bad_handles = vec![vec![0u8; 33]];
        let err = compute_public_decryption_message(&bad_handles, &pts, &[]).unwrap_err();
        assert!(
            err.to_string().contains("too long: 33 bytes (max 32"),
            "Error message should mention 'too long: 33 bytes (max 32', got: {err}"
        );
        assert!(
            err.to_string().contains("too long"),
            "Error message should mention 'too long', got: {err}"
        );

        // If the following test fails, we have changed how the hash is computed so the reference does not match anymore.
        // This is a breaking change that needs to be synced across components. The reference should then be updated.
        let reference_hash_hex = "c7b9ab84a782163ba1911d246e81387510b1f670871ccc7bcefaee95ebf033bf";
        assert_eq!(
            hex::encode(h1),
            reference_hash_hex,
            "Reference hash mismatch"
        );
    }

    #[test]
    fn test_compute_external_signature_preproc() {
        let mut rng = AesRng::seed_from_u64(123);
        let (pk, sk) = gen_sig_keys(&mut rng);
        let actual_address = pk.address();
        let preproc_id = RequestId::new_random(&mut rng);
        let domain = dummy_domain();
        let extra_data = vec![0x0Au8, 0x0B, 0x0C];
        // `external_signature` is always produced regardless of requested schemes.
        let (sig, _signatures) =
            compute_preprocessing_signatures(&sk, &[], &preproc_id, &domain, extra_data.clone())
                .unwrap();

        {
            // happy path
            let sol_struct = PrepKeygenVerification::new(&preproc_id, extra_data.clone());
            assert_eq!(
                recover_address_from_ext_signature(&sol_struct, &domain, &sig).unwrap(),
                actual_address
            );
        }
        {
            // wrong ID
            let bad_preproc_id = RequestId::new_random(&mut rng);
            let sol_struct = PrepKeygenVerification::new(&bad_preproc_id, extra_data.clone());
            assert_ne!(
                recover_address_from_ext_signature(&sol_struct, &domain, &sig).unwrap(),
                actual_address
            );
        }
        {
            // wrong domain
            let bad_domain = alloy_sol_types::eip712_domain!(
                name: "Wrong name",
                version: "1",
                chain_id: 8006,
                verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
            );
            let sol_struct = PrepKeygenVerification::new(&preproc_id, extra_data.clone());
            assert_ne!(
                recover_address_from_ext_signature(&sol_struct, &bad_domain, &sig).unwrap(),
                actual_address
            );
        }
        {
            // wrong signature
            let (_, bad_sk) = gen_sig_keys(&mut rng);
            let (sig, _signatures) = compute_preprocessing_signatures(
                &bad_sk,
                &[],
                &preproc_id,
                &domain,
                extra_data.clone(),
            )
            .unwrap();
            let sol_struct = PrepKeygenVerification::new(&preproc_id, extra_data.clone());
            assert_ne!(
                recover_address_from_ext_signature(&sol_struct, &domain, &sig).unwrap(),
                actual_address
            );
        }
        {
            // wrong extra data
            let bad_extra_data = vec![0x0Bu8, 0x0A, 0x0D];
            let sol_struct = PrepKeygenVerification::new(&preproc_id, bad_extra_data);
            assert_ne!(
                recover_address_from_ext_signature(&sol_struct, &domain, &sig).unwrap(),
                actual_address
            );
        }
    }

    #[test]
    fn keygen_metadata_q126_upgrade() {
        let mut rng = AesRng::seed_from_u64(888);
        let (_verf_key, sig_key) = gen_sig_keys(&mut rng);
        let domain = dummy_domain();

        let key_id = RequestId::new_random(&mut rng);
        let preprocessing_id = RequestId::new_random(&mut rng);
        let server_key_digest = vec![0xAAu8; 32];
        let public_key_digest = vec![0xBBu8; 32];

        let legacy_sol = KeygenVerificationQ126::new_standard(
            &preprocessing_id,
            &key_id,
            server_key_digest.clone(),
            public_key_digest.clone(),
        );
        let external_signature = compute_eip712_signature(&sig_key, &legacy_sol, &domain).unwrap();

        let mut key_digest_map: HashMap<PubDataType, Vec<u8>> = HashMap::new();
        key_digest_map.insert(PubDataType::ServerKey, server_key_digest.clone());
        key_digest_map.insert(PubDataType::PublicKey, public_key_digest.clone());

        let q126 = KeyGenMetadataInnerV0 {
            key_id,
            preprocessing_id,
            key_digest_map: key_digest_map.clone(),
            external_signature: external_signature.clone(),
        };

        // Verify upgrade sets extra_data as None
        let upgraded: KeyGenMetadataInnerV1 = q126.clone().upgrade().unwrap();
        assert_eq!(upgraded.extra_data, None);
        // Upgraded serialization
        let upgraded_bytes = bc2wrap::serialize(&upgraded).unwrap();

        let deserialized_upgraded: KeyGenMetadataInnerV1 =
            bc2wrap::deserialize_slice(&upgraded_bytes).unwrap();
        assert_eq!(deserialized_upgraded.extra_data, None);
        assert_eq!(deserialized_upgraded.key_id, q126.key_id);
        assert_eq!(
            deserialized_upgraded.preprocessing_id,
            q126.preprocessing_id
        );
        assert_eq!(&deserialized_upgraded.key_digest_map, &q126.key_digest_map);
        assert_eq!(
            deserialized_upgraded.external_signature,
            q126.external_signature
        );

        // V1 -> V2 -> V3 -> V4: the HashMap is converted to a BTreeMap (V2), the
        // per-scheme `signatures` list is added (V3), and the optional EIP-712 domain is
        // added (V4).
        // Field-by-field structural equality remains, modulo container type.
        let upgraded_v4: KeyGenMetadataInner = upgraded
            .upgrade()
            .unwrap()
            .upgrade()
            .unwrap()
            .upgrade()
            .unwrap();
        assert_eq!(upgraded_v4.extra_data, None);
        assert_eq!(upgraded_v4.key_id, q126.key_id);
        assert_eq!(upgraded_v4.preprocessing_id, q126.preprocessing_id);
        assert_eq!(
            upgraded_v4.key_digest_map,
            q126.key_digest_map
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect::<BTreeMap<_, _>>(),
        );
        assert_eq!(upgraded_v4.external_signature, q126.external_signature);
        assert!(upgraded_v4.signatures.is_empty());
        assert_eq!(upgraded_v4.eip712_domain, None);
    }

    #[test]
    fn keygen_metadata_preprocessing_id() {
        let mut rng = AesRng::seed_from_u64(890);
        let key_id = RequestId::new_random(&mut rng);
        let preprocessing_id = RequestId::new_random(&mut rng);
        let domain = dummy_domain();
        let expected_domain = StoredEip712Domain::from(&domain);

        let current = KeyGenMetadata::new(
            key_id,
            preprocessing_id,
            BTreeMap::new(),
            &domain,
            vec![],
            vec![],
            vec![],
        );
        assert_eq!(current.preprocessing_id(), Some(&preprocessing_id));
        let KeyGenMetadata::Current(current_inner) = &current else {
            panic!("KeyGenMetadata::new must produce current metadata");
        };
        assert_eq!(current_inner.eip712_domain.as_ref(), Some(&expected_domain));

        let crs = CrsGenMetadata::new(key_id, vec![], 64, &domain, vec![], vec![], vec![]);
        let CrsGenMetadata::Current(crs_inner) = &crs else {
            panic!("CrsGenMetadata::new must produce current metadata");
        };
        assert_eq!(crs_inner.eip712_domain.as_ref(), Some(&expected_domain));

        // Legacy metadata predates the field, so there is nothing to report.
        let legacy = KeyGenMetadata::LegacyV0(HashMap::new());
        assert_eq!(legacy.preprocessing_id(), None);
    }

    #[test]
    fn crs_gen_metadata_q126_upgrade() {
        let mut rng = AesRng::seed_from_u64(889);
        let (_verf_key, sig_key) = gen_sig_keys(&mut rng);
        let domain = dummy_domain();

        let crs_id = RequestId::new_random(&mut rng);
        let crs_digest = vec![0x12u8; 32];
        let max_num_bits: u32 = 64;

        let legacy_sol =
            CrsgenVerificationQ126::new(&crs_id, max_num_bits as usize, crs_digest.clone());
        let external_signature = compute_eip712_signature(&sig_key, &legacy_sol, &domain).unwrap();

        let q126 = CrsGenMetadataInnerV0 {
            crs_id,
            crs_digest: crs_digest.clone(),
            max_num_bits,
            external_signature: external_signature.clone(),
        };

        // Verify upgrade (V0 -> V1 -> V2 -> V3) sets extra_data as None; `signatures`
        // is opt-in, so it upgrades to empty, and the EIP-712 domain is unavailable.
        let upgraded: CrsGenMetadataInner = q126
            .clone()
            .upgrade()
            .unwrap()
            .upgrade()
            .unwrap()
            .upgrade()
            .unwrap();
        assert_eq!(upgraded.extra_data, None);
        assert!(upgraded.signatures.is_empty());
        assert_eq!(upgraded.eip712_domain, None);
        // Upgraded serialization
        let upgraded_bytes = bc2wrap::serialize(&upgraded).unwrap();

        let deserialized_upgraded: CrsGenMetadataInner =
            bc2wrap::deserialize_slice(&upgraded_bytes).unwrap();
        assert_eq!(deserialized_upgraded.extra_data, None);
        assert_eq!(deserialized_upgraded.crs_id, q126.crs_id);
        assert_eq!(deserialized_upgraded.max_num_bits, q126.max_num_bits);
        assert_eq!(&deserialized_upgraded.crs_digest, &q126.crs_digest);
        assert_eq!(
            deserialized_upgraded.external_signature,
            q126.external_signature
        );
    }
}
