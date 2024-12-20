use super::signcryption::{
    internal_verify_sig, safe_serialize_hash_element_versioned, sign, signcrypt,
};
use super::{
    internal_crypto_types::{PrivateSigKey, PublicEncKey, PublicSigKey},
    signcryption::hash_element,
};
use crate::consts::RND_SIZE;
use crate::cryptography::decompression;
use crate::cryptography::signcryption::Reencrypt;
use crate::kms::FheType;
use crate::kms::ReencryptionRequest;
#[cfg(feature = "non-wasm")]
use crate::kms::RequestId;
use crate::kms::{TypedCiphertext, VerifyProvenCtResponsePayload};
use crate::rpc::rpc_types::compute_external_pubdata_signature;
#[cfg(feature = "non-wasm")]
use crate::rpc::rpc_types::SignedPubDataHandleInternal;
use crate::rpc::rpc_types::{
    BaseKms, Kms, Plaintext, PrivDataType, PubDataType, SigncryptionPayload,
};
#[cfg(feature = "non-wasm")]
use crate::util::key_setup::{FhePrivateKey, FhePublicKey};
use crate::util::meta_store::MetaStore;
use crate::util::rate_limiter::{RateLimiter, RateLimiterConfig};
#[cfg(feature = "non-wasm")]
use crate::vault::storage::Storage;
use crate::vault::storage::{
    crypto_material::CentralizedCryptoMaterialStorage, read_all_data_versioned,
    read_pk_at_request_id,
};
use crate::{anyhow_error_and_log, get_exactly_one};
use crate::{consts::ID_LENGTH, cryptography::signcryption::check_normalized};
use crate::{
    consts::{DEC_CAPACITY, MIN_DEC_CACHE},
    cryptography::internal_crypto_types::Signature,
};
use aes_prng::AesRng;
use alloy_primitives::B256;
use alloy_sol_types::SolStruct;
use anyhow::Context;
use bincode::serialize;
#[cfg(feature = "non-wasm")]
use distributed_decryption::execution::endpoints::keygen::FhePubKeySet;
use distributed_decryption::execution::tfhe_internals::parameters::DKGParams;
#[cfg(feature = "non-wasm")]
use distributed_decryption::execution::zk::ceremony::make_centralized_public_parameters;
use k256::ecdsa::SigningKey;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::{fmt, panic};
use tfhe::integer::compression_keys::DecompressionKey;
use tfhe::named::Named;
use tfhe::prelude::FheDecrypt;
#[cfg(feature = "non-wasm")]
use tfhe::zk::CompactPkePublicParams;
#[cfg(feature = "non-wasm")]
use tfhe::Seed;
use tfhe::ServerKey;
use tfhe_versionable::VersionsDispatch;

use tfhe::shortint::ClassicPBSParameters;
use tfhe::{
    ClientKey, ConfigBuilder, FheBool, FheUint1024, FheUint128, FheUint16, FheUint160, FheUint2048,
    FheUint256, FheUint32, FheUint4, FheUint512, FheUint64, FheUint8, Versionize,
};
use tokio::sync::{Mutex, RwLock};

// TODO: we should organize our code so that we can unit test our error messages
const ERR_CLIENT_ADDR_EQ_CONTRACT_ADDR: &str =
    "client address is the same as verifying contract address";

pub fn handle_potential_err<T, E>(resp: Result<T, E>, error: String) -> anyhow::Result<T> {
    resp.map_err(|_| {
        tracing::warn!(error);
        anyhow::Error::msg(format!("Invalid request: \"{}\"", error))
    })
}

#[cfg(feature = "non-wasm")]
pub fn gen_sig_keys<R: CryptoRng + Rng>(rng: &mut R) -> (PublicSigKey, PrivateSigKey) {
    let sk = SigningKey::random(rng);
    let pk = SigningKey::verifying_key(&sk);
    (PublicSigKey::new(*pk), PrivateSigKey::new(sk))
}

#[cfg(feature = "non-wasm")]
pub async fn async_generate_fhe_keys(
    sk: &PrivateSigKey,
    params: DKGParams,
    seed: Option<Seed>,
    eip712_domain: Option<&alloy_sol_types::Eip712Domain>,
) -> anyhow::Result<(FhePubKeySet, KmsFheKeyHandles)> {
    let (send, recv) = tokio::sync::oneshot::channel();
    let sk_copy = sk.to_owned();
    let eip712_domain_copy = eip712_domain.cloned();

    rayon::spawn(move || {
        let out = generate_fhe_keys(&sk_copy, params, seed, eip712_domain_copy.as_ref());
        let _ = send.send(out);
    });
    recv.await.map_err(|e| anyhow::anyhow!(e.to_string()))?
}

#[cfg(feature = "non-wasm")]
pub async fn async_generate_crs(
    sk: &PrivateSigKey,
    rng: AesRng,
    params: DKGParams,
    max_num_bits: Option<u32>,
    eip712_domain: Option<&alloy_sol_types::Eip712Domain>,
) -> anyhow::Result<(CompactPkePublicParams, SignedPubDataHandleInternal)> {
    let (send, recv) = tokio::sync::oneshot::channel();
    let sk_copy = sk.to_owned();
    let eip712_domain_copy = eip712_domain.cloned();

    rayon::spawn(move || {
        let out = gen_centralized_crs(
            &sk_copy,
            &params,
            max_num_bits,
            rng,
            eip712_domain_copy.as_ref(),
        );
        let _ = send.send(out);
    });
    recv.await?
}

#[cfg(feature = "non-wasm")]
pub fn generate_fhe_keys(
    sk: &PrivateSigKey,
    params: DKGParams,
    seed: Option<Seed>,
    eip712_domain: Option<&alloy_sol_types::Eip712Domain>,
) -> anyhow::Result<(FhePubKeySet, KmsFheKeyHandles)> {
    let f = || -> anyhow::Result<(FhePubKeySet, KmsFheKeyHandles)> {
        let client_key = generate_client_fhe_key(params, seed);
        let server_key = client_key.generate_server_key();
        let server_key = server_key.into_raw_parts();
        let decompression_key = server_key.3.clone();
        let server_key = ServerKey::from_raw_parts(
            server_key.0,
            server_key.1,
            server_key.2,
            server_key.3,
            server_key.4,
        );
        let public_key = FhePublicKey::new(&client_key);
        let pks = FhePubKeySet {
            public_key,
            server_key,
            sns_key: None,
        };
        let handles =
            KmsFheKeyHandles::new(sk, client_key, &pks, decompression_key, eip712_domain)?;
        Ok((pks, handles))
    };
    match panic::catch_unwind(f) {
        Ok(x) => x,
        Err(_) => Err(anyhow_error_and_log(
            "FHE key generation panicked!".to_string(),
        )),
    }
}

#[cfg(feature = "non-wasm")]
pub fn generate_client_fhe_key(params: DKGParams, seed: Option<Seed>) -> ClientKey {
    let pbs_params: ClassicPBSParameters = params
        .get_params_basics_handle()
        .to_classic_pbs_parameters();
    let compression_params = params
        .get_params_basics_handle()
        .get_compression_decompression_params();
    let config = ConfigBuilder::with_custom_parameters(pbs_params);
    let config = if let Some(dedicated_pk_params) =
        params.get_params_basics_handle().get_dedicated_pk_params()
    {
        config.use_dedicated_compact_public_key_parameters(dedicated_pk_params)
    } else {
        config
    };
    let config = if let Some(params) = compression_params {
        config.enable_compression(params.raw_compression_parameters)
    } else {
        config
    };
    match seed {
        Some(seed) => ClientKey::generate_with_seed(config, seed),
        None => ClientKey::generate(config),
    }
}

/// compute the CRS in the centralized KMS.
#[cfg(feature = "non-wasm")]
pub(crate) fn gen_centralized_crs<R: Rng + CryptoRng>(
    sk: &PrivateSigKey,
    params: &DKGParams,
    max_num_bits: Option<u32>,
    mut rng: R,
    eip712_domain: Option<&alloy_sol_types::Eip712Domain>,
) -> anyhow::Result<(CompactPkePublicParams, SignedPubDataHandleInternal)> {
    let internal_pp = make_centralized_public_parameters(
        &params
            .get_params_basics_handle()
            .get_compact_pk_enc_params(),
        max_num_bits.map(|x| x as usize),
        &mut rng,
    )?;
    let pke_params = params
        .get_params_basics_handle()
        .get_compact_pk_enc_params();
    let pp = internal_pp.try_into_tfhe_zk_pok_pp(&pke_params)?;
    let crs_info = compute_info(sk, &pp, eip712_domain)?;
    Ok((pp, crs_info))
}

pub struct BaseKmsStruct {
    pub(crate) sig_key: Arc<PrivateSigKey>,
    pub(crate) serialized_verf_key: Arc<Vec<u8>>,
    pub(crate) rng: Arc<Mutex<AesRng>>,
}

impl BaseKmsStruct {
    pub fn new(sig_key: PrivateSigKey) -> anyhow::Result<Self> {
        let serialized_verf_key = Arc::new(serialize(&PublicSigKey::new(
            SigningKey::verifying_key(sig_key.sk()).to_owned(),
        ))?);
        Ok(BaseKmsStruct {
            sig_key: Arc::new(sig_key),
            serialized_verf_key,
            rng: Arc::new(Mutex::new(AesRng::from_entropy())),
        })
    }

    /// Make a clone of this struct with a newly initialized RNG s.t. that both the new and old struct are safe to use.
    pub async fn new_instance(&self) -> Self {
        Self {
            sig_key: self.sig_key.clone(),
            serialized_verf_key: self.serialized_verf_key.clone(),
            rng: Arc::new(Mutex::new(self.new_rng().await)),
        }
    }

    pub async fn new_rng(&self) -> AesRng {
        let mut seed = [0u8; RND_SIZE];
        // Make a seperate scope for the rng so that it is dropped before the lock is released
        {
            let mut base_rng = self.rng.lock().await;
            base_rng.fill_bytes(seed.as_mut());
        }
        AesRng::from_seed(seed)
    }
}

impl BaseKms for BaseKmsStruct {
    fn verify_sig<T>(
        payload: &T,
        signature: &super::internal_crypto_types::Signature,
        key: &PublicSigKey,
    ) -> anyhow::Result<()>
    where
        T: Serialize + AsRef<[u8]>,
    {
        internal_verify_sig(&payload, signature, key)
    }

    /// sign `msg` using the KMS' private signing key
    fn sign<T>(&self, msg: &T) -> anyhow::Result<super::internal_crypto_types::Signature>
    where
        T: Serialize + AsRef<[u8]>,
    {
        sign(msg, &self.sig_key)
    }

    fn get_serialized_verf_key(&self) -> Vec<u8> {
        self.serialized_verf_key.as_ref().clone()
    }

    fn digest<T>(msg: &T) -> anyhow::Result<Vec<u8>>
    where
        T: ?Sized + AsRef<[u8]>,
    {
        Ok(hash_element(msg))
    }
}

/// Verify the EIP-712 encoded payload in the request.
///
/// Fist we need to extract the client public key from the signature.
/// Then the public key is converted into an address and we check
/// whether the address matches the address in the request.
/// We assume the `domain` is trusted since tkms core does not run a light client.
pub(crate) fn verify_reencryption_eip712(request: &ReencryptionRequest) -> anyhow::Result<()> {
    let payload = request
        .payload
        .as_ref()
        .context("Failed to get payload from ReencryptionRequest")?;
    let signature_bytes = &request.signature;

    // print out the req.signature in hex string
    tracing::debug!("🔒 req.signature: {:?}", hex::encode(signature_bytes));

    let client_address =
        alloy_primitives::Address::parse_checksummed(&payload.client_address, None)?;

    // print out the client address
    // note that the alloy address should format to hex already
    tracing::debug!("🔒 client address in payload: {:?}", client_address);

    let enc_key_bytes = payload.enc_key.clone();
    // print out the hex string of the enc_key_bytes
    tracing::debug!("🔒 enc_key_bytes: {:?}", hex::encode(&enc_key_bytes));

    let message = Reencrypt {
        publicKey: alloy_primitives::Bytes::copy_from_slice(&payload.enc_key),
    };

    let wrapped_domain = request
        .domain
        .as_ref()
        .context("Failed to get domain message from request")?;
    tracing::debug!("🔒 wrapped_domain: {:?}", wrapped_domain);

    let chain_id = alloy_primitives::U256::try_from_be_slice(&wrapped_domain.chain_id)
        .context("invalid chain ID")?;
    tracing::debug!("🔒 chain_id: {:?}", chain_id);
    let verifying_contract_address = alloy_primitives::Address::parse_checksummed(
        wrapped_domain.verifying_contract.as_str(),
        None,
    )
    .context("Failed to convert wrappted domain message into address")?;

    let domain = alloy_sol_types::Eip712Domain::new(
        Some(wrapped_domain.name.clone().into()),
        Some(wrapped_domain.version.clone().into()),
        Some(chain_id),
        Some(verifying_contract_address),
        wrapped_domain
            .salt
            .as_ref()
            .map(|inner_salt| B256::from_slice(inner_salt)),
    );

    // this is to prevent malicious dapp
    if client_address == verifying_contract_address {
        return Err(anyhow_error_and_log(ERR_CLIENT_ADDR_EQ_CONTRACT_ADDR));
    }

    // Derive the EIP-712 signing hash.
    let message_hash = message.eip712_signing_hash(&domain);

    // We need to use the alloy signature type since
    // it will let us call `recover_address_from_prehash` later
    // but this signature cannot be wrapper into our own `Signature`
    // type since our own type uses k256::ecdsa, which is not the same
    // as the one in alloy.
    let alloy_signature = alloy_primitives::Signature::try_from(signature_bytes.as_slice())
        .inspect_err(|e| tracing::error!("Failed to parse alloy signature with error: {e}"))?;

    check_normalized(&Signature {
        sig: alloy_signature.to_k256()?,
    })?;

    let recovered_address = alloy_signature.recover_address_from_prehash(&message_hash)?;
    tracing::debug!("🔒 Recovered address: {:?}", recovered_address);

    // Note that `recover_from_prehash` also verifies the signature
    let recovered_verifying_key = alloy_signature.recover_from_prehash(&message_hash)?;
    tracing::debug!("🔒 Recovered verifying key: {:?}", recovered_verifying_key);
    let client_address_from_key =
        alloy_primitives::Address::from_public_key(&recovered_verifying_key);

    let consistent_public_key = client_address_from_key == client_address;
    if !consistent_public_key {
        return Err(anyhow::anyhow!("address is not consistent"));
    }
    Ok(())
}

// We only need to derive (de)serialize for test, which is why they're under a cfg_attr.
#[cfg(feature = "non-wasm")]
#[cfg_attr(any(test, feature = "testing"), derive(Serialize, Deserialize))]
pub struct SoftwareKmsKeys {
    pub(crate) key_info: HashMap<RequestId, KmsFheKeyHandles>,
    pub(crate) sig_sk: PrivateSigKey,
    pub(crate) sig_pk: PublicSigKey,
}

// We only need to derive (de)serialize for test, which is why they're under a cfg_attr.
#[cfg(test)]
#[cfg_attr(any(test, feature = "testing"), derive(Serialize, Deserialize))]
pub struct CentralizedTestingKeys {
    pub params: DKGParams,
    pub software_kms_keys: SoftwareKmsKeys,
    pub pub_fhe_keys: HashMap<RequestId, FhePubKeySet>,
    pub client_pk: PublicSigKey,
    pub client_sk: PrivateSigKey,
    pub server_keys: Vec<PublicSigKey>,
}

#[cfg(feature = "non-wasm")]
#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum KmsFheKeyHandlesVersioned {
    V0(KmsFheKeyHandles),
}

/// This is a data structure that holds the private key material
/// of the centralized KMS.
#[cfg(feature = "non-wasm")]
#[derive(Clone, Serialize, Deserialize, Versionize, Debug)]
#[versionize(KmsFheKeyHandlesVersioned)]
pub struct KmsFheKeyHandles {
    pub client_key: FhePrivateKey,
    pub decompression_key: Option<DecompressionKey>,
    /// Mapping key type to information
    pub public_key_info: HashMap<PubDataType, SignedPubDataHandleInternal>,
}

impl Named for KmsFheKeyHandles {
    const NAME: &'static str = "KmsFheKeyHandles";
}

#[cfg(feature = "non-wasm")]
impl KmsFheKeyHandles {
    /// Compute key handles for the public key materials.
    /// Note that the handles include a signature on the versionized keys.
    pub fn new(
        sig_key: &PrivateSigKey,
        client_key: FhePrivateKey,
        public_keys: &FhePubKeySet,
        decompression_key: Option<DecompressionKey>,
        eip712_domain: Option<&alloy_sol_types::Eip712Domain>,
    ) -> anyhow::Result<Self> {
        let mut public_key_info = HashMap::new();
        public_key_info.insert(
            PubDataType::PublicKey,
            compute_info(sig_key, &public_keys.public_key, eip712_domain)?,
        );
        public_key_info.insert(
            PubDataType::ServerKey,
            compute_info(sig_key, &public_keys.server_key, eip712_domain)?,
        );
        if let Some(sns) = &public_keys.sns_key {
            public_key_info.insert(
                PubDataType::SnsKey,
                compute_info(sig_key, sns, eip712_domain)?,
            );
        }
        Ok(KmsFheKeyHandles {
            client_key,
            decompression_key,
            public_key_info,
        })
    }
}

// Values that need to be stored temporarily as part of an async key generation call.
#[cfg(feature = "non-wasm")]
pub type KeyGenCallValues = HashMap<PubDataType, SignedPubDataHandleInternal>;

// Values that need to be stored temporarily as part of an async decryption call.
// Represents the digest of the request and the result of the decryption (a batch of plaintests),
// as well as an external signature on the batch.
#[cfg(feature = "non-wasm")]
pub type DecCallValues = (Vec<u8>, Vec<Plaintext>, Vec<u8>);

// Values that need to be stored temporarily as part of an async reencryption call.
// Represents the FHE type, the digest of the request and the partial decryption.
#[cfg(feature = "non-wasm")]
pub type ReencCallValues = (FheType, Vec<u8>, Vec<u8>);

/// Software based KMS where keys are stored in a local file
/// Observe that the order of write access MUST be as follows to avoid dead locks:
/// PublicStorage -> PrivateStorage -> FheKeys/XXX_meta_map
#[cfg(feature = "non-wasm")]
pub struct SoftwareKms<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
> {
    pub(crate) base_kms: BaseKmsStruct,
    pub(crate) crypto_storage: CentralizedCryptoMaterialStorage<PubS, PrivS, BackS>,
    // Map storing ongoing key generation requests.
    pub(crate) key_meta_map: Arc<RwLock<MetaStore<KeyGenCallValues>>>,
    // Map storing ongoing decryption requests.
    pub(crate) dec_meta_store: Arc<RwLock<MetaStore<DecCallValues>>>,
    // Map storing ongoing reencryption requests.
    pub(crate) reenc_meta_map: Arc<RwLock<MetaStore<ReencCallValues>>>,
    // Map storing ongoing CRS generation requests.
    pub(crate) crs_meta_map: Arc<RwLock<MetaStore<SignedPubDataHandleInternal>>>,
    // Map storing the completed proven ciphertext verification tasks.
    pub(crate) proven_ct_payload_meta_map: Arc<RwLock<MetaStore<VerifyProvenCtResponsePayload>>>,
    // Rate limiting
    pub(crate) rate_limiter: RateLimiter,
}

/// Perform asynchronous decryption and serialize the result
#[cfg(feature = "non-wasm")]
pub fn central_decrypt<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
    BackS: Storage + Sync + Send + 'static,
>(
    keys: &KmsFheKeyHandles,
    cts: &Vec<TypedCiphertext>,
) -> anyhow::Result<Vec<Plaintext>> {
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

    tracing::info!("Decrypting list of cipher-texts");
    // run the decryption of each ct in the batch in parallel
    cts.par_iter()
        .map(|ct| {
            SoftwareKms::<PubS, PrivS, BackS>::decrypt(
                keys,
                &ct.ciphertext,
                FheType::try_from(ct.fhe_type)?,
            )
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Perform asynchronous reencryption and serialize the result
#[cfg(feature = "non-wasm")]
#[allow(clippy::too_many_arguments)]
pub async fn async_reencrypt<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
    BackS: Storage + Sync + Send + 'static,
>(
    keys: &KmsFheKeyHandles,
    sig_key: &PrivateSigKey,
    rng: &mut (impl CryptoRng + RngCore),
    high_level_ct: &[u8],
    fhe_type: FheType,
    req_digest: &[u8],
    client_enc_key: &PublicEncKey,
    client_address: &alloy_primitives::Address,
) -> anyhow::Result<Vec<u8>> {
    SoftwareKms::<PubS, PrivS, BackS>::reencrypt(
        keys,
        sig_key,
        rng,
        high_level_ct,
        fhe_type,
        req_digest,
        client_enc_key,
        client_address,
    )
}

// impl fmt::Debug for SoftwareKms, we don't want to include the decryption key in the debug output
#[cfg(feature = "non-wasm")]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    > fmt::Debug for SoftwareKms<PubS, PrivS, BackS>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareKms")
            .field("sig_key", &self.base_kms.sig_key)
            .finish() // Don't include fhe_dec_key
    }
}

#[cfg(feature = "non-wasm")]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    > BaseKms for SoftwareKms<PubS, PrivS, BackS>
{
    fn verify_sig<T: Serialize + AsRef<[u8]>>(
        payload: &T,
        signature: &super::internal_crypto_types::Signature,
        verification_key: &PublicSigKey,
    ) -> anyhow::Result<()> {
        BaseKmsStruct::verify_sig(payload, signature, verification_key)
    }

    fn sign<T: Serialize + AsRef<[u8]>>(
        &self,
        msg: &T,
    ) -> anyhow::Result<super::internal_crypto_types::Signature> {
        self.base_kms.sign(msg)
    }

    fn get_serialized_verf_key(&self) -> Vec<u8> {
        self.base_kms.get_serialized_verf_key()
    }

    fn digest<T: ?Sized + AsRef<[u8]>>(msg: &T) -> anyhow::Result<Vec<u8>> {
        BaseKmsStruct::digest(&msg)
    }
}

fn unsafe_decrypt(
    keys: &KmsFheKeyHandles,
    bytes_ct: &[u8],
    fhe_type: FheType,
) -> anyhow::Result<Plaintext> {
    Ok(match fhe_type {
        FheType::Ebool => Plaintext::from_bool(
            decompression::from_bytes::<FheBool>(&keys.decompression_key, bytes_ct)?
                .decrypt(&keys.client_key),
        ),
        FheType::Euint4 => Plaintext::from_u4(
            decompression::from_bytes::<FheUint4>(&keys.decompression_key, bytes_ct)?
                .decrypt(&keys.client_key),
        ),
        FheType::Euint8 => Plaintext::from_u8(
            decompression::from_bytes::<FheUint8>(&keys.decompression_key, bytes_ct)?
                .decrypt(&keys.client_key),
        ),
        FheType::Euint16 => Plaintext::from_u16(
            decompression::from_bytes::<FheUint16>(&keys.decompression_key, bytes_ct)?
                .decrypt(&keys.client_key),
        ),
        FheType::Euint32 => Plaintext::from_u32(
            decompression::from_bytes::<FheUint32>(&keys.decompression_key, bytes_ct)?
                .decrypt(&keys.client_key),
        ),
        FheType::Euint64 => Plaintext::from_u64(
            decompression::from_bytes::<FheUint64>(&keys.decompression_key, bytes_ct)?
                .decrypt(&keys.client_key),
        ),
        FheType::Euint128 => Plaintext::from_u128(
            decompression::from_bytes::<FheUint128>(&keys.decompression_key, bytes_ct)?
                .decrypt(&keys.client_key),
        ),
        FheType::Euint160 => Plaintext::from_u160(
            decompression::from_bytes::<FheUint160>(&keys.decompression_key, bytes_ct)?
                .decrypt(&keys.client_key),
        ),
        FheType::Euint256 => Plaintext::from_u256(
            decompression::from_bytes::<FheUint256>(&keys.decompression_key, bytes_ct)?
                .decrypt(&keys.client_key),
        ),
        FheType::Euint512 => Plaintext::from_u512(
            decompression::from_bytes::<FheUint512>(&keys.decompression_key, bytes_ct)?
                .decrypt(&keys.client_key),
        ),
        FheType::Euint1024 => Plaintext::from_u1024(
            decompression::from_bytes::<FheUint1024>(&keys.decompression_key, bytes_ct)?
                .decrypt(&keys.client_key),
        ),
        FheType::Euint2048 => Plaintext::from_u2048(
            decompression::from_bytes::<FheUint2048>(&keys.decompression_key, bytes_ct)?
                .decrypt(&keys.client_key),
        ),
    })
}

#[cfg(feature = "non-wasm")]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    > Kms for SoftwareKms<PubS, PrivS, BackS>
{
    fn decrypt(
        keys: &KmsFheKeyHandles,
        high_level_ct: &[u8],
        fhe_type: FheType,
    ) -> anyhow::Result<Plaintext> {
        match panic::catch_unwind(|| unsafe_decrypt(keys, high_level_ct, fhe_type)) {
            Ok(x) => x,
            Err(_) => Err(anyhow_error_and_log("decryption panicked".to_string())),
        }
    }

    fn reencrypt(
        keys: &KmsFheKeyHandles,
        sig_key: &PrivateSigKey,
        rng: &mut (impl CryptoRng + RngCore),
        ct: &[u8],
        fhe_type: FheType,
        link: &[u8],
        client_enc_key: &PublicEncKey,
        client_address: &alloy_primitives::Address,
    ) -> anyhow::Result<Vec<u8>> {
        let plaintext = Self::decrypt(keys, ct, fhe_type)?;
        // Observe that we encrypt the plaintext itself, this is different from the threshold case
        // where it is first mapped to a Vec<ResiduePolyF8<Z128>> element
        let signcryption_msg = SigncryptionPayload {
            plaintext,
            link: link.to_vec(),
        };
        let enc_res = signcrypt(
            rng,
            &serialize(&signcryption_msg)?,
            client_enc_key,
            client_address,
            sig_key,
        )?;
        let res = serialize(&enc_res)?;
        tracing::info!("Completed reencryption of ciphertext");
        Ok(res)
    }
}

#[cfg(feature = "non-wasm")]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    > SoftwareKms<PubS, PrivS, BackS>
{
    pub async fn new(
        public_storage: PubS,
        private_storage: PrivS,
        backup_storage: Option<BackS>,
        rate_limiter_conf: Option<RateLimiterConfig>,
    ) -> anyhow::Result<Self> {
        let sks: HashMap<RequestId, PrivateSigKey> =
            read_all_data_versioned(&private_storage, &PrivDataType::SigningKey.to_string())
                .await?;
        let sk = get_exactly_one(sks).inspect_err(|_e| {
            tracing::error!("signing key hashmap is not exactly 1");
        })?;

        // compute corresponding public key and derive address from private sig key
        let pk = SigningKey::verifying_key(sk.sk());
        tracing::info!(
            "Public address is {}",
            alloy_signer::utils::public_key_to_address(pk)
        );

        let key_info: HashMap<RequestId, KmsFheKeyHandles> =
            read_all_data_versioned(&private_storage, &PrivDataType::FheKeyInfo.to_string())
                .await?;
        let mut pk_map = HashMap::new();
        for id in key_info.keys() {
            let public_key = read_pk_at_request_id(&public_storage, id).await?;
            pk_map.insert(id.clone(), public_key);
        }
        tracing::info!(
            "loaded key_info with key_ids: {:?}",
            key_info
                .keys()
                .map(|rid| &rid.request_id)
                .collect::<Vec<_>>()
        );
        let public_key_info = key_info
            .iter()
            .map(|(id, info)| (id.to_owned(), info.public_key_info.to_owned()))
            .collect();
        let crs_info: HashMap<RequestId, SignedPubDataHandleInternal> =
            read_all_data_versioned(&private_storage, &PrivDataType::CrsInfo.to_string()).await?;

        // read the CRS
        let crs: HashMap<RequestId, CompactPkePublicParams> =
            read_all_data_versioned(&public_storage, &PubDataType::CRS.to_string()).await?;

        let crypto_storage = CentralizedCryptoMaterialStorage::new(
            public_storage,
            private_storage,
            backup_storage,
            pk_map,
            crs,
            key_info,
        );

        Ok(SoftwareKms {
            base_kms: BaseKmsStruct::new(sk)?,
            crypto_storage,
            key_meta_map: Arc::new(RwLock::new(MetaStore::new_from_map(public_key_info))),
            dec_meta_store: Arc::new(RwLock::new(MetaStore::new(DEC_CAPACITY, MIN_DEC_CACHE))),
            reenc_meta_map: Arc::new(RwLock::new(MetaStore::new(DEC_CAPACITY, MIN_DEC_CACHE))),
            crs_meta_map: Arc::new(RwLock::new(MetaStore::new_from_map(crs_info))),
            proven_ct_payload_meta_map: Arc::new(RwLock::new(MetaStore::new(
                DEC_CAPACITY,
                MIN_DEC_CACHE,
            ))),
            rate_limiter: RateLimiter::new(rate_limiter_conf.unwrap_or_default()),
        })
    }
}

/// Computes the public into on a serializable `element`.
/// More specifically, computes the unique handle of the `element` and signs this handle using the
/// `kms`.
pub(crate) fn compute_info<S: Serialize + Versionize + Named>(
    sk: &PrivateSigKey,
    element: &S,
    domain: Option<&alloy_sol_types::Eip712Domain>,
) -> anyhow::Result<SignedPubDataHandleInternal> {
    let handle = compute_handle(element)?;
    let signature = sign(&handle, sk)?;

    // if we get an EIP-712 domain, compute the external signature
    let external_signature = match domain {
        Some(domain) => compute_external_pubdata_signature(sk, element, domain)?,
        None => {
            tracing::warn!("Skipping external signature computation due to missing domain");
            vec![]
        }
    };

    Ok(SignedPubDataHandleInternal {
        key_handle: handle,
        signature: serialize(&signature)?,
        external_signature,
    })
}

/// Compute a handle of an element, based on its digest
/// More specifically compute the hash digest, truncate it and convert it to a hex string
pub fn compute_handle<S>(element: &S) -> anyhow::Result<String>
where
    S: Serialize + Versionize + Named,
{
    let mut digest = safe_serialize_hash_element_versioned(element)?;
    // Truncate and convert to hex
    digest.truncate(ID_LENGTH);
    Ok(hex::encode(digest))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{verify_reencryption_eip712, Storage};
    #[cfg(feature = "slow_tests")]
    use crate::consts::{
        DEFAULT_CENTRAL_KEYS_PATH, DEFAULT_CENTRAL_KEY_ID, DEFAULT_PARAM, OTHER_CENTRAL_DEFAULT_ID,
    };
    use crate::consts::{DEFAULT_THRESHOLD_KEY_ID_4P, OTHER_CENTRAL_TEST_ID, TEST_CENTRAL_KEY_ID};
    use crate::consts::{TEST_CENTRAL_KEYS_PATH, TEST_PARAM};
    use crate::cryptography::central_kms::SoftwareKmsKeys;
    use crate::cryptography::central_kms::{gen_sig_keys, SoftwareKms};
    use crate::cryptography::central_kms::{
        CentralizedTestingKeys, ERR_CLIENT_ADDR_EQ_CONTRACT_ADDR,
    };
    use crate::cryptography::internal_crypto_types::PrivateSigKey;
    use crate::cryptography::signcryption::{
        decrypt_signcryption, ephemeral_encryption_key_generation,
        ephemeral_signcryption_key_generation, hash_element,
    };
    use crate::kms::{FheType, RequestId};
    use crate::rpc::rpc_types::{Kms, CURRENT_FORMAT_VERSION};
    use crate::util::file_handling::read_element;
    use crate::util::key_setup::test_tools::compute_cipher;
    use crate::vault::storage::{file::FileStorage, ram::RamStorage};
    use crate::{cryptography::central_kms::generate_fhe_keys, util::file_handling::write_element};
    use aes_prng::AesRng;
    use alloy_signer::SignerSync;
    use alloy_sol_types::SolStruct;
    use distributed_decryption::execution::tfhe_internals::parameters::DKGParams;
    use rand::{RngCore, SeedableRng};
    use serde::{Deserialize, Serialize};
    use serial_test::serial;
    use std::collections::HashMap;
    use std::{path::Path, sync::Arc};
    use tfhe::named::Named;
    use tfhe::set_server_key;
    use tfhe::Versionize;
    use tfhe::{shortint::ClassicPBSParameters, ConfigBuilder, Seed};
    use tfhe_versionable::VersionsDispatch;
    use tokio::sync::OnceCell;

    static ONCE_TEST_KEY: OnceCell<CentralizedTestingKeys> = OnceCell::const_new();
    async fn get_test_keys() -> &'static CentralizedTestingKeys {
        ONCE_TEST_KEY
            .get_or_init(|| async { ensure_kms_test_keys().await })
            .await
    }

    #[cfg(feature = "slow_tests")]
    static ONCE_DEFAULT_KEY: OnceCell<CentralizedTestingKeys> = OnceCell::const_new();
    #[cfg(feature = "slow_tests")]
    pub(crate) async fn get_default_keys() -> &'static CentralizedTestingKeys {
        ONCE_DEFAULT_KEY
            .get_or_init(|| async { ensure_kms_default_keys().await })
            .await
    }

    #[derive(Clone, PartialEq, Eq)]
    enum SimulationType {
        NoError,
        BadFheKey,
        // below are only used for reencryption
        BadSigKey,
        BadEphemeralKey,
    }

    async fn ensure_kms_test_keys() -> CentralizedTestingKeys {
        setup(
            TEST_PARAM,
            &TEST_CENTRAL_KEY_ID.to_string(),
            &OTHER_CENTRAL_TEST_ID.to_string(),
            TEST_CENTRAL_KEYS_PATH,
        )
        .await
    }

    #[cfg(feature = "slow_tests")]
    pub(crate) async fn ensure_kms_default_keys() -> CentralizedTestingKeys {
        setup(
            DEFAULT_PARAM,
            &DEFAULT_CENTRAL_KEY_ID.to_string(),
            &OTHER_CENTRAL_DEFAULT_ID.to_string(),
            DEFAULT_CENTRAL_KEYS_PATH,
        )
        .await
    }

    async fn setup(
        dkg_params: DKGParams,
        key_id: &str,
        other_key_id: &str,
        key_path: &str,
    ) -> CentralizedTestingKeys {
        if Path::new(key_path).exists() {
            return read_element(key_path).await.unwrap();
        }

        let mut rng = AesRng::seed_from_u64(100);
        let seed = Some(Seed(42));
        let (sig_pk, sig_sk) = gen_sig_keys(&mut rng);
        let (pub_fhe_keys, key_info) = generate_fhe_keys(&sig_sk, dkg_params, seed, None).unwrap();
        let mut key_info_map = HashMap::from([(key_id.to_string().try_into().unwrap(), key_info)]);

        let (other_pub_fhe_keys, other_key_info) =
            generate_fhe_keys(&sig_sk, dkg_params, seed, None).unwrap();

        // Insert a key with another handle to setup a KMS with multiple keys
        key_info_map.insert(other_key_id.to_string().try_into().unwrap(), other_key_info);
        let pub_fhe_map = HashMap::from([
            (key_id.to_string().try_into().unwrap(), pub_fhe_keys.clone()),
            (
                other_key_id.to_string().try_into().unwrap(),
                other_pub_fhe_keys,
            ),
        ]);
        let server_keys = vec![sig_pk.clone()];
        let (client_pk, client_sk) = gen_sig_keys(&mut rng);
        let centralized_test_keys = CentralizedTestingKeys {
            params: dkg_params,
            client_pk,
            client_sk,
            server_keys,
            pub_fhe_keys: pub_fhe_map,
            software_kms_keys: SoftwareKmsKeys {
                key_info: key_info_map,
                sig_sk,
                sig_pk,
            },
        };
        assert!(write_element(key_path, &centralized_test_keys)
            .await
            .is_ok());
        centralized_test_keys
    }

    #[tokio::test]
    #[serial(test_keys)]
    async fn multiple_test_keys_access() {
        let central_keys = get_test_keys().await;

        // try to get keys with the default handle
        let default_key = central_keys
            .software_kms_keys
            .key_info
            .get(&TEST_CENTRAL_KEY_ID);
        assert!(default_key.is_some());

        // try to get keys with the some other handle
        let some_key = central_keys
            .software_kms_keys
            .key_info
            .get(&OTHER_CENTRAL_TEST_ID);
        assert!(some_key.is_some());

        // try to get keys with a non-existent handle
        let wrong_key_handle = RequestId::derive("wrongKeyHandle").unwrap();
        let no_key = central_keys
            .software_kms_keys
            .key_info
            .get(&wrong_key_handle);
        assert!(no_key.is_none());
    }

    #[tokio::test]
    #[serial(test_keys)]
    async fn sunshine_test_decrypt() {
        sunshine_decrypt(get_test_keys().await, &TEST_CENTRAL_KEY_ID).await;
    }

    #[tokio::test]
    #[serial(test_keys)]
    async fn decrypt_with_bad_client_key() {
        simulate_decrypt(
            SimulationType::BadFheKey,
            get_test_keys().await,
            &TEST_CENTRAL_KEY_ID,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial(default_keys)]
    async fn sunshine_default_decrypt() {
        sunshine_decrypt(get_default_keys().await, &DEFAULT_CENTRAL_KEY_ID).await;
    }

    #[tokio::test]
    #[serial(test_keys)]
    async fn multiple_test_keys_decrypt() {
        sunshine_decrypt(get_test_keys().await, &OTHER_CENTRAL_TEST_ID).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial(default_keys)]
    async fn multiple_default_keys_decrypt() {
        sunshine_decrypt(get_default_keys().await, &OTHER_CENTRAL_DEFAULT_ID).await;
    }

    async fn sunshine_decrypt(keys: &CentralizedTestingKeys, key_id: &RequestId) {
        simulate_decrypt(SimulationType::NoError, keys, key_id).await;
    }

    async fn simulate_decrypt(
        sim_type: SimulationType,
        keys: &CentralizedTestingKeys,
        key_id: &RequestId,
    ) {
        let msg = 523u64;
        let (ct, fhe_type) = {
            let pub_keys = keys.pub_fhe_keys.get(key_id).unwrap();
            set_server_key(pub_keys.server_key.clone());
            compute_cipher(msg.into(), &pub_keys.public_key, None, false)
        };
        let kms = {
            let inner = SoftwareKms::new(
                RamStorage::from_existing_keys_for_public_storage(&keys.pub_fhe_keys)
                    .await
                    .unwrap(),
                RamStorage::from_existing_keys_for_private_storage(&keys.software_kms_keys)
                    .await
                    .unwrap(),
                None as Option<RamStorage>,
                None,
            )
            .await
            .unwrap();
            if sim_type == SimulationType::BadFheKey {
                set_wrong_client_key(&inner, key_id, keys.params).await;
            }
            inner
        };
        let key_handle = kms
            .crypto_storage
            .read_cloned_centralized_fhe_keys_from_cache(key_id)
            .await
            .unwrap();
        let raw_plaintext = SoftwareKms::<FileStorage, FileStorage, FileStorage>::decrypt(
            &key_handle,
            &ct,
            fhe_type,
        );
        // if bad FHE key is used, then it *might* panic
        let plaintext = if sim_type == SimulationType::BadFheKey {
            match raw_plaintext {
                Ok(x) => x,
                Err(e) => {
                    assert!(e.to_string().contains("decryption panicked"));
                    return;
                }
            }
        } else {
            raw_plaintext.unwrap()
        };
        if sim_type == SimulationType::BadFheKey {
            assert_ne!(plaintext.as_u64(), msg);
        } else {
            assert_eq!(plaintext.as_u64(), msg);
        }

        assert_eq!(plaintext.fhe_type(), FheType::Euint64);
    }

    #[tokio::test]
    async fn sunshine_test_reencrypt() {
        sunshine_reencrypt(get_test_keys().await, &TEST_CENTRAL_KEY_ID).await;
    }

    #[tokio::test]
    async fn reencrypt_with_bad_ephemeral_key() {
        simulate_reencrypt(
            SimulationType::BadEphemeralKey,
            get_test_keys().await,
            &TEST_CENTRAL_KEY_ID,
        )
        .await
    }

    #[tokio::test]
    async fn reencrypt_with_bad_sig_key() {
        simulate_reencrypt(
            SimulationType::BadSigKey,
            get_test_keys().await,
            &TEST_CENTRAL_KEY_ID,
        )
        .await
    }

    #[tokio::test]
    async fn reencrypt_with_bad_client_key() {
        simulate_reencrypt(
            SimulationType::BadFheKey,
            get_test_keys().await,
            &TEST_CENTRAL_KEY_ID,
        )
        .await
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    async fn sunshine_default_reencrypt() {
        sunshine_reencrypt(get_default_keys().await, &DEFAULT_CENTRAL_KEY_ID).await;
    }

    #[tokio::test]
    #[serial]
    async fn multiple_test_keys_reencrypt() {
        sunshine_reencrypt(get_test_keys().await, &OTHER_CENTRAL_TEST_ID).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    async fn multiple_default_keys_reencrypt() {
        sunshine_reencrypt(get_default_keys().await, &OTHER_CENTRAL_DEFAULT_ID).await;
    }

    async fn sunshine_reencrypt(keys: &CentralizedTestingKeys, key_handle: &RequestId) {
        simulate_reencrypt(SimulationType::NoError, keys, key_handle).await
    }

    async fn set_wrong_client_key<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    >(
        inner: &SoftwareKms<PubS, PrivS, BackS>,
        key_handle: &RequestId,
        params: DKGParams,
    ) {
        let pbs_params: ClassicPBSParameters = params
            .get_params_basics_handle()
            .to_classic_pbs_parameters();
        let config = ConfigBuilder::with_custom_parameters(pbs_params);
        let wrong_client_key = tfhe::ClientKey::generate(config);
        inner
            .crypto_storage
            .set_wrong_cached_client_key(key_handle, wrong_client_key)
            .await
            .unwrap();
    }

    fn set_wrong_sig_key<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        BackS: Storage + Sync + Send + 'static,
    >(
        inner: &mut SoftwareKms<PubS, PrivS, BackS>,
        rng: &mut AesRng,
    ) {
        // move to the next state so ensure we're generating a different ecdsa key
        _ = rng.next_u64();
        let wrong_ecdsa_key = k256::ecdsa::SigningKey::random(rng);
        assert_ne!(&wrong_ecdsa_key, inner.base_kms.sig_key.sk());
        inner.base_kms.sig_key = Arc::new(PrivateSigKey::new(wrong_ecdsa_key));
    }

    async fn simulate_reencrypt(
        sim_type: SimulationType,
        keys: &CentralizedTestingKeys,
        key_handle: &RequestId,
    ) {
        let msg = 42305u64;
        let mut rng = AesRng::seed_from_u64(1);
        let (ct, fhe_type) = {
            let pub_keys = keys.pub_fhe_keys.get(key_handle).unwrap();
            set_server_key(pub_keys.server_key.clone());
            compute_cipher(msg.into(), &pub_keys.public_key, None, false)
        };

        let kms = {
            let mut inner = SoftwareKms::new(
                RamStorage::from_existing_keys_for_public_storage(&keys.pub_fhe_keys)
                    .await
                    .unwrap(),
                RamStorage::from_existing_keys_for_private_storage(&keys.software_kms_keys)
                    .await
                    .unwrap(),
                None as Option<RamStorage>,
                None,
            )
            .await
            .unwrap();
            if sim_type == SimulationType::BadFheKey {
                set_wrong_client_key(&inner, key_handle, keys.params).await;
            }
            if sim_type == SimulationType::BadSigKey {
                set_wrong_sig_key(&mut inner, &mut rng);
            }
            inner
        };
        let link = vec![42_u8, 42, 42];
        let (_client_verf_key, client_sig_key) = gen_sig_keys(&mut rng);
        let client_keys = {
            let mut keys = ephemeral_signcryption_key_generation(&mut rng, &client_sig_key);
            if sim_type == SimulationType::BadEphemeralKey {
                let bad_keys = ephemeral_signcryption_key_generation(&mut rng, &client_sig_key);
                keys.sk = bad_keys.sk;
            }
            keys
        };
        let mut rng = kms.base_kms.new_rng().await;
        let raw_cipher = SoftwareKms::<FileStorage, FileStorage, FileStorage>::reencrypt(
            &kms.crypto_storage
                .read_cloned_centralized_fhe_keys_from_cache(key_handle)
                .await
                .unwrap(),
            &kms.base_kms.sig_key,
            &mut rng,
            &ct,
            fhe_type,
            &link,
            &client_keys.pk.enc_key,
            &client_keys.pk.client_address,
        );
        // if bad FHE key is used, then it *might* panic
        let raw_cipher = if sim_type == SimulationType::BadFheKey {
            match raw_cipher {
                Ok(x) => x,
                Err(e) => {
                    assert!(e.to_string().contains("decryption panicked"));
                    return;
                }
            }
        } else {
            raw_cipher.unwrap()
        };
        let decrypted = decrypt_signcryption(
            &raw_cipher,
            &link,
            &client_keys,
            &keys.software_kms_keys.sig_pk,
        );
        if sim_type == SimulationType::BadEphemeralKey {
            assert!(decrypted.is_err());
            assert!(decrypted
                .unwrap_err()
                .to_string()
                .contains("Could not decrypt message"));
            return;
        }
        if sim_type == SimulationType::BadSigKey {
            assert!(decrypted.is_err());
            return;
        }
        let plaintext = decrypted.unwrap();
        if sim_type == SimulationType::BadFheKey {
            assert_ne!(plaintext.as_u64(), msg);
        } else {
            assert_eq!(plaintext.as_u64(), msg);
        }
        assert_eq!(plaintext.fhe_type(), FheType::Euint64);
    }

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug, VersionsDispatch)]
    enum TestTypeVersioned {
        V0(TestType),
    }

    impl Named for TestType {
        const NAME: &'static str = "TestType";
    }

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Versionize)]
    #[versionize(TestTypeVersioned)]
    struct TestType {
        i: u32,
    }

    #[tokio::test]
    async fn ensure_compute_info_consistency() {
        // we need compute info to work without calling the sign function from KMS,
        // i.e., only using a signing key
        // this test makes sure the output is consistent
        let keys = get_test_keys().await;
        let kms = {
            SoftwareKms::new(
                RamStorage::from_existing_keys_for_public_storage(&keys.pub_fhe_keys)
                    .await
                    .unwrap(),
                RamStorage::from_existing_keys_for_private_storage(&keys.software_kms_keys)
                    .await
                    .unwrap(),
                None as Option<RamStorage>,
                None,
            )
            .await
            .unwrap()
        };

        let value = TestType { i: 32 };
        let expected = super::compute_info(&kms.base_kms.sig_key, &value, None).unwrap();
        let actual = super::compute_info(&kms.base_kms.sig_key, &value, None).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_verify_reenc_eip712() {
        let mut rng = AesRng::seed_from_u64(1);
        let (client_pk, client_sk) = gen_sig_keys(&mut rng);
        let client_address = alloy_primitives::Address::from_public_key(client_pk.pk());
        let signer = alloy_signer_local::PrivateKeySigner::from_signing_key(client_sk.sk().clone());
        let ciphertext = vec![1, 2, 3];
        let ciphertext_digest = hash_element(&ciphertext);
        let (enc_pk, _) = ephemeral_encryption_key_generation(&mut rng);
        let key_id = DEFAULT_THRESHOLD_KEY_ID_4P.clone();

        let payload = crate::kms::ReencryptionRequestPayload {
            version: CURRENT_FORMAT_VERSION,
            enc_key: bincode::serialize(&enc_pk).unwrap(),
            client_address: client_address.to_checksum(None),
            fhe_type: 1,
            key_id: Some(key_id),
            ciphertext: Some(ciphertext),
            ciphertext_digest,
        };
        let message = crate::cryptography::signcryption::Reencrypt {
            publicKey: alloy_primitives::Bytes::copy_from_slice(&payload.enc_key),
        };
        let domain = alloy_sol_types::eip712_domain!(
            name: "Authorization token",
            version: "1",
            chain_id: 8006,
            verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
        );

        let message_hash = message.eip712_signing_hash(&domain);
        let signature = signer.sign_hash_sync(&message_hash).unwrap();
        let domain_msg = crate::rpc::rpc_types::alloy_to_protobuf_domain(&domain).unwrap();

        let req = crate::kms::ReencryptionRequest {
            signature: signature.into(),
            payload: Some(payload),
            domain: Some(domain_msg),
            request_id: Some(RequestId {
                request_id: "dummy request ID".to_owned(),
            }),
        };

        {
            // happy path
            verify_reencryption_eip712(&req).unwrap();
        }
        {
            // use a wrong client address (invalid string length)
            let mut bad_payload = req.payload.as_ref().cloned().unwrap();
            bad_payload.client_address = "66f9664f97F2b50F62D13eA064982f936dE76657".to_string();
            let mut bad_req = req.clone();
            bad_req.payload = Some(bad_payload);
            match verify_reencryption_eip712(&bad_req) {
                Ok(_) => panic!("expected failure"),
                Err(e) => {
                    assert_eq!(e.to_string(), "invalid string length");
                }
            }
        }
        {
            // use the same address for verifying contract and client address should fail
            let mut bad_payload = req.payload.as_ref().cloned().unwrap();
            bad_payload.client_address = domain
                .verifying_contract
                .as_ref()
                .cloned()
                .unwrap()
                .to_string();
            let mut bad_req = req.clone();
            bad_req.payload = Some(bad_payload);
            match verify_reencryption_eip712(&bad_req) {
                Ok(_) => panic!("expected failure"),
                Err(e) => {
                    assert!(e.to_string().contains(ERR_CLIENT_ADDR_EQ_CONTRACT_ADDR));
                }
            }
        }
        {
            // bad signature
            let mut bad_req = req.clone();
            bad_req.signature[0] = req.signature[0] ^ 1;
            match verify_reencryption_eip712(&bad_req) {
                Ok(_) => panic!("expected failure"),
                Err(e) => {
                    assert_eq!(e.to_string(), "signature error");
                }
            }
        }
    }
}
