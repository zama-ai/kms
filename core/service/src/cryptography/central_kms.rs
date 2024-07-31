use super::signcryption::{internal_verify_sig, serialize_hash_element, sign, signcrypt, RND_SIZE};
use super::{
    der_types::{PrivateSigKey, PublicEncKey, PublicSigKey},
    signcryption::hash_element,
};
use crate::consts::ID_LENGTH;
use crate::consts::{DEC_CAPACITY, MIN_DEC_CACHE};
use crate::cryptography::der_types::PrivateSigKeyVersioned;
use crate::cryptography::signcryption::Reencrypt;
use crate::kms::ReencryptionRequest;
#[cfg(feature = "non-wasm")]
use crate::kms::RequestId;
use crate::kms::TypedCiphertext;
use crate::rpc::rpc_types::CrsMetaData;
use crate::rpc::rpc_types::{
    BaseKms, Kms, Plaintext, PrivDataType, PubDataType, SigncryptionPayload,
};
use crate::storage::read_all_data;
#[cfg(feature = "non-wasm")]
use crate::storage::Storage;
#[cfg(feature = "non-wasm")]
use crate::util::key_setup::{FhePrivateKey, FhePublicKey};
use crate::util::meta_store::{HandlerStatus, MetaStore};
use crate::{anyhow_error_and_log, some_or_err};
use crate::{
    kms::{FheType, ParamChoice, SignedPubDataHandle},
    rpc::rpc_types::CrsMetaDataVersioned,
};
use aes_prng::AesRng;
use alloy_sol_types::SolStruct;
use anyhow::Context;
use bincode::{deserialize, serialize};
use der::zeroize::Zeroize;
#[cfg(feature = "non-wasm")]
use distributed_decryption::execution::endpoints::keygen::FhePubKeySet;
use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
use distributed_decryption::execution::zk::ceremony::{make_proof_deterministic, PublicParameter};
use itertools::Itertools;
use k256::ecdsa::SigningKey;
use kms_core_common::{Unversionize, Versioned, Versionize};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use std::{borrow::Cow, collections::HashMap};
use std::{fmt, panic};
use tfhe::integer::bigint::U2048;
use tfhe::integer::U256;
use tfhe::prelude::FheDecrypt;

use tfhe::shortint::ClassicPBSParameters;
use tfhe::{
    ClientKey, ConfigBuilder, FheBool, FheUint128, FheUint16, FheUint160, FheUint2048, FheUint256,
    FheUint32, FheUint4, FheUint64, FheUint8,
};
#[cfg(feature = "non-wasm")]
use tfhe_zk_pok::curve_api::bls12_446 as curve;
use tokio::sync::{Mutex, RwLock};

pub(crate) fn handle_potential_err<T, E>(resp: Result<T, E>, error: String) -> anyhow::Result<T> {
    resp.map_err(|_| {
        tracing::warn!(error);
        anyhow::Error::msg(format!("Invalid request: \"{}\"", error))
    })
}

#[cfg(feature = "non-wasm")]
pub fn gen_sig_keys<R: CryptoRng + Rng>(rng: &mut R) -> (PublicSigKey, PrivateSigKey) {
    let sk = SigningKey::random(rng);
    let pk = SigningKey::verifying_key(&sk);
    (PublicSigKey { pk: *pk }, PrivateSigKey { sk })
}

#[cfg(feature = "non-wasm")]
pub async fn async_generate_fhe_keys(
    sk: &PrivateSigKey,
    params: NoiseFloodParameters,
) -> anyhow::Result<(FhePubKeySet, KmsFheKeyHandles)> {
    let (send, recv) = tokio::sync::oneshot::channel();
    let sk_copy = sk.to_owned();
    rayon::spawn(move || {
        let out = generate_fhe_keys(&sk_copy, params);
        let _ = send.send(out);
    });
    recv.await.map_err(|e| anyhow::anyhow!(e.to_string()))?
}

#[cfg(feature = "non-wasm")]
pub async fn async_generate_crs(
    sk: &PrivateSigKey,
    rng: AesRng,
    params: NoiseFloodParameters,
) -> anyhow::Result<(PublicParameter, CrsMetaData)> {
    let (send, recv) = tokio::sync::oneshot::channel();
    let sk_copy = sk.to_owned();
    rayon::spawn(move || {
        let out = gen_centralized_crs(&sk_copy, &params, rng);
        let _ = send.send(out);
    });
    recv.await?
}

//TODO(PKSK): Need to change this function when we want KMS to support the new parameters
//that involve a new set of dedicated encryption keys and corresponding PKSK
//also requires moving away from NoiseFloodParameters and use DKGParams everywhere
#[cfg(feature = "non-wasm")]
pub fn generate_fhe_keys(
    sk: &PrivateSigKey,
    params: NoiseFloodParameters,
) -> anyhow::Result<(FhePubKeySet, KmsFheKeyHandles)> {
    let f = || -> anyhow::Result<(FhePubKeySet, KmsFheKeyHandles)> {
        let client_key = generate_client_fhe_key(params);
        let server_key = client_key.generate_server_key();
        let public_key = FhePublicKey::new(&client_key);
        let pks = FhePubKeySet {
            public_key,
            server_key,
            sns_key: None,
        };
        let handles = KmsFheKeyHandles::new(sk, client_key, &pks)?;
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
pub fn generate_client_fhe_key(params: NoiseFloodParameters) -> ClientKey {
    let pbs_params: ClassicPBSParameters = params.ciphertext_parameters;
    let config = ConfigBuilder::with_custom_parameters(pbs_params);
    ClientKey::generate(config)
}

/// compute the CRS in the centralized KMS.
#[cfg(feature = "non-wasm")]
pub(crate) fn gen_centralized_crs<R: Rng + CryptoRng>(
    sk: &PrivateSigKey,
    params: &NoiseFloodParameters,
    mut rng: R,
) -> anyhow::Result<(PublicParameter, CrsMetaData)> {
    use distributed_decryption::execution::zk::ceremony::compute_witness_dim;
    let witness_dim = compute_witness_dim(&params.ciphertext_parameters)?;
    tracing::info!("Generating CRS with witness dimension {}.", witness_dim);
    let pparam = PublicParameter::new(witness_dim);

    let mut tau = curve::Zp::rand(&mut rng);
    let mut r = curve::Zp::rand(&mut rng);
    let pproof = make_proof_deterministic(&pparam, tau, 1, r);
    tau.zeroize();
    r.zeroize();

    let crs_info = compute_info(sk, &pproof.new_pp)?;
    Ok((pproof.new_pp, crs_info.into()))
}

#[derive(Clone)]
pub struct BaseKmsStruct {
    pub(crate) sig_key: Arc<PrivateSigKey>,
    pub(crate) serialized_verf_key: Arc<Vec<u8>>,
    pub(crate) rng: Arc<Mutex<AesRng>>,
}

impl BaseKmsStruct {
    pub fn new(sig_key: PrivateSigKey) -> anyhow::Result<Self> {
        let serialized_verf_key = Arc::new(serialize(&PublicSigKey {
            pk: SigningKey::verifying_key(&sig_key.sk).to_owned(),
        })?);
        Ok(BaseKmsStruct {
            sig_key: Arc::new(sig_key),
            serialized_verf_key,
            rng: Arc::new(Mutex::new(AesRng::from_entropy())),
        })
    }

    pub async fn new_rng(&self) -> anyhow::Result<AesRng> {
        let mut seed = [0u8; RND_SIZE];
        // Make a seperate scope for the rng so that it is dropped before the lock is released
        {
            let mut base_rng = self.rng.lock().await;
            base_rng.try_fill_bytes(seed.as_mut())?;
        }
        Ok(AesRng::from_seed(seed))
    }
}

impl BaseKms for BaseKmsStruct {
    fn verify_sig<T>(
        payload: &T,
        signature: &super::der_types::Signature,
        key: &PublicSigKey,
    ) -> anyhow::Result<()>
    where
        T: Serialize + AsRef<[u8]>,
    {
        internal_verify_sig(&payload, signature, key)
    }

    fn sign<T>(&self, msg: &T) -> anyhow::Result<super::der_types::Signature>
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
pub(crate) fn verify_eip712(request: &ReencryptionRequest) -> anyhow::Result<()> {
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
    let chain_id = u64::from_le_bytes(
        wrapped_domain.chain_id.as_slice()[0..8]
            .try_into()
            .context("Failed to convert chain id slice")?,
    );

    tracing::debug!("🔒 chain_id: {:?}", chain_id);
    let verifying_contract_address =
        alloy_primitives::Address::from_str(wrapped_domain.verifying_contract.as_str())
            .context("Failed to convert wrappted domain message into address")?;
    let domain = alloy_sol_types::eip712_domain! {
        name: wrapped_domain.name.clone(),
        version: wrapped_domain.version.clone(),
        chain_id: chain_id,
        verifying_contract: verifying_contract_address,
    };

    // Derive the EIP-712 signing hash.
    let message_hash = message.eip712_signing_hash(&domain);

    // We need to use the alloy signature type since
    // it will let us call `recover_address_from_prehash` later
    // but this signature cannot be wrapper into our own `Signature`
    // type since our own type uses k256::ecdsa, which is not the same
    // as the one in alloy.
    let alloy_signature = alloy_primitives::Signature::try_from(signature_bytes.as_slice())
        .map_err(|e| {
            tracing::error!("Failed to parse alloy signature with error: {e}");
            e
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

#[cfg(feature = "non-wasm")]
#[derive(Serialize, Deserialize)]
pub struct SoftwareKmsKeys {
    pub key_info: KeysInfoHashMap,
    pub sig_sk: PrivateSigKey,
    pub sig_pk: PublicSigKey,
}

#[cfg(test)]
#[derive(Serialize, Deserialize)]
pub struct CentralizedTestingKeys {
    pub params: NoiseFloodParameters,
    pub software_kms_keys: SoftwareKmsKeys,
    pub pub_fhe_keys: HashMap<RequestId, FhePubKeySet>,
    pub client_pk: PublicSigKey,
    pub client_sk: PrivateSigKey,
    pub server_keys: Vec<PublicSigKey>,
}

pub type KeysInfoHashMap = HashMap<RequestId, KmsFheKeyHandles>;

#[cfg(feature = "non-wasm")]
#[derive(Clone, Serialize, Deserialize)]
pub enum KmsFheKeyHandlesVersioned<'a> {
    V0(Cow<'a, KmsFheKeyHandles>),
}
impl Versioned for KmsFheKeyHandlesVersioned<'_> {}

#[cfg(feature = "non-wasm")]
#[derive(Clone, Serialize, Deserialize)]
pub struct KmsFheKeyHandles {
    pub client_key: FhePrivateKey,
    pub public_key_info: HashMap<PubDataType, SignedPubDataHandle>, // Mapping key type to information
}

#[cfg(feature = "non-wasm")]
impl Versionize for KmsFheKeyHandles {
    type Versioned<'vers> = KmsFheKeyHandlesVersioned<'vers>
    where
        Self: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        KmsFheKeyHandlesVersioned::V0(Cow::Borrowed(self))
    }
}

#[cfg(feature = "non-wasm")]
impl Unversionize for KmsFheKeyHandles {
    fn unversionize(versioned: Self::Versioned<'_>) -> anyhow::Result<Self> {
        match versioned {
            KmsFheKeyHandlesVersioned::V0(v0) => Ok(v0.into_owned()),
        }
    }
}

#[cfg(feature = "non-wasm")]
impl KmsFheKeyHandles {
    pub fn new(
        sig_key: &PrivateSigKey,
        client_key: FhePrivateKey,
        public_keys: &FhePubKeySet,
    ) -> anyhow::Result<Self> {
        let mut public_key_info = HashMap::new();
        public_key_info.insert(
            PubDataType::PublicKey,
            compute_info(sig_key, &public_keys.public_key)?,
        );
        public_key_info.insert(
            PubDataType::ServerKey,
            compute_info(sig_key, &public_keys.server_key)?,
        );
        if let Some(sns) = &public_keys.sns_key {
            public_key_info.insert(PubDataType::SnsKey, compute_info(sig_key, sns)?);
        }
        Ok(KmsFheKeyHandles {
            client_key,
            public_key_info,
        })
    }
}

// Values that need to be stored temporarily as part of an async key generation call.
#[cfg(feature = "non-wasm")]
type KeyGenCallValues = HashMap<PubDataType, SignedPubDataHandle>;

// Values that need to be stored temporarily as part of an async decryption call.
// Represents the digest of the request and the result of the decryption.
#[cfg(feature = "non-wasm")]
pub type DecCallValues = (Vec<u8>, Vec<Vec<u8>>);

// Values that need to be stored temporarily as part of an async reencryption call.
// Represents the FHE type, the digest of the request and the partial decryption.
#[cfg(feature = "non-wasm")]
pub type ReencCallValues = (FheType, Vec<u8>, Vec<u8>);

/// Software based KMS where keys are stored in a local file
/// Observe that the order of write access MUST be as follows to avoid dead locks:
/// PublicStorage -> PrivateStorage -> FheKeys/XXX_meta_map
#[cfg(feature = "non-wasm")]
pub struct SoftwareKms<PubS: Storage, PrivS: Storage> {
    pub(crate) base_kms: BaseKmsStruct,
    // Storage for data that is supposed to be readable by anyone on the internet,
    // but _may_ be suseptible to malicious modifications.
    pub(crate) public_storage: Arc<Mutex<PubS>>,
    // Storage for data that is supposed to only be readable, writable and modifiable by the entity
    // owner and where any modification will be detected.
    pub(crate) private_storage: Arc<Mutex<PrivS>>,
    // Map storing the already generated FHE keys.
    pub(crate) fhe_keys: Arc<RwLock<KeysInfoHashMap>>,
    // Map storing ongoing key generation requests.
    pub(crate) key_meta_map: Arc<RwLock<MetaStore<KeyGenCallValues>>>,
    // Map storing ongoing decryption requests.
    pub(crate) dec_meta_store: Arc<RwLock<MetaStore<DecCallValues>>>,
    // Map storing ongoing reencryption requests.
    pub(crate) reenc_meta_map: Arc<RwLock<MetaStore<ReencCallValues>>>,
    // Map storing ongoing CRS generation requests.
    pub(crate) crs_meta_map: Arc<RwLock<MetaStore<CrsMetaData>>>,
    // Map storing the identity of parameters and the parameter file paths
    pub(crate) param_file_map: Arc<RwLock<HashMap<ParamChoice, String>>>, // TODO this should be loaded once during boot
}

/// Perform asynchronous decryption and serialize the result
#[cfg(feature = "non-wasm")]
pub fn central_decrypt<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
>(
    client_key: &FhePrivateKey,
    cts: &Vec<TypedCiphertext>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

    // run the decryption of each ct in the batch in parallel
    cts.par_iter()
        .map(|ct| {
            let pt = &SoftwareKms::<PubS, PrivS>::decrypt(
                client_key,
                &ct.ciphertext,
                ct.fhe_type.try_into()?,
            )?;

            handle_potential_err(
                serialize(&pt),
                "Could not serialize the decrypted ciphertext".to_string(),
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
>(
    client_key: &FhePrivateKey,
    sig_key: &PrivateSigKey,
    rng: &mut (impl CryptoRng + RngCore),
    high_level_ct: &[u8],
    fhe_type: FheType,
    req_digest: &[u8],
    client_enc_key: &PublicEncKey,
    client_address: &alloy_primitives::Address,
) -> anyhow::Result<Vec<u8>> {
    SoftwareKms::<PubS, PrivS>::reencrypt(
        client_key,
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
impl<PubS: Storage + Sync + Send + 'static, PrivS: Storage + Sync + Send + 'static> fmt::Debug
    for SoftwareKms<PubS, PrivS>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareKms")
            .field("sig_key", &self.base_kms.sig_key)
            .finish() // Don't include fhe_dec_key
    }
}

#[cfg(feature = "non-wasm")]
impl<PubS: Storage + Sync + Send + 'static, PrivS: Storage + Sync + Send + 'static> BaseKms
    for SoftwareKms<PubS, PrivS>
{
    fn verify_sig<T: Serialize + AsRef<[u8]>>(
        payload: &T,
        signature: &super::der_types::Signature,
        verification_key: &PublicSigKey,
    ) -> anyhow::Result<()> {
        BaseKmsStruct::verify_sig(payload, signature, verification_key)
    }

    fn sign<T: Serialize + AsRef<[u8]>>(
        &self,
        msg: &T,
    ) -> anyhow::Result<super::der_types::Signature> {
        self.base_kms.sign(msg)
    }

    fn get_serialized_verf_key(&self) -> Vec<u8> {
        self.base_kms.get_serialized_verf_key()
    }

    fn digest<T: ?Sized + AsRef<[u8]>>(msg: &T) -> anyhow::Result<Vec<u8>> {
        BaseKmsStruct::digest(&msg)
    }
}

#[cfg(feature = "non-wasm")]
impl<PubS: Storage + Sync + Send + 'static, PrivS: Storage + Sync + Send + 'static> Kms
    for SoftwareKms<PubS, PrivS>
{
    fn decrypt(
        client_key: &FhePrivateKey,
        high_level_ct: &[u8],
        fhe_type: FheType,
    ) -> anyhow::Result<Plaintext> {
        let f = || -> anyhow::Result<Plaintext> {
            Ok(match fhe_type {
                FheType::Ebool => {
                    let cipher: FheBool = deserialize(high_level_ct)?;
                    let plaintext = cipher.decrypt(client_key);
                    Plaintext::from_bool(plaintext)
                }
                FheType::Euint4 => {
                    let cipher: FheUint4 = deserialize(high_level_ct)?;
                    let plaintext: u8 = cipher.decrypt(client_key);
                    Plaintext::from_u4(plaintext)
                }
                FheType::Euint8 => {
                    let cipher: FheUint8 = deserialize(high_level_ct)?;
                    let plaintext: u8 = cipher.decrypt(client_key);
                    Plaintext::from_u8(plaintext)
                }
                FheType::Euint16 => {
                    let cipher: FheUint16 = deserialize(high_level_ct)?;
                    let plaintext: u16 = cipher.decrypt(client_key);
                    Plaintext::from_u16(plaintext)
                }
                FheType::Euint32 => {
                    let cipher: FheUint32 = deserialize(high_level_ct)?;
                    let plaintext: u32 = cipher.decrypt(client_key);
                    Plaintext::from_u32(plaintext)
                }
                FheType::Euint64 => {
                    let cipher: FheUint64 = bincode::deserialize(high_level_ct)?;
                    let plaintext: u64 = cipher.decrypt(client_key);
                    Plaintext::from_u64(plaintext)
                }
                FheType::Euint128 => {
                    let cipher: FheUint128 = bincode::deserialize(high_level_ct)?;
                    let plaintext: u128 = cipher.decrypt(client_key);
                    Plaintext::from_u128(plaintext)
                }
                FheType::Euint160 => {
                    let cipher: FheUint160 = bincode::deserialize(high_level_ct)?;
                    let plaintext: U256 = cipher.decrypt(client_key);
                    Plaintext::from_u160(plaintext)
                }
                FheType::Euint256 => {
                    let cipher: FheUint256 = bincode::deserialize(high_level_ct)?;
                    let plaintext: U256 = cipher.decrypt(client_key);
                    Plaintext::from_u256(plaintext)
                }
                FheType::Euint512 => {
                    todo!("Implement Euint512 decryption")
                }
                FheType::Euint1024 => {
                    todo!("Implement Euint1024 decryption")
                }
                FheType::Euint2048 => {
                    let cipher: FheUint2048 = bincode::deserialize(high_level_ct)?;
                    let plaintext: U2048 = cipher.decrypt(client_key);
                    Plaintext::from_u2048(plaintext)
                }
            })
        };
        match panic::catch_unwind(f) {
            Ok(x) => x,
            Err(_) => Err(anyhow_error_and_log("decryption panicked".to_string())),
        }
    }

    fn reencrypt(
        client_key: &FhePrivateKey,
        sig_key: &PrivateSigKey,
        rng: &mut (impl CryptoRng + RngCore),
        ct: &[u8],
        fhe_type: FheType,
        link: &[u8],
        client_enc_key: &PublicEncKey,
        client_address: &alloy_primitives::Address,
    ) -> anyhow::Result<Vec<u8>> {
        let plaintext = Self::decrypt(client_key, ct, fhe_type)?;
        // Observe that we encrypt the plaintext itself, this is different from the threshold case
        // where it is first mapped to a Vec<Residuepoly<Z128>> element
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
        tracing::info!("Completed reencyption of ciphertext");
        Ok(res)
    }
}

#[cfg(feature = "non-wasm")]
impl<PubS: Storage + Sync + Send + 'static, PrivS: Storage + Sync + Send + 'static>
    SoftwareKms<PubS, PrivS>
{
    pub async fn new(
        param_file_map: HashMap<String, String>,
        public_storage: PubS,
        private_storage: PrivS,
    ) -> anyhow::Result<Self> {
        let sks: HashMap<RequestId, PrivateSigKeyVersioned> =
            read_all_data(&private_storage, &PrivDataType::SigningKey.to_string()).await?;
        if sks.len() != 1 {
            return Err(anyhow_error_and_log(
                "Server signing key map should only contain one entry",
            ));
        }

        let sk = PrivateSigKey::unversionize(
            some_or_err(
                sks.values().collect_vec().first(),
                format!(
                    "There is no private signing key stored in {}",
                    private_storage.info()
                ),
            )?
            .to_owned()
            .to_owned(),
        )?;
        let key_info_versioned: HashMap<RequestId, KmsFheKeyHandlesVersioned> =
            read_all_data(&private_storage, &PrivDataType::FheKeyInfo.to_string()).await?;
        let mut key_info = HashMap::new();
        for (id, versioned_handles) in key_info_versioned {
            key_info.insert(id, KmsFheKeyHandles::unversionize(versioned_handles)?);
        }
        tracing::info!(
            "loaded key_info with key_ids: {:?}",
            key_info
                .keys()
                .map(|rid| &rid.request_id)
                .collect::<Vec<_>>()
        );
        let key_info_w_status = key_info
            .iter()
            .map(|(id, info)| {
                (
                    id.to_owned(),
                    HandlerStatus::Done(info.public_key_info.to_owned()),
                )
            })
            .collect();
        let cs: HashMap<RequestId, CrsMetaDataVersioned> =
            read_all_data(&private_storage, &PrivDataType::CrsInfo.to_string()).await?;
        let mut cs_w_status: HashMap<RequestId, HandlerStatus<CrsMetaData>> = HashMap::new();
        for (id, crs) in cs {
            cs_w_status.insert(
                id.to_owned(),
                HandlerStatus::Done(CrsMetaData::unversionize(crs.to_owned())?),
            );
        }

        let param_file_map = Arc::new(RwLock::new(HashMap::from_iter(
            param_file_map
                .into_iter()
                .filter_map(|(k, v)| ParamChoice::from_str_name(&k).map(|x| (x, v))),
        )));
        Ok(SoftwareKms {
            base_kms: BaseKmsStruct::new(sk)?,
            public_storage: Arc::new(Mutex::new(public_storage)),
            private_storage: Arc::new(Mutex::new(private_storage)),
            fhe_keys: Arc::new(RwLock::new(key_info)),
            key_meta_map: Arc::new(RwLock::new(MetaStore::new_from_map(key_info_w_status))),
            dec_meta_store: Arc::new(RwLock::new(MetaStore::new(DEC_CAPACITY, MIN_DEC_CACHE))),
            reenc_meta_map: Arc::new(RwLock::new(MetaStore::new(DEC_CAPACITY, MIN_DEC_CACHE))),
            crs_meta_map: Arc::new(RwLock::new(MetaStore::new_from_map(cs_w_status))),
            param_file_map,
        })
    }
}

/// Computes the public into on a serializable `element`.
/// More specifically, computes the unique handle of the `element` and signs this handle using the
/// `kms`.
pub(crate) fn compute_info<S: Serialize>(
    sk: &PrivateSigKey,
    element: &S,
) -> anyhow::Result<SignedPubDataHandle> {
    let ser = serialize(element)?;
    let handle = compute_handle(&ser)?;
    let signature = sign(&handle, sk)?;
    Ok(SignedPubDataHandle {
        key_handle: handle,
        signature: serialize(&signature)?,
    })
}

/// Compute a handle of an element, based on its digest
/// More specifically compute the hash digest, truncate it and convert it to a hex string
pub fn compute_handle<S>(bytes: &S) -> anyhow::Result<String>
where
    S: Serialize,
{
    let mut digest = serialize_hash_element(bytes)?;
    // Truncate and convert to hex
    digest.truncate(ID_LENGTH);
    Ok(hex::encode(digest))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{KmsFheKeyHandles, Storage};
    #[cfg(feature = "slow_tests")]
    use crate::consts::{
        DEFAULT_CENTRAL_KEYS_PATH, DEFAULT_CENTRAL_KEY_ID, DEFAULT_PARAM_PATH,
        OTHER_CENTRAL_DEFAULT_ID,
    };
    use crate::consts::{OTHER_CENTRAL_TEST_ID, TEST_CENTRAL_KEY_ID};
    use crate::consts::{TEST_CENTRAL_KEYS_PATH, TEST_PARAM_PATH};
    use crate::cryptography::central_kms::CentralizedTestingKeys;
    use crate::cryptography::central_kms::SoftwareKmsKeys;
    use crate::cryptography::central_kms::{gen_sig_keys, SoftwareKms};
    use crate::cryptography::der_types::PrivateSigKey;
    use crate::cryptography::signcryption::{
        decrypt_signcryption, ephemeral_signcryption_key_generation,
    };
    use crate::kms::{FheType, RequestId};
    use crate::rpc::central_rpc::default_param_file_map;
    use crate::rpc::rpc_types::Kms;
    use crate::storage::{FileStorage, RamStorage, StorageType};
    use crate::util::file_handling::read_element;
    use crate::util::key_setup::test_tools::compute_cipher;
    use crate::{
        cryptography::central_kms::generate_fhe_keys,
        util::file_handling::{read_as_json, write_element},
    };
    use aes_prng::AesRng;
    use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
    use rand::{RngCore, SeedableRng};
    use serial_test::serial;
    use std::collections::HashMap;
    use std::{path::Path, sync::Arc};
    use tfhe::shortint::ClassicPBSParameters;
    use tfhe::ConfigBuilder;
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
            TEST_PARAM_PATH,
            &TEST_CENTRAL_KEY_ID.to_string(),
            &OTHER_CENTRAL_TEST_ID.to_string(),
            TEST_CENTRAL_KEYS_PATH,
        )
        .await
    }

    #[cfg(feature = "slow_tests")]
    pub(crate) async fn ensure_kms_default_keys() -> CentralizedTestingKeys {
        setup(
            DEFAULT_PARAM_PATH,
            &DEFAULT_CENTRAL_KEY_ID.to_string(),
            &OTHER_CENTRAL_DEFAULT_ID.to_string(),
            DEFAULT_CENTRAL_KEYS_PATH,
        )
        .await
    }

    async fn setup(
        param_path: &str,
        key_id: &str,
        other_key_id: &str,
        key_path: &str,
    ) -> CentralizedTestingKeys {
        if Path::new(key_path).exists() {
            return read_element(key_path).await.unwrap();
        }

        let mut rng = AesRng::seed_from_u64(100);
        let params: NoiseFloodParameters = read_as_json(param_path).await.unwrap();
        let (sig_pk, sig_sk) = gen_sig_keys(&mut rng);
        let (pub_fhe_keys, key_info) = generate_fhe_keys(&sig_sk, params).unwrap();
        let mut key_info_map = HashMap::from([(key_id.to_string().try_into().unwrap(), key_info)]);

        let (other_pub_fhe_keys, other_key_info) = generate_fhe_keys(&sig_sk, params).unwrap();

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
            params,
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
        let (ct, fhe_type) = compute_cipher(
            msg.into(),
            &keys.pub_fhe_keys.get(key_id).unwrap().public_key,
        );
        let kms = {
            let inner = SoftwareKms::new(
                default_param_file_map(),
                RamStorage::new(StorageType::PUB),
                RamStorage::from_existing_keys(&keys.software_kms_keys)
                    .await
                    .unwrap(),
            )
            .await
            .unwrap();
            if sim_type == SimulationType::BadFheKey {
                set_wrong_client_key(&inner, key_id, keys.params).await;
            }
            inner
        };
        let raw_plaintext = SoftwareKms::<FileStorage, FileStorage>::decrypt(
            &kms.fhe_keys.read().await.get(key_id).unwrap().client_key,
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
    >(
        inner: &SoftwareKms<PubS, PrivS>,
        key_handle: &RequestId,
        params: NoiseFloodParameters,
    ) {
        let pbs_params: ClassicPBSParameters = params.ciphertext_parameters;
        let config = ConfigBuilder::with_custom_parameters(pbs_params);
        let wrong_client_key = tfhe::ClientKey::generate(config);
        let mut key_info = inner.fhe_keys.write().await;
        let x: &mut KmsFheKeyHandles = key_info.get_mut(key_handle).unwrap();
        let wrong_handles = KmsFheKeyHandles {
            client_key: wrong_client_key,
            public_key_info: x.public_key_info.clone(),
        };
        *x = wrong_handles;
    }

    fn set_wrong_sig_key<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
    >(
        inner: &mut SoftwareKms<PubS, PrivS>,
        rng: &mut AesRng,
    ) {
        // move to the next state so ensure we're generating a different ecdsa key
        _ = rng.next_u64();
        let wrong_ecdsa_key = k256::ecdsa::SigningKey::random(rng);
        assert_ne!(wrong_ecdsa_key, inner.base_kms.sig_key.sk);
        inner.base_kms.sig_key = Arc::new(PrivateSigKey {
            sk: wrong_ecdsa_key,
        });
    }

    async fn simulate_reencrypt(
        sim_type: SimulationType,
        keys: &CentralizedTestingKeys,
        key_handle: &RequestId,
    ) {
        let msg = 42305u64;
        let mut rng = AesRng::seed_from_u64(1);
        let (ct, fhe_type) = compute_cipher(
            msg.into(),
            &keys.pub_fhe_keys.get(key_handle).unwrap().public_key,
        );
        let kms = {
            let mut inner = SoftwareKms::new(
                default_param_file_map(),
                RamStorage::new(StorageType::PUB),
                RamStorage::from_existing_keys(&keys.software_kms_keys)
                    .await
                    .unwrap(),
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
        let mut rng = kms.base_kms.new_rng().await.unwrap();
        let raw_cipher = SoftwareKms::<FileStorage, FileStorage>::reencrypt(
            &kms.fhe_keys
                .read()
                .await
                .get(key_handle)
                .unwrap()
                .client_key,
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

    #[tokio::test]
    async fn ensure_compute_info_consistency() {
        // we need compute info to work without calling the sign function from KMS,
        // i.e., only using a signing key
        // this test makes sure the output is consistent
        let keys = get_test_keys().await;
        let kms = {
            SoftwareKms::new(
                default_param_file_map(),
                RamStorage::new(StorageType::PUB),
                RamStorage::from_existing_keys(&keys.software_kms_keys)
                    .await
                    .unwrap(),
            )
            .await
            .unwrap()
        };

        let value = "bonjour".to_string();
        let expected = super::compute_info(&kms.base_kms.sig_key, &value).unwrap();
        let actual = super::compute_info(&kms.base_kms.sig_key, &value).unwrap();
        assert_eq!(expected, actual);
    }
}
