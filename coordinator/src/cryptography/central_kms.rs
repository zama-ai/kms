use super::der_types::{PrivateSigKey, PublicEncKey, PublicSigKey, Signature};
use super::signcryption::{
    internal_verify_sig, internal_verify_sig_eip712, serialize_hash_element, sign, sign_eip712,
    signcrypt, RND_SIZE,
};
#[cfg(feature = "non-wasm")]
use crate::kms::RequestId;
#[cfg(feature = "non-wasm")]
use crate::storage::PublicStorage;
#[cfg(feature = "non-wasm")]
use crate::util::key_setup::{FhePrivateKey, FhePublicKey};
use crate::{anyhow_error_and_log, storage::read_all_data};
use crate::{
    consts::ID_LENGTH,
    rpc::rpc_types::{BaseKms, Kms, Plaintext, RawDecryption, SigncryptionPayload},
};
use crate::{consts::TEST_KEY_ID, rpc::rpc_types::PrivDataType};
use crate::{kms::FhePubKeyInfo, some_or_err};
use crate::{kms::FheType, rpc::rpc_types::PubDataType};
use aes_prng::AesRng;
use alloy_sol_types::{Eip712Domain, SolStruct};
use der::zeroize::Zeroize;
#[cfg(feature = "non-wasm")]
use distributed_decryption::execution::endpoints::keygen::FhePubKeySet;
use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
use distributed_decryption::execution::zk::ceremony::{make_proof_deterministic, PublicParameter};
use itertools::Itertools;
use k256::ecdsa::SigningKey;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_asn1_der::to_vec;
use std::{collections::HashMap, sync::Arc};
use std::{fmt, panic};
use tfhe::ClientKey;
use tfhe::{integer::U256, shortint::ClassicPBSParameters};
use tfhe::{prelude::FheDecrypt, FheUint128, FheUint160};
use tfhe::{ConfigBuilder, FheBool, FheUint16, FheUint32, FheUint4, FheUint64, FheUint8};
#[cfg(feature = "non-wasm")]
use tfhe_zk_pok::curve_api::bls12_446 as curve;
use tokio::sync::Mutex;
#[cfg(feature = "non-wasm")]
use tokio::task::JoinHandle;

fn handle_potential_err<T, E>(resp: Result<T, E>, error: String) -> anyhow::Result<T> {
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
pub fn gen_default_kms_keys<R: CryptoRng + RngCore>(
    params: NoiseFloodParameters,
    rng: &mut R,
    key_handle: Option<RequestId>,
) -> (SoftwareKmsKeys, FhePubKeySet) {
    let (client_key, fhe_pub_keys) = generate_fhe_keys(params);
    let (server_pk, server_sk) = gen_sig_keys(rng);
    let kms = BaseKmsStruct::new(server_sk.clone());
    let key_info = KmsFheKeyHandles::new(&kms, client_key, &fhe_pub_keys).unwrap();
    let handle = key_handle.unwrap_or((*TEST_KEY_ID).clone());
    (
        SoftwareKmsKeys {
            key_info: HashMap::from([(handle, key_info)]),
            sig_sk: server_sk,
            sig_pk: server_pk,
        },
        fhe_pub_keys,
    )
}

#[cfg(feature = "non-wasm")]
pub async fn async_generate_fhe_keys(
    params: NoiseFloodParameters,
) -> (FhePrivateKey, FhePubKeySet) {
    generate_fhe_keys(params)
}

#[cfg(feature = "non-wasm")]
pub async fn async_generate_crs(
    rng: AesRng,
    params: NoiseFloodParameters,
) -> anyhow::Result<PublicParameter> {
    gen_centralized_crs(&params, rng)
}

#[cfg(feature = "non-wasm")]
pub fn generate_fhe_keys(params: NoiseFloodParameters) -> (FhePrivateKey, FhePubKeySet) {
    let client_key = generate_client_fhe_key(params);
    let server_key = client_key.generate_server_key();
    let public_key = FhePublicKey::new(&client_key);
    let pks = FhePubKeySet {
        public_key,
        server_key,
        sns_key: None,
    };
    (client_key, pks)
}

#[cfg(feature = "non-wasm")]
pub fn generate_client_fhe_key(params: NoiseFloodParameters) -> ClientKey {
    let pbs_params: ClassicPBSParameters = params.ciphertext_parameters;
    let config = ConfigBuilder::with_custom_parameters(pbs_params, None);
    ClientKey::generate(config)
}

/// compute the CRS in the centralized KMS.
#[cfg(feature = "non-wasm")]
pub(crate) fn gen_centralized_crs<R: Rng + CryptoRng>(
    params: &NoiseFloodParameters,
    mut rng: R,
) -> anyhow::Result<PublicParameter> {
    use distributed_decryption::execution::zk::ceremony::compute_witness_dim;
    let witness_dim = compute_witness_dim(&params.ciphertext_parameters)?;
    tracing::info!("Generating CRS with witness dimension {}.", witness_dim);
    let pparam = PublicParameter::new(witness_dim);

    let mut tau = curve::Zp::rand(&mut rng);
    let mut r = curve::Zp::rand(&mut rng);
    let pproof = make_proof_deterministic(&pparam, tau, 1, r);
    tau.zeroize();
    r.zeroize();

    Ok(pproof.new_pp)
}

#[derive(Clone)]
pub struct BaseKmsStruct {
    pub(crate) sig_key: Arc<PrivateSigKey>,
    pub(crate) rng: Arc<Mutex<AesRng>>,
}

impl BaseKmsStruct {
    pub fn new(sig_sk: PrivateSigKey) -> Self {
        BaseKmsStruct {
            sig_key: Arc::new(sig_sk),
            rng: Arc::new(Mutex::new(AesRng::from_entropy())),
        }
    }

    pub fn new_rng(&self) -> anyhow::Result<AesRng> {
        let mut seed = [0u8; RND_SIZE];
        // Make a seperate scope for the rng so that it is dropped before the lock is released
        {
            let mut base_rng =
                handle_potential_err(self.rng.try_lock(), "Could not get lock on rng".to_string())?;
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
    ) -> bool
    where
        T: Serialize + AsRef<[u8]>,
    {
        if !internal_verify_sig(&payload, signature, key) {
            return false;
        }
        true
    }

    fn sign<T>(&self, msg: &T) -> anyhow::Result<super::der_types::Signature>
    where
        T: Serialize + AsRef<[u8]>,
    {
        sign(msg, &self.sig_key)
    }

    fn get_verf_key(&self) -> PublicSigKey {
        PublicSigKey {
            pk: SigningKey::verifying_key(&self.sig_key.sk).to_owned(),
        }
    }

    fn digest<T>(msg: &T) -> anyhow::Result<Vec<u8>>
    where
        T: fmt::Debug + Serialize,
    {
        serialize_hash_element(msg)
    }

    fn verify_sig_eip712<T: SolStruct>(
        payload: &T,
        domain: &Eip712Domain,
        signature: &Signature,
        verification_key: &PublicSigKey,
    ) -> bool {
        internal_verify_sig_eip712(payload, domain, signature, verification_key)
    }

    fn sign_eip712<T: SolStruct>(
        &self,
        msg: &T,
        domain: &Eip712Domain,
    ) -> anyhow::Result<Signature> {
        sign_eip712(msg, domain, &self.sig_key)
    }
}

#[cfg(feature = "non-wasm")]
#[derive(Serialize, Deserialize)]
pub struct SoftwareKmsKeys {
    pub key_info: KeysHashMap,
    pub sig_sk: PrivateSigKey,
    pub sig_pk: PublicSigKey,
}

// TODO rename to CrcInfoHashMap (later, to avoid conflicts with other PRs)
pub type CrsHashMap = HashMap<RequestId, FhePubKeyInfo>;
pub type KeysHashMap = HashMap<RequestId, KmsFheKeyHandles>;

#[cfg(feature = "non-wasm")]
#[derive(Clone, Serialize, Deserialize)]
pub struct KmsFheKeyHandles {
    pub client_key: FhePrivateKey,
    pub public_key_info: HashMap<PubDataType, FhePubKeyInfo>, // Mapping key type to information
}

#[cfg(feature = "non-wasm")]
impl KmsFheKeyHandles {
    pub fn new<K: BaseKms>(
        kms: &K,
        client_key: FhePrivateKey,
        public_keys: &FhePubKeySet,
    ) -> anyhow::Result<Self> {
        let mut public_key_info = HashMap::new();
        public_key_info.insert(
            PubDataType::PublicKey,
            compute_info(kms, &public_keys.public_key)?,
        );
        public_key_info.insert(
            PubDataType::ServerKey,
            compute_info(kms, &public_keys.server_key)?,
        );
        if let Some(sns) = &public_keys.sns_key {
            public_key_info.insert(PubDataType::SnsKey, compute_info(kms, sns)?);
        }
        Ok(KmsFheKeyHandles {
            client_key,
            public_key_info,
        })
    }
}

// Values that needs to be stored temporarely as part of an async key generation call.
#[cfg(feature = "non-wasm")]
type KeyGenCallValues = (ClientKey, FhePubKeySet);
#[cfg(feature = "non-wasm")]
type CrsGenValues = anyhow::Result<PublicParameter>;

// Values that needs to be stored temporarely as part of an async decryption call.
// Represents the digest of the request and the result of the decryption.
#[cfg(feature = "non-wasm")]
pub type DecCallValues = (Vec<u8>, anyhow::Result<Vec<u8>>);

// Values that needs to be stored temporarely as part of an async reencryption call.
// Represents the server_needed, FHE type, the digest of the request and the result of the reencryption.
#[cfg(feature = "non-wasm")]
pub type ReencCallValues = ((u32, FheType, Vec<u8>), anyhow::Result<Vec<u8>>);

pub type CompMap<A> = Arc<Mutex<HashMap<RequestId, JoinHandle<A>>>>;
/// Software based KMS where keys are stored in a local file
#[cfg(feature = "non-wasm")]
pub struct SoftwareKms<
    PubS: PublicStorage + Sync + Send + 'static,
    PrivS: PublicStorage + Sync + Send + 'static,
> {
    pub(crate) base_kms: BaseKmsStruct,
    // Storage for data that is supposed to be readable by anyone on the internet,
    // but _may_ be suseptible to malicious modifications.
    pub(crate) public_storage: Arc<Mutex<PubS>>,
    // Storage for data that is supposed to only be readable, writable and modifiable by the entity owner
    // and where any modification will be detected.
    pub(crate) private_storage: Arc<Mutex<PrivS>>,
    // Map storing the already generated FHE keys.
    pub key_handles: Arc<Mutex<KeysHashMap>>,
    // Map storing ongoing key generation requests.
    pub key_gen_map: CompMap<KeyGenCallValues>,
    // Map storing ongoing decryption requests.
    pub decrypt_map: CompMap<DecCallValues>,
    // Map storing ongoing reencryption requests.
    pub reenc_map: CompMap<ReencCallValues>,
    // Map storing the already generated CRS keys.
    pub crs_handles: Arc<Mutex<CrsHashMap>>,
    // Map storing ongoing CRS generation requests.
    pub crs_gen_map: CompMap<CrsGenValues>,
}

/// Perform asynchronous decryption and serialize the result using asn1
#[cfg(feature = "non-wasm")]
pub async fn async_decrypt<
    PubS: PublicStorage + Sync + Send + 'static,
    PrivS: PublicStorage + Sync + Send + 'static,
>(
    client_key: &FhePrivateKey,
    high_level_ct: &[u8],
    fhe_type: FheType,
) -> anyhow::Result<Vec<u8>> {
    handle_potential_err(
        to_vec(&SoftwareKms::<PubS, PrivS>::decrypt(
            client_key,
            high_level_ct,
            fhe_type,
        )?),
        "Could not serialize the decrypted ciphertext".to_string(),
    )
}

/// Perform asynchronous reencryption and serialize the result using asn1
#[cfg(feature = "non-wasm")]
#[allow(clippy::too_many_arguments)]
pub async fn async_reencrypt<
    PubS: PublicStorage + Sync + Send + 'static,
    PrivS: PublicStorage + Sync + Send + 'static,
>(
    client_key: &FhePrivateKey,
    sig_key: &PrivateSigKey,
    rng: &mut (impl CryptoRng + RngCore),
    high_level_ct: &[u8],
    fhe_type: FheType,
    req_digest: &[u8],
    client_enc_key: &PublicEncKey,
    client_verf_key: &PublicSigKey,
) -> anyhow::Result<Vec<u8>> {
    SoftwareKms::<PubS, PrivS>::reencrypt(
        client_key,
        sig_key,
        rng,
        high_level_ct,
        fhe_type,
        req_digest,
        client_enc_key,
        client_verf_key,
    )
}

// impl fmt::Debug for SoftwareKms, we don't want to include the decryption key in the debug output
#[cfg(feature = "non-wasm")]
impl<PubS: PublicStorage + Sync + Send + 'static, PrivS: PublicStorage + Sync + Send + 'static>
    fmt::Debug for SoftwareKms<PubS, PrivS>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareKms")
            .field("sig_key", &self.base_kms.sig_key)
            .finish() // Don't include fhe_dec_key
    }
}

#[cfg(feature = "non-wasm")]
impl<PubS: PublicStorage + Sync + Send + 'static, PrivS: PublicStorage + Sync + Send + 'static>
    BaseKms for SoftwareKms<PubS, PrivS>
{
    fn verify_sig<T: Serialize + AsRef<[u8]>>(
        payload: &T,
        signature: &super::der_types::Signature,
        verification_key: &PublicSigKey,
    ) -> bool {
        BaseKmsStruct::verify_sig(payload, signature, verification_key)
    }

    fn sign<T: Serialize + AsRef<[u8]>>(
        &self,
        msg: &T,
    ) -> anyhow::Result<super::der_types::Signature> {
        self.base_kms.sign(msg)
    }

    // TODO should just return reference
    fn get_verf_key(&self) -> PublicSigKey {
        self.base_kms.get_verf_key()
    }

    fn digest<T: fmt::Debug + Serialize>(msg: &T) -> anyhow::Result<Vec<u8>> {
        BaseKmsStruct::digest(&msg)
    }

    fn verify_sig_eip712<T: SolStruct>(
        payload: &T,
        domain: &Eip712Domain,
        signature: &Signature,
        verification_key: &PublicSigKey,
    ) -> bool {
        BaseKmsStruct::verify_sig_eip712(payload, domain, signature, verification_key)
    }

    fn sign_eip712<T: SolStruct>(
        &self,
        msg: &T,
        domain: &Eip712Domain,
    ) -> anyhow::Result<Signature> {
        self.base_kms.sign_eip712(msg, domain)
    }
}

#[cfg(feature = "non-wasm")]
impl<PubS: PublicStorage + Sync + Send + 'static, PrivS: PublicStorage + Sync + Send + 'static> Kms
    for SoftwareKms<PubS, PrivS>
{
    fn decrypt(
        client_key: &FhePrivateKey,
        high_level_ct: &[u8],
        fhe_type: FheType,
    ) -> anyhow::Result<Plaintext> {
        let f = || -> anyhow::Result<Plaintext> {
            Ok(match fhe_type {
                FheType::Bool => {
                    let cipher: FheBool = bincode::deserialize(high_level_ct)?;
                    let plaintext = cipher.decrypt(client_key);
                    Plaintext::from_bool(plaintext)
                }
                FheType::Euint4 => {
                    let cipher: FheUint4 = bincode::deserialize(high_level_ct)?;
                    let plaintext: u8 = cipher.decrypt(client_key);
                    Plaintext::from_u4(plaintext)
                }
                FheType::Euint8 => {
                    let cipher: FheUint8 = bincode::deserialize(high_level_ct)?;
                    let plaintext: u8 = cipher.decrypt(client_key);
                    Plaintext::from_u8(plaintext)
                }
                FheType::Euint16 => {
                    let cipher: FheUint16 = bincode::deserialize(high_level_ct)?;
                    let plaintext: u16 = cipher.decrypt(client_key);
                    Plaintext::from_u16(plaintext)
                }
                FheType::Euint32 => {
                    let cipher: FheUint32 = bincode::deserialize(high_level_ct)?;
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
        req_digest: &[u8],
        client_enc_key: &PublicEncKey,
        client_verf_key: &PublicSigKey,
    ) -> anyhow::Result<Vec<u8>> {
        let plaintext = Self::decrypt(client_key, ct, fhe_type)?;
        // Observe that we encrypt the plaintext itself, this is different from the threshold case
        // where it is first mapped to a Vec<Residuepoly<Z128>> element
        let bytes: Vec<u8> = plaintext.into();
        let raw_decryption = RawDecryption::new(bytes, fhe_type);
        let signcryption_msg = SigncryptionPayload {
            raw_decryption,
            req_digest: req_digest.to_vec(),
        };
        let enc_res = signcrypt(
            rng,
            &serde_asn1_der::to_vec(&signcryption_msg)?,
            client_enc_key,
            client_verf_key,
            sig_key,
        )?;
        let res = to_vec(&enc_res)?;
        tracing::info!("Completed reencyption of ciphertext");
        Ok(res)
    }
}

#[cfg(feature = "non-wasm")]
impl<PubS: PublicStorage + Sync + Send + 'static, PrivS: PublicStorage + Sync + Send + 'static>
    SoftwareKms<PubS, PrivS>
{
    pub fn new(public_storage: PubS, private_storage: PrivS) -> anyhow::Result<Self> {
        let sks: HashMap<RequestId, PrivateSigKey> =
            read_all_data(&private_storage, &PrivDataType::SigningKey.to_string())?;
        let sk = some_or_err(
            sks.values().collect_vec().first(),
            "There is no private signing key stored".to_string(),
        )?
        .to_owned()
        .to_owned();
        let key_info: KeysHashMap =
            read_all_data(&private_storage, &PrivDataType::FheKeyInfo.to_string())?;
        let cs: CrsHashMap = read_all_data(&private_storage, &PrivDataType::CrsInfo.to_string())?;
        Ok(SoftwareKms {
            base_kms: BaseKmsStruct::new(sk),
            public_storage: Arc::new(Mutex::new(public_storage)),
            private_storage: Arc::new(Mutex::new(private_storage)),
            key_handles: Arc::new(Mutex::new(key_info)),
            key_gen_map: Arc::new(Mutex::new(HashMap::new())),
            decrypt_map: Arc::new(Mutex::new(HashMap::new())),
            reenc_map: Arc::new(Mutex::new(HashMap::new())),
            crs_handles: Arc::new(Mutex::new(cs)),
            crs_gen_map: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

/// Computes the public into on a serializable `element`.
/// More specifically, computes the unique handle of the `element` and signs this handle using the `kms`.
pub fn compute_info<K: BaseKms, S: Serialize>(
    kms: &K,
    element: &S,
) -> anyhow::Result<FhePubKeyInfo> {
    // TODO hack serialize using serde because of issues with asn1 and public key serialization
    let ser = bincode::serialize(element)?;
    let handle = compute_handle(&ser)?;
    let signature = kms.sign(&handle)?;

    Ok(FhePubKeyInfo {
        key_handle: handle,
        signature: bincode::serialize(&signature)?,
    })
}

pub(crate) fn compute_info_from_key<S: Serialize>(
    sk: &PrivateSigKey,
    element: &S,
) -> anyhow::Result<FhePubKeyInfo> {
    let ser = bincode::serialize(element)?;
    let handle = compute_handle(&ser)?;
    let signature = sign(&handle, sk)?;
    Ok(FhePubKeyInfo {
        key_handle: handle,
        signature: bincode::serialize(&signature)?,
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
mod tests {
    use super::{KmsFheKeyHandles, PublicStorage};
    #[cfg(feature = "slow_tests")]
    use crate::consts::{
        DEFAULT_CENTRAL_CRS_PATH, DEFAULT_CENTRAL_CT_PATH, DEFAULT_CENTRAL_KEYS_PATH,
        DEFAULT_CENTRAL_OTHER_CT_PATH, DEFAULT_CRS_ID, DEFAULT_KEY_ID, DEFAULT_PARAM_PATH,
        DEFAULT_THRESHOLD_CT_PATH, DEFAULT_THRESHOLD_KEYS_PATH, OTHER_DEFAULT_ID,
    };
    use crate::cryptography::signcryption::decrypt_signcryption;
    use crate::kms::{FheType, RequestId};
    use crate::rpc::rpc_types::Plaintext;
    use crate::util::file_handling::read_element;
    use crate::util::key_setup::{
        ensure_central_crs_store_exists, ensure_dir_exist, CentralizedTestingKeys,
    };
    use crate::{
        consts::TEST_CRS_ID,
        util::key_setup::{ensure_central_keys_exist, ensure_ciphertext_exist},
    };
    use crate::{
        consts::{
            OTHER_TEST_ID, TEST_CENTRAL_CRS_PATH, TEST_CENTRAL_CT_PATH, TEST_CENTRAL_KEYS_PATH,
            TEST_CENTRAL_OTHER_CT_PATH, TEST_KEY_ID, TEST_PARAM_PATH, TEST_THRESHOLD_CT_PATH,
            TEST_THRESHOLD_KEYS_PATH,
        },
        storage::RamStorage,
    };
    use crate::{
        cryptography::central_kms::{gen_sig_keys, SoftwareKms},
        rpc::rpc_types::Kms,
    };
    use crate::{cryptography::der_types::PrivateSigKey, storage::FileStorage};
    use crate::{cryptography::request::ephemeral_key_generation, storage::StorageType};
    use aes_prng::AesRng;
    use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
    use rand::{RngCore, SeedableRng};
    use serial_test::serial;
    use std::sync::Arc;
    use tfhe::shortint::ClassicPBSParameters;
    use tfhe::ConfigBuilder;

    #[derive(Clone, PartialEq, Eq)]
    enum SimulationType {
        NoError,
        BadFheKey,
        // below are only used for reencryption
        BadSigKey,
        BadEphemeralKey,
    }

    #[test]
    fn sunshine_test_decrypt() {
        sunshine_decrypt(
            TEST_CENTRAL_KEYS_PATH,
            (*TEST_KEY_ID).clone(),
            TEST_CENTRAL_CT_PATH,
        );
    }

    #[test]
    fn decrypt_with_bad_client_key() {
        simulate_decrypt(
            SimulationType::BadFheKey,
            TEST_CENTRAL_KEYS_PATH,
            (*TEST_KEY_ID).clone(),
            TEST_CENTRAL_CT_PATH,
        );
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn sunshine_default_decrypt() {
        sunshine_decrypt(
            DEFAULT_CENTRAL_KEYS_PATH,
            (*DEFAULT_KEY_ID).clone(),
            DEFAULT_CENTRAL_CT_PATH,
        );
    }

    #[test]
    #[serial]
    fn multiple_test_keys_decrypt() {
        sunshine_decrypt(
            TEST_CENTRAL_KEYS_PATH,
            (*OTHER_TEST_ID).clone(),
            TEST_CENTRAL_OTHER_CT_PATH,
        );
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn multiple_default_keys_decrypt() {
        sunshine_decrypt(
            DEFAULT_CENTRAL_KEYS_PATH,
            (*OTHER_DEFAULT_ID).clone(),
            DEFAULT_CENTRAL_OTHER_CT_PATH,
        );
    }
    #[cfg(test)]
    #[ctor::ctor]
    fn ensure_testing_material_exists() {
        use crate::util::key_setup::{ensure_threshold_keys_exist, ThresholdTestingKeys};

        ensure_dir_exist();
        ensure_central_keys_exist(
            TEST_PARAM_PATH,
            TEST_CENTRAL_KEYS_PATH,
            &TEST_KEY_ID,
            &OTHER_TEST_ID,
        );

        ensure_central_crs_store_exists(
            TEST_PARAM_PATH,
            TEST_CENTRAL_CRS_PATH,
            TEST_CENTRAL_KEYS_PATH,
            &TEST_CRS_ID,
        );

        ensure_threshold_keys_exist(
            TEST_PARAM_PATH,
            TEST_THRESHOLD_KEYS_PATH,
            &TEST_KEY_ID.to_string(),
        );

        let threshold_keys: ThresholdTestingKeys =
            read_element(&format!("{TEST_THRESHOLD_KEYS_PATH}-1.bin")).unwrap();
        ensure_ciphertext_exist(TEST_THRESHOLD_CT_PATH, &threshold_keys.fhe_pub);

        let central_keys: CentralizedTestingKeys = read_element(TEST_CENTRAL_KEYS_PATH).unwrap();
        ensure_ciphertext_exist(
            TEST_CENTRAL_CT_PATH,
            &central_keys
                .pub_fhe_keys
                .get(&TEST_KEY_ID)
                .unwrap()
                .public_key,
        );
        ensure_ciphertext_exist(
            TEST_CENTRAL_OTHER_CT_PATH,
            &central_keys
                .pub_fhe_keys
                .get(&OTHER_TEST_ID)
                .unwrap()
                .public_key,
        );
    }

    #[cfg(feature = "slow_tests")]
    #[cfg(test)]
    #[ctor::ctor]
    fn ensure_default_material_exists() {
        use crate::{
            consts::OTHER_DEFAULT_ID,
            util::key_setup::{ensure_threshold_keys_exist, ThresholdTestingKeys},
        };

        ensure_dir_exist();

        ensure_central_keys_exist(
            DEFAULT_PARAM_PATH,
            DEFAULT_CENTRAL_KEYS_PATH,
            &DEFAULT_KEY_ID,
            &OTHER_DEFAULT_ID,
        );
        ensure_central_crs_store_exists(
            DEFAULT_PARAM_PATH,
            DEFAULT_CENTRAL_CRS_PATH,
            DEFAULT_CENTRAL_KEYS_PATH,
            &DEFAULT_CRS_ID,
        );
        ensure_threshold_keys_exist(
            DEFAULT_PARAM_PATH,
            DEFAULT_THRESHOLD_KEYS_PATH,
            &DEFAULT_KEY_ID.to_string(),
        );

        let threshold_keys: ThresholdTestingKeys =
            read_element(&format!("{DEFAULT_THRESHOLD_KEYS_PATH}-1.bin")).unwrap();
        ensure_ciphertext_exist(DEFAULT_THRESHOLD_CT_PATH, &threshold_keys.fhe_pub);

        let central_keys: CentralizedTestingKeys = read_element(DEFAULT_CENTRAL_KEYS_PATH).unwrap();
        ensure_ciphertext_exist(
            DEFAULT_CENTRAL_CT_PATH,
            &central_keys
                .pub_fhe_keys
                .get(&DEFAULT_KEY_ID)
                .unwrap()
                .public_key,
        );
        ensure_ciphertext_exist(
            DEFAULT_CENTRAL_OTHER_CT_PATH,
            &central_keys
                .pub_fhe_keys
                .get(&OTHER_DEFAULT_ID)
                .unwrap()
                .public_key,
        );
    }

    #[test]
    fn multiple_test_keys_access() {
        let central_keys: CentralizedTestingKeys = read_element(TEST_CENTRAL_KEYS_PATH).unwrap();

        // try to get keys with the default handle
        let default_key = central_keys.software_kms_keys.key_info.get(&TEST_KEY_ID);
        assert!(default_key.is_some());

        // try to get keys with the some other handle
        let some_key = central_keys.software_kms_keys.key_info.get(&OTHER_TEST_ID);
        assert!(some_key.is_some());

        // try to get keys with a non-existent handle
        let wrong_key_handle = RequestId {
            request_id: "wrongKeyHandle".to_owned(),
        };
        let no_key = central_keys
            .software_kms_keys
            .key_info
            .get(&wrong_key_handle);
        assert!(no_key.is_none());
    }

    fn sunshine_decrypt(kms_key_path: &str, key_id: RequestId, cipher_path: &str) {
        simulate_decrypt(SimulationType::NoError, kms_key_path, key_id, cipher_path)
    }

    fn simulate_decrypt(
        sim_type: SimulationType,
        kms_key_path: &str,
        key_id: RequestId,
        cipher_path: &str,
    ) {
        let msg = 42_u8;
        let keys: CentralizedTestingKeys = read_element(kms_key_path).unwrap();
        let kms = {
            let inner = SoftwareKms::new(
                RamStorage::new(StorageType::PUB),
                RamStorage::from_existing_keys(&keys.software_kms_keys).unwrap(),
            )
            .unwrap();
            if sim_type == SimulationType::BadFheKey {
                set_wrong_client_key(&inner, &key_id, keys.params);
            }
            inner
        };
        let (ct, fhe_type): (Vec<u8>, FheType) = read_element(cipher_path).unwrap();
        let raw_plaintext = SoftwareKms::<FileStorage, FileStorage>::decrypt(
            &kms.key_handles
                .try_lock()
                .unwrap()
                .get(&key_id)
                .unwrap()
                .client_key,
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
            assert_ne!(plaintext.as_u8(), msg);
        } else {
            assert_eq!(plaintext.as_u8(), msg);
        }
    }

    #[test]
    fn sunshine_test_reencrypt() {
        sunshine_reencrypt(TEST_CENTRAL_KEYS_PATH, &TEST_KEY_ID, TEST_CENTRAL_CT_PATH);
    }

    #[test]
    fn reencrypt_with_bad_ephemeral_key() {
        simulate_reencrypt(
            SimulationType::BadEphemeralKey,
            TEST_CENTRAL_KEYS_PATH,
            &TEST_KEY_ID,
            TEST_CENTRAL_CT_PATH,
        )
    }

    #[test]
    fn reencrypt_with_bad_sig_key() {
        simulate_reencrypt(
            SimulationType::BadSigKey,
            TEST_CENTRAL_KEYS_PATH,
            &TEST_KEY_ID,
            TEST_CENTRAL_CT_PATH,
        )
    }

    #[test]
    fn reencrypt_with_bad_client_key() {
        simulate_reencrypt(
            SimulationType::BadFheKey,
            TEST_CENTRAL_KEYS_PATH,
            &TEST_KEY_ID,
            TEST_CENTRAL_CT_PATH,
        )
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn sunshine_default_reencrypt() {
        sunshine_reencrypt(
            DEFAULT_CENTRAL_KEYS_PATH,
            &DEFAULT_KEY_ID,
            DEFAULT_CENTRAL_CT_PATH,
        );
    }

    #[test]
    #[serial]
    fn multiple_test_keys_reencrypt() {
        sunshine_reencrypt(
            TEST_CENTRAL_KEYS_PATH,
            &OTHER_TEST_ID,
            TEST_CENTRAL_OTHER_CT_PATH,
        );
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn multiple_default_keys_reencrypt() {
        sunshine_reencrypt(
            DEFAULT_CENTRAL_KEYS_PATH,
            &OTHER_DEFAULT_ID,
            DEFAULT_CENTRAL_OTHER_CT_PATH,
        );
    }

    fn sunshine_reencrypt(kms_key_path: &str, key_handle: &RequestId, cipher_path: &str) {
        simulate_reencrypt(
            SimulationType::NoError,
            kms_key_path,
            key_handle,
            cipher_path,
        )
    }

    fn set_wrong_client_key<
        PubS: PublicStorage + Sync + Send + 'static,
        PrivS: PublicStorage + Sync + Send + 'static,
    >(
        inner: &SoftwareKms<PubS, PrivS>,
        key_handle: &RequestId,
        params: NoiseFloodParameters,
    ) {
        let pbs_params: ClassicPBSParameters = params.ciphertext_parameters;
        let config = ConfigBuilder::with_custom_parameters(pbs_params, None);
        let wrong_client_key = tfhe::ClientKey::generate(config);
        let mut key_info = inner.key_handles.try_lock().unwrap();
        let x = key_info.get_mut(key_handle).unwrap();
        let wrong_handles = KmsFheKeyHandles {
            client_key: wrong_client_key,
            public_key_info: x.public_key_info.clone(),
        };
        *x = wrong_handles;
    }

    fn set_wrong_sig_key<
        PubS: PublicStorage + Sync + Send + 'static,
        PrivS: PublicStorage + Sync + Send + 'static,
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

    fn simulate_reencrypt(
        sim_type: SimulationType,
        kms_key_path: &str,
        key_handle: &RequestId,
        cipher_path: &str,
    ) {
        let msg = 42_u8;
        let mut rng = AesRng::seed_from_u64(1);
        let keys: CentralizedTestingKeys = read_element(kms_key_path).unwrap();
        let kms = {
            let mut inner = SoftwareKms::new(
                RamStorage::new(StorageType::PUB),
                RamStorage::from_existing_keys(&keys.software_kms_keys).unwrap(),
            )
            .unwrap();
            // TODO this should be updated since things might fail with probability 1/256
            // if the key sampled randomly gives the message chosen (since it is only 8 bit)
            if sim_type == SimulationType::BadFheKey {
                set_wrong_client_key(&inner, key_handle, keys.params);
            }
            if sim_type == SimulationType::BadSigKey {
                set_wrong_sig_key(&mut inner, &mut rng);
            }
            inner
        };
        let (ct, fhe_type): (Vec<u8>, FheType) = read_element(cipher_path).unwrap();
        let link = vec![42_u8, 42, 42];
        let (_client_verf_key, client_sig_key) = gen_sig_keys(&mut rng);
        let client_keys = {
            let mut keys = ephemeral_key_generation(&mut rng, &client_sig_key);
            if sim_type == SimulationType::BadEphemeralKey {
                let bad_keys = ephemeral_key_generation(&mut rng, &client_sig_key);
                keys.sk = bad_keys.sk;
            }
            keys
        };
        let mut rng = kms.base_kms.new_rng().unwrap();
        let raw_cipher = SoftwareKms::<FileStorage, FileStorage>::reencrypt(
            &kms.key_handles
                .try_lock()
                .unwrap()
                .get(key_handle)
                .unwrap()
                .client_key,
            &kms.base_kms.sig_key,
            &mut rng,
            &ct,
            fhe_type,
            &link,
            &client_keys.pk.enc_key,
            &client_keys.pk.verification_key,
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
        let decrypted = decrypted.unwrap();
        if sim_type == SimulationType::BadSigKey {
            assert!(decrypted.is_none());
            return;
        }
        let decrypted_msg = decrypted.unwrap();
        let plaintext: Plaintext = decrypted_msg.try_into().unwrap();
        if sim_type == SimulationType::BadFheKey {
            assert_ne!(plaintext.as_u8(), msg);
        } else {
            assert_eq!(plaintext.as_u8(), msg);
        }
        assert_eq!(plaintext.fhe_type(), FheType::Euint8);
    }

    #[test]
    fn ensure_compute_info_consistency() {
        // we need compute info to work without calling the sign function from KMS,
        // i.e., only using a signing key
        // this test makes sure the output is consistent
        let kms_key_path = TEST_CENTRAL_KEYS_PATH;
        let keys: CentralizedTestingKeys = read_element(kms_key_path).unwrap();
        let kms = {
            SoftwareKms::new(
                RamStorage::new(StorageType::PUB),
                RamStorage::from_existing_keys(&keys.software_kms_keys).unwrap(),
            )
            .unwrap()
        };

        let value = "bonjour".to_string();
        let expected = super::compute_info(&kms.base_kms, &value).unwrap();
        let actual = super::compute_info_from_key(&kms.base_kms.sig_key, &value).unwrap();
        assert_eq!(expected, actual);
    }
}
