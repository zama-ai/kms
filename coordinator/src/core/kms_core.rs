use super::der_types::{PrivateSigKey, PublicEncKey, PublicSigKey, Signature};
use super::signcryption::{
    safe_hash_element, sign, sign_eip712, signcrypt, verify_sig, verify_sig_eip712, RND_SIZE,
};
use crate::anyhow_error_and_warn_log;
use crate::consts::KEY_HANDLE;
use crate::kms::FheType;
use crate::rpc::rpc_types::{BaseKms, Kms, Plaintext, RawDecryption, SigncryptionPayload};
use crate::setup_rpc::{FhePrivateKey, FhePublicKey};
use aes_prng::AesRng;
use alloy_sol_types::{Eip712Domain, SolStruct};
use der::zeroize::Zeroize;
use distributed_decryption::execution::endpoints::keygen::PubKeySet;
use distributed_decryption::execution::zk::ceremony::{make_proof_deterministic, PublicParameter};
use distributed_decryption::{
    error::error_handler::anyhow_error_and_log,
    execution::tfhe_internals::parameters::NoiseFloodParameters,
};
use k256::ecdsa::SigningKey;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_asn1_der::to_vec;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::{fmt, panic};
use tfhe::prelude::FheDecrypt;
use tfhe::shortint::ClassicPBSParameters;
use tfhe::ClientKey;
use tfhe::{ConfigBuilder, FheBool, FheUint16, FheUint32, FheUint4, FheUint64, FheUint8};
use zk_poc::curve_api::bls12_446 as curve;

fn handle_potential_err<T, E>(resp: Result<T, E>, error: String) -> anyhow::Result<T> {
    resp.map_err(|_| {
        tracing::warn!(error);
        anyhow::Error::msg(format!("Invalid request: \"{}\"", error))
    })
}

pub fn gen_sig_keys<R: CryptoRng + Rng>(rng: &mut R) -> (PublicSigKey, PrivateSigKey) {
    let sk = SigningKey::random(rng);
    let pk = SigningKey::verifying_key(&sk);
    (PublicSigKey { pk: *pk }, PrivateSigKey { sk })
}

pub fn gen_default_kms_keys<R: CryptoRng + RngCore>(
    params: NoiseFloodParameters,
    rng: &mut R,
    key_handle: Option<String>,
) -> (SoftwareKmsKeys, PubKeySet) {
    let (client_key, fhe_pub_keys) = generate_fhe_keys(params);
    let (sig_pk, sig_sk) = gen_sig_keys(rng);
    let handle = key_handle.unwrap_or(KEY_HANDLE.to_string());
    (
        SoftwareKmsKeys {
            client_keys: HashMap::from([(handle, client_key)]),
            sig_sk,
            sig_pk,
        },
        fhe_pub_keys,
    )
}

pub fn generate_fhe_keys(params: NoiseFloodParameters) -> (FhePrivateKey, PubKeySet) {
    let client_key = generate_client_fhe_key(params);
    let server_key = client_key.generate_server_key();
    let public_key = FhePublicKey::new(&client_key);
    let pks = PubKeySet {
        public_key,
        server_key,
        sns_key: None,
    };
    (client_key, pks)
}

pub fn generate_client_fhe_key(params: NoiseFloodParameters) -> ClientKey {
    let pbs_params: ClassicPBSParameters = params.ciphertext_parameters;
    let config = ConfigBuilder::with_custom_parameters(pbs_params, None);
    ClientKey::generate(config)
}

/// Compute an estimate for the witness dim from given LWE params. This might come out of tfhe-rs in
/// the future.
fn compute_witness_dimension(params: &NoiseFloodParameters) -> usize {
    let d = params.ciphertext_parameters.lwe_dimension.0;
    let k = 32_usize; // this is an upper estimate for a packed 64 bit message and in line with the example in https://eprint.iacr.org/2023/800.pdf p.68
    let t = params.ciphertext_parameters.message_modulus.0;
    let b = 1_u64 << 42; // this is an estimate from https://eprint.iacr.org/2023/800.pdf p.68 and will come from the parameters in the future

    // dimension computation taken from https://eprint.iacr.org/2023/800.pdf p.68. Will come from the parameters in the future.
    let big_d =
        d + k * t.ilog2() as usize + (d + k) * (1 + b.ilog2() as usize + d.ilog2() as usize);

    big_d + 1
}

/// compute the CRS in the centralized KMS.
pub(crate) fn gen_centralized_crs<R: Rng + CryptoRng>(
    params: &NoiseFloodParameters,
    rng: &mut R,
) -> PublicParameter {
    let witness_dim = compute_witness_dimension(params);
    tracing::info!("Generating CRS with witness dimension {}.", witness_dim);
    let pparam = PublicParameter::new(witness_dim);

    let mut tau = curve::Zp::rand(rng);
    let mut r = curve::Zp::rand(rng);
    let pproof = make_proof_deterministic(&pparam, tau, 1, r);
    tau.zeroize();
    r.zeroize();

    pproof.new_pp
}

#[derive(Clone)]
pub struct BaseKmsStruct {
    pub(crate) sig_key: PrivateSigKey,
    pub(crate) rng: Arc<Mutex<AesRng>>,
}

impl BaseKmsStruct {
    pub fn new(sig_sk: PrivateSigKey) -> Self {
        BaseKmsStruct {
            sig_key: sig_sk,
            rng: Arc::new(Mutex::new(AesRng::from_entropy())),
        }
    }

    pub(crate) fn new_rng(&self) -> anyhow::Result<AesRng> {
        let mut seed = [0u8; RND_SIZE];
        // Make a seperate scope for the rng so that it is dropped before the lock is released
        {
            let mut base_rng =
                handle_potential_err(self.rng.lock(), "Could not lock rng".to_owned())?;
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
        T: Serialize,
    {
        let msg = match to_vec(payload) {
            Ok(msg) => msg,
            Err(e) => {
                tracing::warn!(
                    "Could not encode payload for signature verification: {:?}",
                    e,
                );
                return false;
            }
        };
        if !verify_sig(&msg, signature, key) {
            return false;
        }
        true
    }

    fn sign<T>(&self, msg: &T) -> anyhow::Result<super::der_types::Signature>
    where
        T: Serialize,
    {
        let to_sign = match to_vec(msg) {
            Ok(to_sign) => to_sign,
            Err(e) => {
                return Err(anyhow_error_and_warn_log(format!(
                    "Could not encode message for signing: {:?}",
                    e
                )));
            }
        };
        sign(&to_sign, &self.sig_key)
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
        safe_hash_element(msg)
    }

    fn verify_sig_eip712<T: SolStruct>(
        payload: &T,
        domain: &Eip712Domain,
        signature: &Signature,
        verification_key: &PublicSigKey,
    ) -> bool {
        verify_sig_eip712(payload, domain, signature, verification_key)
    }

    fn sign_eip712<T: SolStruct>(
        &self,
        msg: &T,
        domain: &Eip712Domain,
    ) -> anyhow::Result<Signature> {
        sign_eip712(msg, domain, &self.sig_key)
    }
}

#[derive(Serialize, Deserialize)]
pub struct SoftwareKmsKeys {
    pub client_keys: HashMap<String, FhePrivateKey>,
    pub sig_sk: PrivateSigKey,
    pub sig_pk: PublicSigKey,
}

pub type CrsHashMap = HashMap<String, PublicParameter>;

/// Software based KMS where keys are stored in a local file
pub struct SoftwareKms {
    base_kms: BaseKmsStruct,
    pub client_keys: Arc<Mutex<HashMap<String, FhePrivateKey>>>,
    pub crs_store: Arc<Mutex<CrsHashMap>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SignedCRS {
    pub crs: PublicParameter,
    pub signature: Signature,
}

impl SignedCRS {
    pub fn new<K: BaseKms>(crs: &PublicParameter, base_kms: &K) -> anyhow::Result<Self> {
        let serialized = bincode::serialize(crs)?;
        let signature = base_kms.sign(&serialized)?;
        Ok(SignedCRS {
            crs: crs.clone(),
            signature,
        })
    }

    pub fn verify_signature(&self, verf_key: &PublicSigKey) -> bool {
        let serialized = match bincode::serialize(&self.crs) {
            Ok(serialized) => serialized,
            Err(_) => {
                tracing::warn!("Could not serialize CRS");
                return false;
            }
        };
        BaseKmsStruct::verify_sig(&serialized, &self.signature, verf_key)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SignedFhePublicKeySet {
    pub public_key_set: PubKeySet,
    pub signature: Signature,
}

impl SignedFhePublicKeySet {
    pub fn new<K: BaseKms>(public_key_set: PubKeySet, base_kms: &K) -> anyhow::Result<Self> {
        // TODO it should not be needed to "preserialize" here
        // However, due to lack of support in serde_asn1, this currently does not work for tfhe-rs
        // public keys Hence we need another approach to serialize these for now.
        let serialized = bincode::serialize(&public_key_set)?;
        let signature = base_kms.sign(&serialized)?;
        Ok(SignedFhePublicKeySet {
            public_key_set,
            signature,
        })
    }

    pub fn verify_signature(&self, verf_key: &PublicSigKey) -> bool {
        let serialized = match bincode::serialize(&self.public_key_set) {
            Ok(serialized) => serialized,
            Err(_) => {
                tracing::warn!("Could not serialize keyset");
                return false;
            }
        };
        BaseKmsStruct::verify_sig(&serialized, &self.signature, verf_key)
    }
}

// impl fmt::Debug for SoftwareKms, we don't want to include the decryption key in the debug output
impl fmt::Debug for SoftwareKms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareKms")
            .field("sig_key", &self.base_kms.sig_key)
            .finish() // Don't include fhe_dec_key
    }
}

impl BaseKms for SoftwareKms {
    fn verify_sig<T: Serialize>(
        payload: &T,
        signature: &super::der_types::Signature,
        verification_key: &PublicSigKey,
    ) -> bool {
        BaseKmsStruct::verify_sig(payload, signature, verification_key)
    }

    fn sign<T: Serialize>(&self, msg: &T) -> anyhow::Result<super::der_types::Signature> {
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

impl Kms for SoftwareKms {
    fn decrypt(
        &self,
        high_level_ct: &[u8],
        fhe_type: FheType,
        key_handle: &str,
    ) -> anyhow::Result<Plaintext> {
        let client_keys = handle_potential_err(
            self.client_keys.lock(),
            "Could not get handle on client keys".to_string(),
        )?;
        let client_key = match client_keys.get(key_handle) {
            Some(client_key) => client_key,
            None => {
                return Err(anyhow_error_and_log(format!(
                    "The key handle {key_handle} does not exist"
                )))
            }
        };
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
            })
        };
        match panic::catch_unwind(f) {
            Ok(x) => x,
            Err(_) => Err(anyhow_error_and_log("decryption panicked".to_string())),
        }
    }

    fn reencrypt(
        &self,
        ct: &[u8],
        fhe_type: FheType,
        req_digest: &[u8],
        client_enc_key: &PublicEncKey,
        client_verf_key: &PublicSigKey,
        key_handle: &str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let plaintext = Kms::decrypt(self, ct, fhe_type, key_handle)?;
        // Observe that we encrypt the plaintext itself, this is different from the threshold case
        // where it is first mapped to a Vec<Residuepoly<Z128>> element
        let raw_decryption =
            RawDecryption::new(plaintext.as_u128().to_le_bytes().to_vec(), fhe_type);
        let signcryption_msg = SigncryptionPayload {
            raw_decryption,
            req_digest: req_digest.to_vec(),
        };
        let enc_res = signcrypt(
            &mut self.base_kms.new_rng()?,
            &serde_asn1_der::to_vec(&signcryption_msg)?,
            client_enc_key,
            client_verf_key,
            &self.base_kms.sig_key,
        )?;
        let res = to_vec(&enc_res)?;
        tracing::info!("Completed reencyption of ciphertext");
        Ok(Some(res))
    }
}

impl SoftwareKms {
    pub fn new(
        client_keys: HashMap<String, FhePrivateKey>,
        sig_key: PrivateSigKey,
        crs_store: Option<CrsHashMap>,
    ) -> Self {
        // Use crs_store passed in if it exists, otherwise create a new one
        let cs = match crs_store {
            Some(crs_store) => crs_store,
            None => CrsHashMap::new(),
        };

        SoftwareKms {
            base_kms: BaseKmsStruct::new(sig_key),
            client_keys: Arc::new(Mutex::new(client_keys)),
            crs_store: Arc::new(Mutex::new(cs)),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "slow_tests")]
    use crate::consts::{
        DEFAULT_CENTRAL_CRS_PATH, DEFAULT_CENTRAL_CT_PATH, DEFAULT_CENTRAL_KEYS_PATH,
        DEFAULT_CENTRAL_MULTI_CT_PATH, DEFAULT_CENTRAL_MULTI_KEYS_PATH, DEFAULT_CRS_HANDLE,
        DEFAULT_PARAM_PATH, DEFAULT_THRESHOLD_CT_PATH, DEFAULT_THRESHOLD_KEYS_PATH,
    };
    use crate::consts::{
        KEY_HANDLE, OTHER_KEY_HANDLE, TEST_CENTRAL_CRS_PATH, TEST_CENTRAL_CT_PATH,
        TEST_CENTRAL_KEYS_PATH, TEST_CENTRAL_MULTI_CT_PATH, TEST_CENTRAL_MULTI_KEYS_PATH,
        TEST_CRS_HANDLE, TEST_PARAM_PATH, TEST_THRESHOLD_CT_PATH, TEST_THRESHOLD_KEYS_PATH,
    };
    use crate::core::der_types::PrivateSigKey;
    use crate::core::kms_core::{gen_sig_keys, SoftwareKms};
    use crate::core::request::ephemeral_key_generation;
    use crate::core::signcryption::decrypt_signcryption;
    use crate::file_handling::read_element;
    use crate::kms::FheType;
    use crate::rpc::rpc_types::{Kms, Plaintext};
    use crate::setup_rpc::{
        ensure_central_crs_store_exists, ensure_central_key_ct_exist,
        ensure_central_multiple_keys_ct_exist, ensure_dir_exist, ensure_threshold_key_ct_exist,
        CentralizedTestingKeys,
    };
    use aes_prng::AesRng;
    use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
    use rand::{RngCore, SeedableRng};
    use serial_test::serial;
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
        sunshine_decrypt(TEST_CENTRAL_KEYS_PATH, KEY_HANDLE, TEST_CENTRAL_CT_PATH);
    }

    #[test]
    fn decrypt_with_bad_client_key() {
        simulate_decrypt(
            SimulationType::BadFheKey,
            TEST_CENTRAL_KEYS_PATH,
            KEY_HANDLE,
            TEST_CENTRAL_CT_PATH,
        );
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn sunshine_default_decrypt() {
        sunshine_decrypt(
            DEFAULT_CENTRAL_KEYS_PATH,
            KEY_HANDLE,
            DEFAULT_CENTRAL_CT_PATH,
        );
    }

    #[test]
    #[serial]
    fn multiple_test_keys_decrypt() {
        sunshine_decrypt(
            TEST_CENTRAL_MULTI_KEYS_PATH,
            OTHER_KEY_HANDLE,
            TEST_CENTRAL_MULTI_CT_PATH,
        );
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn multiple_default_keys_decrypt() {
        sunshine_decrypt(
            DEFAULT_CENTRAL_MULTI_KEYS_PATH,
            OTHER_KEY_HANDLE,
            DEFAULT_CENTRAL_MULTI_CT_PATH,
        );
    }
    #[cfg(test)]
    #[ctor::ctor]
    fn ensure_testing_material_exists() {
        ensure_dir_exist();

        ensure_central_crs_store_exists(
            TEST_PARAM_PATH,
            TEST_CENTRAL_CRS_PATH,
            Some(TEST_CRS_HANDLE.to_string()),
        );

        ensure_central_key_ct_exist(
            TEST_PARAM_PATH,
            TEST_CENTRAL_KEYS_PATH,
            TEST_CENTRAL_CT_PATH,
        );

        ensure_threshold_key_ct_exist(
            TEST_PARAM_PATH,
            TEST_THRESHOLD_KEYS_PATH,
            TEST_THRESHOLD_CT_PATH,
        );

        ensure_central_multiple_keys_ct_exist(
            TEST_PARAM_PATH,
            TEST_CENTRAL_MULTI_KEYS_PATH,
            OTHER_KEY_HANDLE,
            TEST_CENTRAL_MULTI_CT_PATH,
        );
    }

    #[cfg(feature = "slow_tests")]
    #[cfg(test)]
    #[ctor::ctor]
    fn ensure_default_material_exists() {
        ensure_dir_exist();

        ensure_central_crs_store_exists(
            DEFAULT_PARAM_PATH,
            DEFAULT_CENTRAL_CRS_PATH,
            Some(DEFAULT_CRS_HANDLE.to_string()),
        );

        ensure_central_key_ct_exist(
            DEFAULT_PARAM_PATH,
            DEFAULT_CENTRAL_KEYS_PATH,
            DEFAULT_CENTRAL_CT_PATH,
        );

        ensure_threshold_key_ct_exist(
            DEFAULT_PARAM_PATH,
            DEFAULT_THRESHOLD_KEYS_PATH,
            DEFAULT_THRESHOLD_CT_PATH,
        );

        ensure_central_multiple_keys_ct_exist(
            DEFAULT_PARAM_PATH,
            DEFAULT_CENTRAL_MULTI_KEYS_PATH,
            OTHER_KEY_HANDLE,
            DEFAULT_CENTRAL_MULTI_CT_PATH,
        );
    }

    #[test]
    fn multiple_test_keys_access() {
        let central_keys: CentralizedTestingKeys =
            read_element(TEST_CENTRAL_MULTI_KEYS_PATH).unwrap();

        // try to get keys with the default handle
        let default_key = central_keys.software_kms_keys.client_keys.get(KEY_HANDLE);
        assert!(default_key.is_some());

        // try to get keys with the some other handle
        let some_key = central_keys
            .software_kms_keys
            .client_keys
            .get(OTHER_KEY_HANDLE);
        assert!(some_key.is_some());

        // try to get keys with a non-existent handle
        let no_key = central_keys
            .software_kms_keys
            .client_keys
            .get("wrongKeyHandle");
        assert!(no_key.is_none());
    }

    fn sunshine_decrypt(kms_key_path: &str, key_handle: &str, cipher_path: &str) {
        simulate_decrypt(
            SimulationType::NoError,
            kms_key_path,
            key_handle,
            cipher_path,
        )
    }

    fn simulate_decrypt(
        sim_type: SimulationType,
        kms_key_path: &str,
        key_handle: &str,
        cipher_path: &str,
    ) {
        let msg = 42_u8;
        let keys: CentralizedTestingKeys = read_element(kms_key_path).unwrap();
        let kms = {
            let inner = SoftwareKms::new(
                keys.software_kms_keys.client_keys.clone(),
                keys.software_kms_keys.sig_sk,
                None,
            );
            if sim_type == SimulationType::BadFheKey {
                set_wrong_client_key(&inner, key_handle, keys.params);
            }
            inner
        };
        let (ct, fhe_type): (Vec<u8>, FheType) = read_element(cipher_path).unwrap();
        let plaintext: Plaintext = match kms.decrypt(&ct, fhe_type, key_handle) {
            Ok(x) => x,
            Err(e) => {
                assert!(e.to_string().contains("decryption panicked"));
                return;
            }
        };
        if sim_type == SimulationType::BadFheKey {
            assert_ne!(plaintext.as_u8(), msg);
        } else {
            assert_eq!(plaintext.as_u8(), msg);
        }
    }

    #[test]
    fn sunshine_test_reencrypt() {
        sunshine_reencrypt(TEST_CENTRAL_KEYS_PATH, KEY_HANDLE, TEST_CENTRAL_CT_PATH);
    }

    #[test]
    fn reencrypt_with_bad_ephemeral_key() {
        simulate_reencrypt(
            SimulationType::BadEphemeralKey,
            TEST_CENTRAL_KEYS_PATH,
            KEY_HANDLE,
            TEST_CENTRAL_CT_PATH,
        )
    }

    #[test]
    fn reencrypt_with_bad_sig_key() {
        simulate_reencrypt(
            SimulationType::BadSigKey,
            TEST_CENTRAL_KEYS_PATH,
            KEY_HANDLE,
            TEST_CENTRAL_CT_PATH,
        )
    }

    #[test]
    fn reencrypt_with_bad_client_key() {
        simulate_reencrypt(
            SimulationType::BadFheKey,
            TEST_CENTRAL_KEYS_PATH,
            KEY_HANDLE,
            TEST_CENTRAL_CT_PATH,
        )
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn sunshine_default_reencrypt() {
        sunshine_reencrypt(
            DEFAULT_CENTRAL_KEYS_PATH,
            KEY_HANDLE,
            DEFAULT_CENTRAL_CT_PATH,
        );
    }

    #[test]
    #[serial]
    fn multiple_test_keys_reencrypt() {
        sunshine_reencrypt(
            TEST_CENTRAL_MULTI_KEYS_PATH,
            OTHER_KEY_HANDLE,
            TEST_CENTRAL_MULTI_CT_PATH,
        );
    }

    #[cfg(feature = "slow_tests")]
    #[test]
    fn multiple_default_keys_reencrypt() {
        sunshine_reencrypt(
            DEFAULT_CENTRAL_MULTI_KEYS_PATH,
            OTHER_KEY_HANDLE,
            DEFAULT_CENTRAL_MULTI_CT_PATH,
        );
    }

    fn sunshine_reencrypt(kms_key_path: &str, key_handle: &str, cipher_path: &str) {
        simulate_reencrypt(
            SimulationType::NoError,
            kms_key_path,
            key_handle,
            cipher_path,
        )
    }

    fn set_wrong_client_key(inner: &SoftwareKms, key_handle: &str, params: NoiseFloodParameters) {
        let pbs_params: ClassicPBSParameters = params.ciphertext_parameters;
        let config = ConfigBuilder::with_custom_parameters(pbs_params, None);
        let wrong_client_key = tfhe::ClientKey::generate(config);
        let mut client_keys = inner.client_keys.lock().unwrap();
        let x = client_keys.get_mut(key_handle).unwrap();
        *x = wrong_client_key;
    }

    fn set_wrong_sig_key(inner: &mut SoftwareKms, rng: &mut AesRng) {
        // move to the next state so ensure we're generating a different ecdsa key
        _ = rng.next_u64();
        let wrong_ecdsa_key = k256::ecdsa::SigningKey::random(rng);
        assert_ne!(wrong_ecdsa_key, inner.base_kms.sig_key.sk);
        inner.base_kms.sig_key = PrivateSigKey {
            sk: wrong_ecdsa_key,
        };
    }

    fn simulate_reencrypt(
        sim_type: SimulationType,
        kms_key_path: &str,
        key_handle: &str,
        cipher_path: &str,
    ) {
        let msg = 42_u8;
        let mut rng = AesRng::seed_from_u64(1);
        let keys: CentralizedTestingKeys = read_element(kms_key_path).unwrap();
        let params = keys.params;
        let kms = {
            let mut inner = SoftwareKms::new(
                keys.software_kms_keys.client_keys.clone(),
                keys.software_kms_keys.sig_sk,
                None,
            );
            if sim_type == SimulationType::BadFheKey {
                set_wrong_client_key(&inner, key_handle, params);
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
        let raw_cipher = kms.reencrypt(
            &ct,
            fhe_type,
            &link,
            &client_keys.pk.enc_key,
            &client_keys.pk.verification_key,
            key_handle,
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
        }
        .unwrap();
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
}
