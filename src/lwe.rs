use crate::algebra::base_ring::Z128;
use crate::algebra::poly::Poly;
use crate::algebra::residue_poly::ResiduePoly;
use crate::algebra::residue_poly::ResiduePoly128;
use crate::algebra::residue_poly::ResiduePoly64;
use crate::algebra::structure_traits::BaseRing;
use crate::algebra::structure_traits::Zero;
use crate::execution::constants::REAL_KEY_PATH;
use crate::execution::random::get_rng;
use crate::execution::random::secret_rng_from_seed;
use crate::execution::random::seed_from_rng;
use crate::execution::sharing::shamir::RingEmbed;
use crate::file_handling::read_as_json;
use aligned_vec::ABox;
use core::fmt;
use core::fmt::Debug;
use ndarray::Array1;
use num_integer::div_ceil;
use num_traits::AsPrimitive;
use rand::{CryptoRng, Rng};
use serde::Deserialize;
use serde::Serialize;
use std::num::Wrapping;
use tfhe::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::prelude::allocate_and_generate_new_binary_glwe_secret_key;
use tfhe::core_crypto::prelude::allocate_and_generate_new_binary_lwe_secret_key;
use tfhe::core_crypto::prelude::allocate_and_generate_new_lwe_compact_public_key;
use tfhe::core_crypto::prelude::convert_standard_lwe_bootstrap_key_to_fourier_128;
use tfhe::core_crypto::prelude::decrypt_lwe_ciphertext;
use tfhe::core_crypto::prelude::encrypt_lwe_ciphertext_with_compact_public_key;
use tfhe::core_crypto::prelude::par_generate_lwe_bootstrap_key;
use tfhe::core_crypto::prelude::ActivatedRandomGenerator;
use tfhe::core_crypto::prelude::EncryptionRandomGenerator;
use tfhe::core_crypto::prelude::Fourier128LweBootstrapKey;
use tfhe::core_crypto::prelude::LweBootstrapKey;
use tfhe::core_crypto::prelude::LweCiphertext;
use tfhe::core_crypto::prelude::LweCiphertextOwned;
use tfhe::core_crypto::prelude::LweSecretKey;
use tfhe::core_crypto::prelude::LweSecretKeyOwned;
use tfhe::core_crypto::prelude::Plaintext;
use tfhe::core_crypto::prelude::UnsignedInteger;
use tfhe::core_crypto::prelude::*;
use tfhe::core_crypto::prelude::{
    programmable_bootstrap_f128_lwe_ciphertext, CastFrom, GlweCiphertextOwned, GlweSize,
    UnsignedTorus,
};
use tfhe::core_crypto::seeders::new_seeder;
use tfhe::core_crypto::seeders::Seeder;
use tfhe::integer::block_decomposition::BlockDecomposer;
use tfhe::integer::block_decomposition::BlockRecomposer;
use tfhe::integer::block_decomposition::DecomposableInto;
use tfhe::shortint::prelude::DecompositionBaseLog;
use tfhe::shortint::prelude::DecompositionLevelCount;
use tfhe::shortint::prelude::GlweDimension;
use tfhe::shortint::prelude::LweDimension;
use tfhe::shortint::prelude::PolynomialSize;
use tfhe::shortint::prelude::StandardDev;
use tfhe::shortint::MessageModulus;
use zeroize::Zeroize;

// Copied from tfhe-rs lwe_noise_gap_programmable_bootstrapping since it is only specified in their test code
#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq)]
pub struct CiphertextParameters<S>
where
    S: UnsignedInteger + Copy,
{
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_modular_std_dev: StandardDev,
    pub glwe_modular_std_dev: StandardDev,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub message_modulus_log: MessageModulus, //NOTE: IN TFHE RS THIS IS NOT LOG BUT THE ACTUAL MODULUS
    pub usable_message_modulus_log: MessageModulus, //NOTE: THIS DOES NOT EXISTS IN TFHE RS + SAME AS ABOVE
    pub ciphertext_modulus: CiphertextModulus<S>,
}

#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq)]
pub struct ThresholdLWEParameters {
    pub input_cipher_parameters: CiphertextParameters<u64>,
    pub output_cipher_parameters: CiphertextParameters<u128>,
}

pub(crate) fn gen_single_party_share<R: Rng + CryptoRng, Z>(
    rng: &mut R,
    secret: Z,
    threshold: usize,
    party_id: usize,
) -> anyhow::Result<ResiduePoly<Z>>
where
    Z: BaseRing,
    ResiduePoly<Z>: RingEmbed,
{
    let embedded_secret = ResiduePoly::from_scalar(secret);
    let poly = Poly::sample_random_with_fixed_constant(rng, embedded_secret, threshold);
    let share = poly.eval(&ResiduePoly::embed_exceptional_set(party_id)?);
    Ok(share)
}

/// Map a raw, decrypted message to its real value by dividing by the appropriate shift, delta, assuming padding
pub(crate) fn from_expanded_msg<Scalar: UnsignedInteger + AsPrimitive<u128>>(
    raw_plaintext: Scalar,
    message_mod_bits: usize,
) -> Z128 {
    // delta = q/t where t is the amount of plain text bits
    // Observe we actually divide this by 2 (i.e. subtract 1 bit) to make space for padding
    let delta_pad_bits = (Scalar::BITS as u128) - (message_mod_bits as u128 + 1_u128);

    // compute delta / 2
    let delta_pad_half = 1 << (delta_pad_bits - 1);

    // add delta/2 to kill the negative noise, note this does not affect the message.
    let raw_msg = raw_plaintext.as_().wrapping_add(delta_pad_half) >> delta_pad_bits;

    let msg = Wrapping(raw_msg % (1 << message_mod_bits));
    // Observe that in certain situations the computation of b-<a,s> may be negative
    // Concretely this happens when the message encrypted is 0 and randomness ends up being negative.
    // We cannot simply do the standard modulo operation then, as this would mean the message becomes
    // 2^message_mod_bits instead of 0 as it should be.
    // However the maximal negative value it can have (without a general decryption error) is delta/2
    // which we can compute as 1 << delta_pad_bits, since the padding already halves the true delta
    if raw_plaintext.as_() > Scalar::MAX.as_() - (1 << delta_pad_bits) {
        Z128::ZERO
    } else {
        msg
    }
}

/// Map a real message, of a few bits, to the encryption domain, by applying the appropriate shift, delta.
/// The function assumes padding will be used.
pub(crate) fn to_expanded_msg(message: u64, message_mod_bits: usize) -> Plaintext<u64> {
    let sanitized_msg = message % (1 << message_mod_bits);
    // Observe we shift with u64::BITS - 1 to allow for the padding bit so PBS can be used on the ciphertext made from this
    let delta_bits = (u64::BITS - 1) - message_mod_bits as u32;
    Plaintext(sanitized_msg << delta_bits)
}

/// Map a distributedly decrypting ring element from Z_{2^128}[X] to its message.
/// That is, take the constant term of the polynomial and divide by the appropriate delta.
pub fn value_to_message(rec_value: Z128, message_mod_bits: usize) -> anyhow::Result<Z128> {
    Ok(from_expanded_msg(rec_value.0, message_mod_bits))
}

pub fn gen_key_set<R: Rng + CryptoRng>(
    threshold_lwe_parameters: ThresholdLWEParameters,
    rng: &mut R,
) -> KeySet {
    let input_param = threshold_lwe_parameters.input_cipher_parameters;
    let output_param = threshold_lwe_parameters.output_cipher_parameters;
    let mut secret_rng = secret_rng_from_seed(seed_from_rng(rng).0);
    let mut deterministic_seeder =
        DeterministicSeeder::<ActivatedRandomGenerator>::new(seed_from_rng(rng));
    let mut enc_rng = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
        deterministic_seeder.seed(),
        &mut deterministic_seeder,
    );

    // let mut rng = secret_rng_from_seed(seed_from_rng(rng).0);
    let input_lwe_secret_key: LweSecretKey<Vec<u64>> =
        allocate_and_generate_new_binary_lwe_secret_key(
            threshold_lwe_parameters
                .input_cipher_parameters
                .lwe_dimension,
            &mut secret_rng,
        );
    //BSK generation
    let output_glwe_secret_key_out = allocate_and_generate_new_binary_glwe_secret_key(
        output_param.glwe_dimension,
        output_param.polynomial_size,
        &mut secret_rng,
    );
    let output_lwe_secret_key_out = output_glwe_secret_key_out.clone().into_lwe_secret_key();

    // BSK generation
    let intput_glwe_secret_key: GlweSecretKey<Vec<u64>> =
        allocate_and_generate_new_binary_glwe_secret_key(
            input_param.glwe_dimension,
            input_param.polynomial_size,
            &mut secret_rng,
        );
    // let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();
    let sk = SecretKey::new(
        threshold_lwe_parameters,
        input_lwe_secret_key.clone(),
        intput_glwe_secret_key,
        output_lwe_secret_key_out,
    );

    // TODO OUTCOMMENTED CODE might not be needed for us
    // let mut bsk_in = LweBootstrapKey::new(
    //     0_u64,
    //     input_param.glwe_dimension.to_glwe_size(),
    //     input_param.polynomial_size,
    //     input_param.pbs_base_log,
    //     input_param.pbs_level,
    //     input_param.lwe_dimension,
    //     input_param.ciphertext_modulus,
    // );

    // par_generate_lwe_bootstrap_key(
    //     &input_lwe_secret_key,
    //     &output_glwe_secret_key,
    //     &mut bsk_in,
    //     input_param.glwe_modular_std_dev,
    //     &mut enc_rng,
    // );

    // let mut fbsk_in = FourierLweBootstrapKey::new(
    //     input_param.lwe_dimension,
    //     input_param.glwe_dimension.to_glwe_size(),
    //     input_param.polynomial_size,
    //     input_param.pbs_base_log,
    //     input_param.pbs_level,
    // );

    // convert_standard_lwe_bootstrap_key_to_fourier(&bsk_in, &mut fbsk_in);
    // drop(bsk_in);

    // //KSK after the PBS
    // let ksk_in = allocate_and_generate_new_lwe_keyswitch_key(
    //     &output_glwe_secret_key.into_lwe_secret_key(),
    //     &input_lwe_secret_key,
    //     input_param.ks_base_log,
    //     input_param.ks_level,
    //     input_param.lwe_modular_std_dev,
    //     input_param.ciphertext_modulus,
    //     &mut enc_rng,
    // );

    // Convert to u128 key
    let mut input_lwe_secret_key_out =
        LweSecretKey::new_empty_key(0_u128, input_param.lwe_dimension);
    input_lwe_secret_key_out
        .as_mut()
        .iter_mut()
        .zip(input_lwe_secret_key.as_ref().iter())
        .for_each(|(dst, &src)| *dst = src as u128);

    let mut bsk_out = LweBootstrapKey::new(
        0_u128,
        output_param.glwe_dimension.to_glwe_size(),
        output_param.polynomial_size,
        output_param.pbs_base_log,
        output_param.pbs_level,
        input_param.lwe_dimension,
        output_param.ciphertext_modulus,
    );

    par_generate_lwe_bootstrap_key(
        &input_lwe_secret_key_out,
        &output_glwe_secret_key_out,
        &mut bsk_out,
        output_param.glwe_modular_std_dev,
        &mut enc_rng,
    );

    let mut fbsk_out = Fourier128LweBootstrapKey::new(
        input_param.lwe_dimension,
        output_param.glwe_dimension.to_glwe_size(),
        output_param.polynomial_size,
        output_param.pbs_base_log,
        output_param.pbs_level,
    );

    convert_standard_lwe_bootstrap_key_to_fourier_128(&bsk_out, &mut fbsk_out);
    drop(bsk_out);

    let ck = BootstrappingKey::new(threshold_lwe_parameters, fbsk_out);
    let pk = PublicKey::new_seeded(&mut enc_rng, &sk);

    KeySet { pk, ck, sk }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SecretKeyShare {
    pub input_key_share128: Array1<ResiduePoly128>,
    pub input_key_share64: Array1<ResiduePoly64>,
    pub threshold_lwe_parameters: ThresholdLWEParameters,
}

// Couldn't derive Zeroize because Array1 does not implement Zeroize
// so we manually erase the shares
impl Zeroize for SecretKeyShare {
    fn zeroize(&mut self) {
        for s in &mut self.input_key_share128 {
            s.zeroize();
        }
        for s in &mut self.input_key_share64 {
            s.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SecretKey {
    // Key for decrypting ciphertexts in the 64 bit format
    pub lwe_secret_key_64: LweSecretKeyOwned<u64>, // only used for constructing public key and debugging
    pub glwe_secret_key_64: GlweSecretKeyOwned<u64>,
    // Key for decrypting ciphertexts in the 128 bit format
    pub lwe_secret_key_128: LweSecretKeyOwned<u128>,
    pub threshold_lwe_parameters: ThresholdLWEParameters,
}
impl Default for SecretKey {
    fn default() -> Self {
        let default_params: ThresholdLWEParameters =
            read_as_json(REAL_KEY_PATH.to_string()).unwrap();
        let keyset = gen_key_set(default_params, &mut get_rng());
        keyset.sk
    }
}
impl SecretKey {
    pub fn new(
        threshold_lwe_parameters: ThresholdLWEParameters,
        lwe_secret_key_64: LweSecretKeyOwned<u64>,
        glwe_secret_key_64: GlweSecretKeyOwned<u64>,
        lwe_secret_key_128: LweSecretKeyOwned<u128>,
    ) -> Self {
        SecretKey {
            lwe_secret_key_64,
            glwe_secret_key_64,
            lwe_secret_key_128,
            threshold_lwe_parameters,
        }
    }

    pub fn decrypt_block_64(&self, ct: &Ciphertext64Block) -> Z128 {
        let raw_plaintext = decrypt_lwe_ciphertext(&self.lwe_secret_key_64, ct);
        from_expanded_msg(
            raw_plaintext.0,
            self.threshold_lwe_parameters
                .output_cipher_parameters
                .message_modulus_log
                .0,
        )
    }

    pub fn decrypt_block_128(&self, ct: &Ciphertext128Block) -> Z128 {
        let raw_plaintext = decrypt_lwe_ciphertext(&self.lwe_secret_key_128, ct);
        from_expanded_msg(
            raw_plaintext.0,
            self.threshold_lwe_parameters
                .output_cipher_parameters
                .message_modulus_log
                .0,
        )
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct PublicKey {
    // TODO this should be changed to the high level public key, see issue 333
    pub public_key: LweCompactPublicKey<Vec<u64>>,
    pub threshold_lwe_parameters: ThresholdLWEParameters,
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Public key vector{:?}", self.public_key.clone())
    }
}

/// keygen that generates secret key shares for a single given party and a public key
impl PublicKey {
    pub fn new_seeded(
        rng: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
        secret_key: &SecretKey,
    ) -> Self {
        let input_compact_lwe_public_key = allocate_and_generate_new_lwe_compact_public_key(
            &secret_key.lwe_secret_key_64,
            secret_key
                .threshold_lwe_parameters
                .input_cipher_parameters
                .lwe_modular_std_dev,
            secret_key
                .threshold_lwe_parameters
                .input_cipher_parameters
                .ciphertext_modulus,
            rng,
        );

        PublicKey {
            public_key: input_compact_lwe_public_key,
            threshold_lwe_parameters: secret_key.threshold_lwe_parameters,
        }
    }

    pub fn new(secret_key: &SecretKey) -> Self {
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut rng =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
        Self::new_seeded(&mut rng, secret_key)
    }

    /// Encrypts a [message], which is an unsigned integer using a explicit randomness generator [rng].
    pub fn encrypt<T: DecomposableInto<u64> + UnsignedInteger, R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        message: T,
    ) -> Ciphertext64 {
        self.encrypt_w_bitlimit(rng, message, T::BITS)
    }

    /// Encrypts a [message] into a cipher with [bits_to_encrypt] bits domain, using a explicit randomness generator [rng].
    /// That is, the argument [bits_to_encrypt] defines the amount of plaintext bit that should be in the resultant cipher regardless of the type T of [message].
    pub fn encrypt_w_bitlimit<T: DecomposableInto<u64> + UnsignedInteger, R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        message: T,
        bits_to_encrypt: usize,
    ) -> Ciphertext64 {
        // TODO @Dragos do you know how we make a comparison on message of type T to ensure that bits_to_encrypt is able to contain the entire message?
        let bits_in_block = self
            .threshold_lwe_parameters
            .input_cipher_parameters
            .usable_message_modulus_log
            .0;
        let decomposer = BlockDecomposer::new(message, bits_in_block as u32);
        // T::BITS
        let num_blocks = div_ceil(bits_to_encrypt, bits_in_block);
        decomposer
            .iter_as::<u64>()
            .take(num_blocks)
            .map(|clear_block| self.encrypt_block(rng, clear_block))
            .collect::<Vec<_>>()
    }

    /// encrypt message using pubkey.
    pub fn encrypt_block<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        message: u64,
    ) -> Ciphertext64Block {
        let plaintext = to_expanded_msg(
            message,
            self.threshold_lwe_parameters
                .output_cipher_parameters
                .message_modulus_log
                .0,
        );
        let mut lwe_ciphertext_in: LweCiphertext<Vec<u64>> = LweCiphertext::new(
            0u64,
            self.public_key.lwe_dimension().to_lwe_size(),
            self.public_key.ciphertext_modulus(),
        );

        let mut sec_rng = secret_rng_from_seed(seed_from_rng(rng).0);
        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(seed_from_rng(rng));
        let mut enc_rng = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
            deterministic_seeder.seed(),
            &mut deterministic_seeder,
        );

        encrypt_lwe_ciphertext_with_compact_public_key(
            &self.public_key,
            &mut lwe_ciphertext_in,
            plaintext,
            self.threshold_lwe_parameters
                .input_cipher_parameters
                .lwe_modular_std_dev,
            self.threshold_lwe_parameters
                .input_cipher_parameters
                .lwe_modular_std_dev,
            &mut sec_rng,
            &mut enc_rng,
        );

        lwe_ciphertext_in
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyPair {
    pub pk: PublicKey,
    pub sk: SecretKey,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeySet {
    pub pk: PublicKey,
    pub ck: BootstrappingKey,
    pub sk: SecretKey,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PubConKeyPair {
    pub pk: PublicKey,
    pub ck: BootstrappingKey,
}
impl PubConKeyPair {
    pub fn new(keyset: KeySet) -> Self {
        PubConKeyPair {
            pk: keyset.pk,
            ck: keyset.ck,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct BootstrappingKey {
    pub threshold_lwe_parameters: ThresholdLWEParameters,
    pub fbsk_out: Fourier128LweBootstrapKey<ABox<[f64]>>,
    // pub fbsk_in: FourierLweBootstrapKey<ABox<[c64]>>,
    // pub ksk_in: LweKeyswitchKey<Vec<u64>>,
}
impl Debug for BootstrappingKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Bootstrapping key vector{:?}", self.fbsk_out)
    }
}
impl BootstrappingKey {
    pub fn new(
        threshold_lwe_parameters: ThresholdLWEParameters,
        fbsk_out: Fourier128LweBootstrapKey<ABox<[f64]>>,
    ) -> Self {
        BootstrappingKey {
            threshold_lwe_parameters,
            fbsk_out,
        }
    }
}

pub type Ciphertext64 = Vec<Ciphertext64Block>;
pub type Ciphertext64Block = LweCiphertextOwned<u64>;
pub type Ciphertext128 = Vec<Ciphertext128Block>;
pub type Ciphertext128Block = LweCiphertextOwned<u128>;

pub fn keygen_single_party_share<R: Rng + CryptoRng>(
    keyset: &KeySet,
    rng: &mut R,
    party_id: usize,
    threshold: usize,
) -> anyhow::Result<SecretKeyShare> {
    let input_key_bits128: Vec<_> = keyset
        .sk
        .lwe_secret_key_128
        .clone()
        .into_container()
        .iter()
        .map(|b| gen_single_party_share(rng, Wrapping(*b), threshold, party_id).unwrap())
        .collect();

    let input_key_bits64: Vec<_> = keyset
        .sk
        .lwe_secret_key_64
        .clone()
        .into_container()
        .iter()
        .map(|b| gen_single_party_share(rng, Wrapping(*b), threshold, party_id).unwrap())
        .collect();

    let shared_sk = SecretKeyShare {
        input_key_share128: Array1::from_vec(input_key_bits128),
        input_key_share64: Array1::from_vec(input_key_bits64),
        threshold_lwe_parameters: keyset.pk.threshold_lwe_parameters,
    };
    Ok(shared_sk)
}
/// keygen that generates secret key shares for many parties and a public key
pub fn keygen_all_party_shares<R: Rng + CryptoRng>(
    keyset: &KeySet,
    rng: &mut R,
    num_parties: usize,
    threshold: usize,
) -> anyhow::Result<Vec<SecretKeyShare>> {
    let s_vector = keyset.sk.lwe_secret_key_128.clone().into_container();
    let s_length = s_vector.len();
    let mut vv128: Vec<Vec<ResiduePoly128>> = vec![Vec::with_capacity(s_length); num_parties];

    // for each bit in the secret key generate all parties shares
    for (i, bit) in s_vector.iter().enumerate() {
        let embedded_secret = ResiduePoly128::from_scalar(Wrapping(*bit));
        let poly = Poly::sample_random_with_fixed_constant(rng, embedded_secret, threshold);

        for (party_id, v) in vv128.iter_mut().enumerate().take(num_parties) {
            v.insert(
                i,
                poly.eval(&ResiduePoly::embed_exceptional_set(party_id + 1)?),
            );
        }
    }

    // do the same for 64 bit key
    let s_vector64 = keyset.sk.lwe_secret_key_64.clone().into_container();
    let s_length64 = s_vector64.len();
    let mut vv64: Vec<Vec<ResiduePoly64>> = vec![Vec::with_capacity(s_length64); num_parties];
    // for each bit in the secret key generate all parties shares
    for (i, bit) in s_vector64.iter().enumerate() {
        let embedded_secret = ResiduePoly64::from_scalar(Wrapping(*bit));
        let poly = Poly::sample_random_with_fixed_constant(rng, embedded_secret, threshold);

        for (party_id, v) in vv64.iter_mut().enumerate().take(num_parties) {
            v.insert(
                i,
                poly.eval(&ResiduePoly::embed_exceptional_set(party_id + 1)?),
            );
        }
    }

    // put the individual parties shares into SecretKeyShare structs
    let shared_sks: Vec<_> = (0..num_parties)
        .map(|p| SecretKeyShare {
            input_key_share128: Array1::from_vec(vv128[p].clone()),
            input_key_share64: Array1::from_vec(vv64[p].clone()),
            threshold_lwe_parameters: keyset.pk.threshold_lwe_parameters,
        })
        .collect();

    Ok(shared_sks)
}

// TODO is this the general correct formula? should be:
// output_lwe_secret_key.lwe_dimension().to_lwe_size(),
// and
// output_lwe_secret_key_out.lwe_dimension().to_lwe_size(),
fn pbs_cipher_size<S>(params: &CiphertextParameters<S>) -> LweSize
where
    S: UnsignedInteger,
{
    LweSize(1 + params.glwe_dimension.0 * params.polynomial_size.0)
}

/// Converts a ciphertext over a 64 bit domain to a ciphertext over a 128 bit domain (which is needed for secure threshold decryption).
/// Conversion is done using a precreated conversion key [ck].
/// Observe that the decryption key will be different after conversion, since [ck] is actually a key-switching key.
pub fn to_large_ciphertext(ck: &BootstrappingKey, small_ct: &Ciphertext64) -> Ciphertext128 {
    let mut res = Vec::with_capacity(small_ct.len());
    for current_block in small_ct {
        res.push(to_large_ciphertext_block(ck, current_block));
    }
    res
}

/// Converts a single ciphertext block over a 64 bit domain to a ciphertext block over a 128 bit domain (which is needed for secure threshold decryption).
/// Conversion is done using a precreated conversion key, [ck].
/// Observe that the decryption key will be different after conversion, since [ck] is actually a key-switching key.
pub fn to_large_ciphertext_block(
    ck: &BootstrappingKey,
    small_ct: &Ciphertext64Block,
) -> Ciphertext128Block {
    // Accumulator definition
    let delta = 1_u64
        << (u64::BITS
            - 1
            - ck.threshold_lwe_parameters
                .input_cipher_parameters
                .message_modulus_log
                .0 as u32);
    let msg_modulus = 1_u64
        << ck
            .threshold_lwe_parameters
            .input_cipher_parameters
            .message_modulus_log
            .0;

    let f_out = |x: u128| x;
    let delta_u128 = (delta as u128) << 64;
    let accumulator_out: GlweCiphertextOwned<u128> = generate_accumulator(
        ck.threshold_lwe_parameters
            .output_cipher_parameters
            .polynomial_size,
        ck.threshold_lwe_parameters
            .output_cipher_parameters
            .glwe_dimension
            .to_glwe_size(),
        msg_modulus.cast_into(),
        ck.threshold_lwe_parameters
            .output_cipher_parameters
            .ciphertext_modulus,
        delta_u128,
        f_out,
    );

    //MSUP
    let mut ms_output_lwe =
        LweCiphertext::new(0_u128, small_ct.lwe_size(), CiphertextModulus::new_native());
    lwe_ciphertext_modulus_switch_up(&mut ms_output_lwe, small_ct);

    let mut out_pbs_ct = LweCiphertext::new(
        0_u128,
        pbs_cipher_size(&ck.threshold_lwe_parameters.output_cipher_parameters),
        ck.threshold_lwe_parameters
            .output_cipher_parameters
            .ciphertext_modulus,
    );
    programmable_bootstrap_f128_lwe_ciphertext(
        &ms_output_lwe,
        &mut out_pbs_ct,
        &accumulator_out,
        &ck.fbsk_out,
    );
    out_pbs_ct
}

// Here we will define a helper function to generate an accumulator for a PBS
fn generate_accumulator<F, Scalar: UnsignedTorus + CastFrom<usize>>(
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    message_modulus: usize,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    delta: Scalar,
    f: F,
) -> GlweCiphertextOwned<Scalar>
where
    F: Fn(Scalar) -> Scalar,
{
    // N/(p/2) = size of each block, to correct noise from the input we introduce the
    // notion of box, which manages redundancy to yield a denoised value
    // for several noisy values around a true input value.
    let box_size = polynomial_size.0 / message_modulus;

    // Create the accumulator
    let mut accumulator_scalar = vec![Scalar::ZERO; polynomial_size.0];

    // Fill each box with the encoded denoised value
    for i in 0..message_modulus {
        let index = i * box_size;
        accumulator_scalar[index..index + box_size]
            .iter_mut()
            .for_each(|a| *a = f(Scalar::cast_from(i)) * delta);
    }

    let half_box_size = box_size / 2;

    // Negate the first half_box_size coefficients to manage negacyclicity and rotate
    for a_i in accumulator_scalar[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }

    // Rotate the accumulator
    accumulator_scalar.rotate_left(half_box_size);

    let accumulator_plaintext = PlaintextList::from_container(accumulator_scalar);

    allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size,
        &accumulator_plaintext,
        ciphertext_modulus,
    )
}

/// The method below is copied verbatim from the `noise-gap-exp` branch in tfhe-rs-internal since this branch will likely not be merged in main.
///
/// Takes a ciphertext, `input`, of a certain domain, [InputScalar] and overwrites the content of `output`
/// with the ciphertext converted to the [OutputScaler] domain.
pub fn lwe_ciphertext_modulus_switch_up<InputScalar, OutputScalar, InputCont, OutputCont>(
    output: &mut LweCiphertext<OutputCont>,
    input: &LweCiphertext<InputCont>,
) where
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: UnsignedInteger,
    InputCont: Container<Element = InputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
{
    assert!(input.ciphertext_modulus().is_native_modulus());

    output
        .as_mut()
        .iter_mut()
        .zip(input.as_ref().iter())
        .for_each(|(dst, &src)| *dst = src.cast_into());
    let modulus_up: CiphertextModulus<OutputScalar> = input.ciphertext_modulus().try_to().unwrap();

    lwe_ciphertext_cleartext_mul_assign(
        output,
        Cleartext(modulus_up.get_power_of_two_scaling_to_native_torus()),
    );
}

/// Helper function that takes a vector of decrypted plaintexts (each of [bits_in_block] plaintext bits)
/// and combine them into the integer message (u128) of many bits.
pub fn combine128(bits_in_block: u32, decryptions: Vec<Z128>) -> anyhow::Result<u128> {
    let mut recomposer = BlockRecomposer::<u128>::new(bits_in_block);

    for block in decryptions {
        if !recomposer.add_unmasked(block.0) {
            // End of T::BITS reached no need to try more
            // recomposition
            break;
        };
    }
    Ok(recomposer.value())
}

#[cfg(test)]
mod tests {
    use crate::execution::constants::SMALL_TEST_KEY_PATH;
    use crate::execution::constants::SMALL_TEST_PARAM_PATH;
    use crate::lwe::to_large_ciphertext_block;
    use crate::lwe::KeyPair;
    use crate::{
        algebra::base_ring::Z128,
        file_handling::{read_as_json, read_element},
        lwe::{
            from_expanded_msg, get_rng, secret_rng_from_seed, seed_from_rng, to_expanded_msg,
            KeySet, ThresholdLWEParameters,
        },
    };
    use aes_prng::AesRng;
    use num_traits::AsPrimitive;
    use rand::{RngCore, SeedableRng};
    use std::num::Wrapping;
    use tfhe::{
        core_crypto::prelude::{LweSecretKey, LweSecretKeyOwned, Plaintext, UnsignedInteger},
        shortint::prelude::LweDimension,
    };

    #[test]
    fn indeterminism_of_rng() {
        let mut rng1 = get_rng();
        let mut rng2 = get_rng();
        assert_ne!(rng1.next_u64(), rng2.next_u64());
    }

    #[test]
    fn determinism_of_seed() {
        let mut rng1 = secret_rng_from_seed(42);
        let mut rng2 = secret_rng_from_seed(42);
        // let mut buf1 = [0_u8; 32];
        // let mut buf2 = [1_u8; 32];
        let lwe_secret_key_1: LweSecretKeyOwned<u64> =
            LweSecretKey::generate_new_binary(LweDimension(700), &mut rng1);
        let lwe_secret_key_2: LweSecretKeyOwned<u64> =
            LweSecretKey::generate_new_binary(LweDimension(700), &mut rng2);
        assert_eq!(lwe_secret_key_1, lwe_secret_key_2);
    }

    #[test]
    fn seed_of_rng() {
        let mut rng = AesRng::seed_from_u64(42);
        let seed1 = seed_from_rng(&mut rng);
        let seed2 = seed_from_rng(&mut rng);
        // Check sufficient expected size
        assert!(seed1.0 > (1_u128 << 100));
        // Check randomness
        assert_ne!(seed1, seed2);
    }

    #[test]
    fn check_cipher_mapping() {
        for msg in 0..=17 {
            let cipher_domain: Plaintext<u64> = to_expanded_msg(msg, 4);
            let plain_domain = from_expanded_msg(cipher_domain.0, 4);
            // Compare with the message, taken modulo the message domain size, 16=1<<4
            assert_eq!(plain_domain.0, (msg as u128) % (1 << 4));
        }
    }

    #[test]
    fn sunshine_block() {
        let params: ThresholdLWEParameters =
            read_as_json(SMALL_TEST_PARAM_PATH.to_string()).unwrap();
        let usable_mod_bits = params.input_cipher_parameters.usable_message_modulus_log.0;
        let keys: KeySet = read_element(SMALL_TEST_KEY_PATH.to_string()).unwrap();
        for msg in 0..(1 << usable_mod_bits) {
            let mut rng = AesRng::seed_from_u64(msg);
            let small_ct = keys.pk.encrypt_block(&mut rng, msg);
            let small_res = keys.sk.decrypt_block_64(&small_ct);
            assert_eq!(msg as u128, small_res.0);
            let large_ct = to_large_ciphertext_block(&keys.ck, &small_ct);
            let large_res = keys.sk.decrypt_block_128(&large_ct);
            assert_eq!(msg as u128, large_res.0);
        }
    }

    /// Tests the fixing of this bug https://github.com/zama-ai/distributed-decryption/issues/181
    /// which could result in decrypting 2^message_bits when a message 0 was encrypted and randomness
    /// in the encryption ends up being negative
    #[test]
    fn negative_wrapping() {
        let params: ThresholdLWEParameters =
            read_as_json(SMALL_TEST_PARAM_PATH.to_string()).unwrap();
        let delta_half = 1
            << ((u128::BITS as u128 - 1_u128)
                - params.output_cipher_parameters.message_modulus_log.0 as u128);
        // Should be rounded to 0, since it is the negative part of the numbers that should round to 0
        let msg = u128::MAX - delta_half + 1;
        let res = from_expanded_msg(msg, params.output_cipher_parameters.message_modulus_log.0);
        assert_eq!(0, res.0);

        // Check that this is where the old code failed
        let res = old_from_expanded_msg(msg, params.output_cipher_parameters.message_modulus_log.0);
        assert_ne!(0, res.0);

        // Should not be 0, but instead the maximal message allowed
        let msg = u128::MAX - delta_half - 1;
        let res = from_expanded_msg(msg, params.output_cipher_parameters.message_modulus_log.0);
        assert_eq!(
            (1 << params.output_cipher_parameters.message_modulus_log.0) - 1,
            res.0
        );
    }

    fn old_from_expanded_msg<Scalar: UnsignedInteger + AsPrimitive<u128>>(
        raw_plaintext: Scalar,
        message_mod_bits: usize,
    ) -> Z128 {
        let delta_bits = (Scalar::BITS as u128 - 1_u128) - message_mod_bits as u128;
        let rounding_bit = 1 << (delta_bits - 1);
        //compute the rounding bit
        let rounding = (raw_plaintext.as_() & rounding_bit) << 1;

        let msg = (raw_plaintext.as_().wrapping_add(rounding)) >> delta_bits;
        Wrapping(msg % (1 << message_mod_bits))
    }

    #[test]
    fn sunshine_domain_switching() {
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH.to_string()).unwrap();
        let keypair = KeyPair {
            sk: keyset.sk,
            pk: keyset.pk,
        };
        let message = (1
            << keypair
                .pk
                .threshold_lwe_parameters
                .input_cipher_parameters
                .message_modulus_log
                .0)
            - 1;
        let small_ct = keypair.pk.encrypt_block(&mut get_rng(), message);
        let large_ct = to_large_ciphertext_block(&keyset.ck, &small_ct);
        let res_small = keypair.sk.decrypt_block_64(&small_ct);
        let res_large = keypair.sk.decrypt_block_128(&large_ct);
        assert_eq!(message as u128, res_small.0);
        assert_eq!(message as u128, res_large.0);
    }
}
