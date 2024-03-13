use crate::algebra::base_ring::Z128;
use crate::algebra::residue_poly::ResiduePoly;
use crate::algebra::residue_poly::ResiduePoly128;
use crate::algebra::residue_poly::ResiduePoly64;
use crate::algebra::structure_traits::{BaseRing, RingEmbed, Zero};
use crate::execution::random::secret_rng_from_seed;
use crate::execution::random::seed_from_rng;
use crate::{algebra::poly::Poly, error::error_handler::anyhow_error_and_log};
use aligned_vec::ABox;
use core::fmt;
use core::fmt::Debug;
use ndarray::Array1;
use num_traits::AsPrimitive;
use rand::{CryptoRng, Rng};
use serde::Deserialize;
use serde::Serialize;
use std::num::Wrapping;
use tfhe::core_crypto::prelude::decrypt_lwe_ciphertext;
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
use tfhe::core_crypto::seeders::Seeder;
use tfhe::integer::block_decomposition::BlockRecomposer;
use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::shortint::prelude::DecompositionBaseLog;
use tfhe::shortint::prelude::DecompositionLevelCount;
use tfhe::shortint::prelude::GlweDimension;
use tfhe::shortint::prelude::LweDimension;
use tfhe::shortint::prelude::PolynomialSize;
use tfhe::shortint::prelude::StandardDev;
use tfhe::shortint::MessageModulus;
use tfhe::shortint::ShortintParameterSet;
use tfhe::{
    core_crypto::commons::ciphertext_modulus::CiphertextModulus, shortint::ClassicPBSParameters,
};
use tfhe::{core_crypto::commons::generators::DeterministicSeeder, shortint::CarryModulus};
use tfhe::{core_crypto::prelude::allocate_and_generate_new_binary_glwe_secret_key, ClientKey};
use tfhe::{core_crypto::prelude::allocate_and_generate_new_binary_lwe_secret_key, shortint};
use tfhe::{
    core_crypto::prelude::convert_standard_lwe_bootstrap_key_to_fourier_128,
    integer::IntegerCiphertext,
};
use tracing::instrument;
use zeroize::Zeroize;

#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq)]
pub struct CiphertextParameters<Scalar>
where
    Scalar: UnsignedInteger + Copy,
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
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
    pub encryption_key_choice: EncryptionKeyChoice,
}
impl<Scalar: UnsignedInteger> CiphertextParameters<Scalar> {
    // Return the minimum amount of bits that can be used for a message in each block.
    pub fn message_modulus_log(&self) -> u32 {
        self.message_modulus.0.ilog2()
    }

    // Return the minimum amount of bits that can be used for a carry in each block.
    pub fn carry_modulus_log(&self) -> u32 {
        self.carry_modulus.0.ilog2()
    }

    // Return the minimum total amounts of availble bits in each block. I.e. including both message and carry bits
    pub fn total_block_bits(&self) -> u32 {
        self.carry_modulus_log() + self.message_modulus_log()
    }

    pub fn pbs_cipher_size(&self) -> LweSize {
        LweSize(1 + self.glwe_dimension.0 * self.polynomial_size.0)
    }
}

impl From<CiphertextParameters<u64>> for ClassicPBSParameters {
    fn from(value: CiphertextParameters<u64>) -> Self {
        ClassicPBSParameters {
            lwe_dimension: value.lwe_dimension,
            glwe_dimension: value.glwe_dimension,
            polynomial_size: value.polynomial_size,
            lwe_modular_std_dev: value.lwe_modular_std_dev,
            glwe_modular_std_dev: value.glwe_modular_std_dev,
            pbs_base_log: value.pbs_base_log,
            pbs_level: value.pbs_level,
            ks_base_log: value.ks_base_log,
            ks_level: value.ks_level,
            message_modulus: value.message_modulus,
            carry_modulus: value.carry_modulus,
            ciphertext_modulus: value.ciphertext_modulus,
            encryption_key_choice: value.encryption_key_choice,
        }
    }
}

#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq)]
pub struct ThresholdLWEParameters {
    pub input_cipher_parameters: CiphertextParameters<u64>,
    pub output_cipher_parameters: CiphertextParameters<u128>,
}

pub type Ciphertext64 = BaseRadixCiphertext<tfhe::shortint::Ciphertext>;
pub type Ciphertext64Block = tfhe::shortint::Ciphertext;
// Observe that tfhe-rs is hard-coded to use u64, hence we require custom types for the 128 bit versions for now.
pub type Ciphertext128 = Vec<Ciphertext128Block>;
pub type Ciphertext128Block = LweCiphertextOwned<u128>;

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
pub struct LargeClientKey {
    pub large_key: LweSecretKeyOwned<u128>,
    pub params: CiphertextParameters<u128>,
}
impl LargeClientKey {
    pub fn new(params: CiphertextParameters<u128>, large_key: LweSecretKeyOwned<u128>) -> Self {
        LargeClientKey { large_key, params }
    }

    pub fn decrypt_128(&self, ct: &Ciphertext128) -> u128 {
        if ct.is_empty() {
            return 0;
        }

        let bits_in_block = self.params.message_modulus_log();
        let mut recomposer = BlockRecomposer::<u128>::new(bits_in_block);

        for encrypted_block in ct {
            let decrypted_block = self.decrypt_block_128(encrypted_block);
            if !recomposer.add_unmasked(decrypted_block.0) {
                // End of T::BITS reached no need to try more
                // recomposition
                break;
            };
        }

        recomposer.value()
    }

    pub(crate) fn decrypt_block_128(&self, ct: &Ciphertext128Block) -> Z128 {
        let total_bits = self.params.total_block_bits() as usize;
        let raw_plaintext = decrypt_lwe_ciphertext(&self.large_key, ct);
        from_expanded_msg(raw_plaintext.0, total_bits)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeySet {
    pub public_key: tfhe::CompactPublicKey,
    pub server_key: tfhe::ServerKey,
    pub client_key: tfhe::ClientKey,
    pub client_output_key: LargeClientKey,
    pub conversion_key: ConversionKey,
}
impl KeySet {
    pub(crate) fn get_raw_client_key(&self) -> LweSecretKey<Vec<u64>> {
        let (inner_client_key, _) = self.client_key.clone().into_raw_parts();
        let short_client_key = inner_client_key.into_raw_parts();
        let (_glwe_secret_key, lwe_secret_key, _shortint_param) = short_client_key.into_raw_parts();
        lwe_secret_key
    }

    pub(crate) fn threshold_lwe_parameters(&self) -> &ThresholdLWEParameters {
        &self.conversion_key.threshold_lwe_parameters
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PubConKeyPair {
    pub public_key: tfhe::CompactPublicKey,
    pub conversion_key: ConversionKey,
}
impl PubConKeyPair {
    pub fn new(keyset: KeySet) -> Self {
        PubConKeyPair {
            public_key: keyset.public_key,
            conversion_key: keyset.conversion_key,
        }
    }
}
impl PartialEq for PubConKeyPair {
    fn eq(&self, other: &Self) -> bool {
        // TODO this is not the best implementation due to the clone, but
        // it is not sure how else to implement this properly.
        self.public_key.clone().into_raw_parts().into_raw_parts()
            == other.public_key.clone().into_raw_parts().into_raw_parts()
            && self.conversion_key == other.conversion_key
    }
}

/// Key used for switch-and-squash to convert a ciphertext over u64 to one over u128
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct ConversionKey {
    pub threshold_lwe_parameters: ThresholdLWEParameters,
    pub fbsk_out: Fourier128LweBootstrapKey<ABox<[f64]>>,
}
impl Debug for ConversionKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Bootstrapping key vector{:?}", self.fbsk_out)
    }
}
impl ConversionKey {
    pub fn new(
        threshold_lwe_parameters: ThresholdLWEParameters,
        fbsk_out: Fourier128LweBootstrapKey<ABox<[f64]>>,
    ) -> Self {
        ConversionKey {
            threshold_lwe_parameters,
            fbsk_out,
        }
    }

    /// Converts a ciphertext over a 64 bit domain to a ciphertext over a 128 bit domain (which is needed for secure threshold decryption).
    /// Conversion is done using a precreated conversion key [conversion_key].
    /// Observe that the decryption key will be different after conversion, since [conversion_key] is actually a key-switching key.
    #[instrument(skip(self, raw_small_ct))]
    pub fn to_large_ciphertext(
        &self,
        raw_small_ct: &Ciphertext64,
    ) -> anyhow::Result<Ciphertext128> {
        let blocks = raw_small_ct.blocks();
        let mut res = Vec::with_capacity(blocks.len());
        for current_block in blocks {
            res.push(self.to_large_ciphertext_block(current_block)?);
        }
        Ok(res)
    }

    /// Converts a single ciphertext block over a 64 bit domain to a ciphertext block over a 128 bit domain (which is needed for secure threshold decryption).
    /// Conversion is done using a precreated conversion key, [conversion_key].
    /// Observe that the decryption key will be different after conversion, since [conversion_key] is actually a key-switching key.
    pub fn to_large_ciphertext_block(
        &self,
        small_ct_block: &Ciphertext64Block,
    ) -> anyhow::Result<Ciphertext128Block> {
        let input_param = self.threshold_lwe_parameters.input_cipher_parameters;
        let output_param = self.threshold_lwe_parameters.output_cipher_parameters;
        let total_bits = input_param.total_block_bits();
        // Accumulator definition
        let delta = 1_u64 << (u64::BITS - 1 - total_bits);
        let msg_modulus = 1_u64 << total_bits;

        let f_out = |x: u128| x;
        let delta_u128 = (delta as u128) << 64;
        let accumulator_out: GlweCiphertextOwned<u128> = Self::generate_accumulator(
            output_param.polynomial_size,
            output_param.glwe_dimension.to_glwe_size(),
            msg_modulus.cast_into(),
            output_param.ciphertext_modulus,
            delta_u128,
            f_out,
        );

        //MSUP
        let mut ms_output_lwe = LweCiphertext::new(
            0_u128,
            input_param.lwe_dimension.to_lwe_size(),
            CiphertextModulus::new_native(),
        );
        Self::lwe_ciphertext_modulus_switch_up(&mut ms_output_lwe, &small_ct_block.ct)?;

        let mut out_pbs_ct = LweCiphertext::new(
            0_u128,
            output_param.pbs_cipher_size(),
            output_param.ciphertext_modulus,
        );
        programmable_bootstrap_f128_lwe_ciphertext(
            &ms_output_lwe,
            &mut out_pbs_ct,
            &accumulator_out,
            &self.fbsk_out,
        );
        Ok(out_pbs_ct)
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

    /// The method below is copied from the `noise-gap-exp` branch in tfhe-rs-internal (and added error handling)
    /// since this branch will likely not be merged in main.
    ///
    /// Takes a ciphertext, `input`, of a certain domain, [InputScalar] and overwrites the content of `output`
    /// with the ciphertext converted to the [OutputScaler] domain.
    fn lwe_ciphertext_modulus_switch_up<InputScalar, OutputScalar, InputCont, OutputCont>(
        output: &mut LweCiphertext<OutputCont>,
        input: &LweCiphertext<InputCont>,
    ) -> anyhow::Result<()>
    where
        InputScalar: UnsignedInteger + CastInto<OutputScalar>,
        OutputScalar: UnsignedInteger,
        InputCont: Container<Element = InputScalar>,
        OutputCont: ContainerMut<Element = OutputScalar>,
    {
        if !input.ciphertext_modulus().is_native_modulus() {
            return Err(anyhow_error_and_log(
                "Ciphertext modulus is not native, which is the only kind supported".to_string(),
            ));
        }

        output
            .as_mut()
            .iter_mut()
            .zip(input.as_ref().iter())
            .for_each(|(dst, &src)| *dst = src.cast_into());
        let modulus_up: CiphertextModulus<OutputScalar> = input
            .ciphertext_modulus()
            .try_to()
            .map_err(|_| anyhow_error_and_log("Could not parse ciphertext modulus".to_string()))?;

        lwe_ciphertext_cleartext_mul_assign(
            output,
            Cleartext(modulus_up.get_power_of_two_scaling_to_native_torus()),
        );
        Ok(())
    }
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
    message_and_carry_mod_bits: usize,
) -> Z128 {
    // delta = q/t where t is the amount of plain text bits
    // Observe we actually divide this by 2 (i.e. subtract 1 bit) to make space for padding
    let delta_pad_bits = (Scalar::BITS as u128) - (message_and_carry_mod_bits as u128 + 1_u128);

    // compute delta / 2
    let delta_pad_half = 1 << (delta_pad_bits - 1);

    // add delta/2 to kill the negative noise, note this does not affect the message.
    let raw_msg = raw_plaintext.as_().wrapping_add(delta_pad_half) >> delta_pad_bits;

    let msg = Wrapping(raw_msg % (1 << message_and_carry_mod_bits));
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
#[allow(dead_code)]
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
    let mut secret_rng = secret_rng_from_seed(seed_from_rng(rng).0);

    let input_lwe_secret_key: LweSecretKey<Vec<u64>> =
        allocate_and_generate_new_binary_lwe_secret_key(
            threshold_lwe_parameters
                .input_cipher_parameters
                .lwe_dimension,
            &mut secret_rng,
        );
    let input_glwe_secret_key: GlweSecretKey<Vec<u64>> =
        allocate_and_generate_new_binary_glwe_secret_key(
            input_param.glwe_dimension,
            input_param.polynomial_size,
            &mut secret_rng,
        );

    let client_key = to_hl_client_key(
        &threshold_lwe_parameters,
        input_lwe_secret_key,
        input_glwe_secret_key,
    );
    let public_key = tfhe::CompactPublicKey::new(&client_key);
    let server_key = tfhe::ServerKey::new(&client_key);
    let (client_output_key, conversion_key) =
        generate_large_keys(threshold_lwe_parameters, client_key.clone(), rng);

    KeySet {
        client_key,
        public_key,
        server_key,
        conversion_key,
        client_output_key,
    }
}

/// Function for generating a pair of keys for the noise drowning algorithms.
/// That is, the method takes a client key working over u64 and generates a random client key working over u128.
/// Then, the method constructs a key switching key to convert ciphertext encrypted with the key over u64,
/// to ciphertexts encrypted over u128.
pub fn generate_large_keys<R: Rng + CryptoRng>(
    threshold_lwe_parameters: ThresholdLWEParameters,
    input_sk: ClientKey,
    rng: &mut R,
) -> (LargeClientKey, ConversionKey) {
    let output_param = threshold_lwe_parameters.output_cipher_parameters;
    let input_param = threshold_lwe_parameters.input_cipher_parameters;

    let mut secret_rng = secret_rng_from_seed(seed_from_rng(rng).0);
    let mut deterministic_seeder =
        DeterministicSeeder::<ActivatedRandomGenerator>::new(seed_from_rng(rng));
    let mut enc_rng = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
        deterministic_seeder.seed(),
        &mut deterministic_seeder,
    );

    // Generate output secret key
    let output_glwe_secret_key_out = allocate_and_generate_new_binary_glwe_secret_key(
        output_param.glwe_dimension,
        output_param.polynomial_size,
        &mut secret_rng,
    );
    let output_lwe_secret_key_out = output_glwe_secret_key_out.clone().into_lwe_secret_key();
    let client_output_key = LargeClientKey::new(output_param, output_lwe_secret_key_out);

    // Generate conversion key
    let (short_sk, _whopbs_param) = input_sk.into_raw_parts();
    let (_raw_input_glwe_secret_key, raw_input_lwe_secret_key, _short_param) =
        short_sk.into_raw_parts().into_raw_parts();
    let mut input_lwe_secret_key_out =
        LweSecretKey::new_empty_key(0_u128, input_param.lwe_dimension);
    // Convert input secret key to a u128 bit key
    input_lwe_secret_key_out
        .as_mut()
        .iter_mut()
        .zip(raw_input_lwe_secret_key.as_ref().iter())
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

    let conversion_key = ConversionKey::new(threshold_lwe_parameters, fbsk_out);
    (client_output_key, conversion_key)
}

/// Helper method for converting a low level client key into a high level client key.
pub fn to_hl_client_key(
    params: &ThresholdLWEParameters,
    lwe_secret_key: LweSecretKey<Vec<u64>>,
    glwe_secret_key: GlweSecretKey<Vec<u64>>,
) -> tfhe::ClientKey {
    let classic_params = params.input_cipher_parameters.into();
    let sps =
        ShortintParameterSet::new_pbs_param_set(tfhe::shortint::PBSParameters::PBS(classic_params));
    let sck = shortint::ClientKey::from_raw_parts(glwe_secret_key, lwe_secret_key, sps);
    ClientKey::from_raw_parts(sck.into(), None)
}

/// Helper method for converting a low level public key into a high level public key.
pub fn to_hl_public_key(
    params: &ThresholdLWEParameters,
    compact_lwe_public_key: LweCompactPublicKey<Vec<u64>>,
) -> tfhe::CompactPublicKey {
    let classic_params = params.input_cipher_parameters.into();
    let sps =
        ShortintParameterSet::new_pbs_param_set(tfhe::shortint::PBSParameters::PBS(classic_params));
    let ipk = shortint::CompactPublicKey::from_raw_parts(
        compact_lwe_public_key,
        sps,
        params.input_cipher_parameters.encryption_key_choice.into(),
    );
    let cpk = tfhe::integer::public_key::CompactPublicKey::from_raw_parts(ipk);
    tfhe::CompactPublicKey::from_raw_parts(cpk)
}

pub fn keygen_single_party_share<R: Rng + CryptoRng>(
    keyset: &KeySet,
    rng: &mut R,
    party_id: usize,
    threshold: usize,
) -> anyhow::Result<SecretKeyShare> {
    let output_bits = &keyset.client_output_key.large_key.as_ref().len();
    let mut input_key_bits128 = Vec::with_capacity(*output_bits);
    for cur_bit in keyset.client_output_key.large_key.as_ref() {
        input_key_bits128.push(gen_single_party_share(
            rng,
            Wrapping(*cur_bit),
            threshold,
            party_id,
        )?);
    }

    let input_bits = keyset.get_raw_client_key().into_container().len();
    let mut input_key_bits64 = Vec::with_capacity(input_bits);
    for cur_bit in keyset.get_raw_client_key().as_ref() {
        input_key_bits64.push(gen_single_party_share(
            rng,
            Wrapping(*cur_bit),
            threshold,
            party_id,
        )?);
    }

    let shared_sk = SecretKeyShare {
        input_key_share128: Array1::from_vec(input_key_bits128),
        input_key_share64: Array1::from_vec(input_key_bits64),
        threshold_lwe_parameters: *keyset.threshold_lwe_parameters(),
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
    let s_vector = keyset.client_output_key.large_key.clone().into_container();
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
    let s_vector64 = keyset.get_raw_client_key().into_container();
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
            threshold_lwe_parameters: *keyset.threshold_lwe_parameters(),
        })
        .collect();

    Ok(shared_sks)
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
    use super::{to_hl_public_key, CiphertextParameters};
    use crate::execution::constants::{REAL_KEY_PATH, SMALL_TEST_KEY_PATH};
    use crate::{
        algebra::base_ring::Z128,
        execution::random::get_rng,
        file_handling::{read_as_json, read_element},
        lwe::{
            from_expanded_msg, secret_rng_from_seed, seed_from_rng, to_expanded_msg, KeySet,
            ThresholdLWEParameters,
        },
    };
    use crate::{execution::constants::SMALL_TEST_PARAM_PATH, lwe::to_hl_client_key};
    use aes_prng::AesRng;
    use num_traits::AsPrimitive;
    use rand::{RngCore, SeedableRng};
    use std::num::Wrapping;
    use tfhe::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
    use tfhe::{
        core_crypto::prelude::{LweSecretKey, LweSecretKeyOwned, Plaintext, UnsignedInteger},
        generate_keys,
        prelude::{FheDecrypt, FheEncrypt},
        set_server_key,
        shortint::prelude::LweDimension,
        ConfigBuilder, FheUint8,
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
    fn sunshine_enc_dec() {
        let keys: KeySet = read_element(SMALL_TEST_KEY_PATH.to_string()).unwrap();
        for msg in 0_u8..8 {
            let small_ct = FheUint8::encrypt(msg, &keys.public_key);
            let (raw_ct, _id) = small_ct.clone().into_raw_parts();
            let small_res: u8 = small_ct.decrypt(&keys.client_key);
            assert_eq!(msg, small_res);
            let large_ct = keys.conversion_key.to_large_ciphertext(&raw_ct).unwrap();
            let large_res = keys.client_output_key.decrypt_128(&large_ct);
            assert_eq!(msg as u128, large_res);
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
                - params.output_cipher_parameters.total_block_bits() as u128);
        // Should be rounded to 0, since it is the negative part of the numbers that should round to 0
        let msg = u128::MAX - delta_half + 1;
        let res = from_expanded_msg(
            msg,
            params.output_cipher_parameters.total_block_bits() as usize,
        );
        assert_eq!(0, res.0);

        // Check that this is where the old code failed
        let res = old_from_expanded_msg(
            msg,
            params.output_cipher_parameters.total_block_bits() as usize,
        );
        assert_ne!(0, res.0);

        // Should not be 0, but instead the maximal message allowed
        let msg = u128::MAX - delta_half - 1;
        let res = from_expanded_msg(
            msg,
            params.output_cipher_parameters.total_block_bits() as usize,
        );
        assert_eq!(
            (1 << params.output_cipher_parameters.total_block_bits()) - 1,
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
        let message = 255_u8;
        let keyset: KeySet = read_element(SMALL_TEST_KEY_PATH.to_string()).unwrap();
        let small_ct = FheUint8::encrypt(message, &keyset.client_key);
        let large_ct = keyset
            .conversion_key
            .to_large_ciphertext(&small_ct.clone().into_raw_parts().0)
            .unwrap();
        let res_small: u8 = small_ct.decrypt(&keyset.client_key);
        let res_large = keyset.client_output_key.decrypt_128(&large_ct);
        assert_eq!(message, res_small);
        assert_eq!(message as u128, res_large);
    }
    #[test]
    #[ignore]
    fn hl_sk_key_conversion() {
        let config = ConfigBuilder::default().build();
        let (client_key, _server_key) = generate_keys(config);
        let (raw_sk, _whobs) = client_key.clone().into_raw_parts();
        let (glwe_key, lwe_key, params) = raw_sk.into_raw_parts().into_raw_parts();
        let input_param: CiphertextParameters<u64> = CiphertextParameters {
            lwe_dimension: params.lwe_dimension(),
            glwe_dimension: params.glwe_dimension(),
            polynomial_size: params.polynomial_size(),
            lwe_modular_std_dev: params.lwe_modular_std_dev(),
            glwe_modular_std_dev: params.glwe_modular_std_dev(),
            pbs_base_log: params.pbs_base_log(),
            pbs_level: params.pbs_level(),
            ks_base_log: params.ks_base_log(),
            ks_level: params.ks_level(),
            message_modulus: params.message_modulus(),
            carry_modulus: params.carry_modulus(),
            ciphertext_modulus: params.ciphertext_modulus(),
            encryption_key_choice: params.encryption_key_choice(),
        };
        let output_param: CiphertextParameters<u128> = CiphertextParameters {
            lwe_dimension: params.lwe_dimension(),
            glwe_dimension: params.glwe_dimension(),
            polynomial_size: params.polynomial_size(),
            lwe_modular_std_dev: params.lwe_modular_std_dev(),
            glwe_modular_std_dev: params.glwe_modular_std_dev(),
            pbs_base_log: params.pbs_base_log(),
            pbs_level: params.pbs_level(),
            ks_base_log: params.ks_base_log(),
            ks_level: params.ks_level(),
            message_modulus: params.message_modulus(),
            carry_modulus: params.carry_modulus(),
            ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
            encryption_key_choice: params.encryption_key_choice(),
        };
        let threshold_params = ThresholdLWEParameters {
            input_cipher_parameters: input_param,
            output_cipher_parameters: output_param,
        };
        let hl_client_key = to_hl_client_key(&threshold_params, lwe_key, glwe_key);
        assert_eq!(
            hl_client_key.into_raw_parts(),
            client_key.clone().into_raw_parts()
        );
        let ct = FheUint8::encrypt(42_u8, &client_key);
        let msg: u8 = ct.decrypt(&client_key);
        assert_eq!(42, msg);
    }

    #[test]
    #[ignore]
    fn hl_pk_key_conversion() {
        let config = ConfigBuilder::default().build();
        let (client_key, _server_key) = generate_keys(config);
        let pk = tfhe::CompactPublicKey::new(&client_key);
        let raw_pk = pk.clone().into_raw_parts().into_raw_parts();
        let (lcpk, params, _order) = raw_pk.into_raw_parts();
        let input_param: CiphertextParameters<u64> = CiphertextParameters {
            lwe_dimension: params.lwe_dimension(),
            glwe_dimension: params.glwe_dimension(),
            polynomial_size: params.polynomial_size(),
            lwe_modular_std_dev: params.lwe_modular_std_dev(),
            glwe_modular_std_dev: params.glwe_modular_std_dev(),
            pbs_base_log: params.pbs_base_log(),
            pbs_level: params.pbs_level(),
            ks_base_log: params.ks_base_log(),
            ks_level: params.ks_level(),
            message_modulus: params.message_modulus(),
            carry_modulus: params.carry_modulus(),
            ciphertext_modulus: params.ciphertext_modulus(),
            encryption_key_choice: params.encryption_key_choice(),
        };
        let output_param: CiphertextParameters<u128> = CiphertextParameters {
            lwe_dimension: params.lwe_dimension(),
            glwe_dimension: params.glwe_dimension(),
            polynomial_size: params.polynomial_size(),
            lwe_modular_std_dev: params.lwe_modular_std_dev(),
            glwe_modular_std_dev: params.glwe_modular_std_dev(),
            pbs_base_log: params.pbs_base_log(),
            pbs_level: params.pbs_level(),
            ks_base_log: params.ks_base_log(),
            ks_level: params.ks_level(),
            message_modulus: params.message_modulus(),
            carry_modulus: params.carry_modulus(),
            ciphertext_modulus: CiphertextModulus::<u128>::new_native(),
            encryption_key_choice: params.encryption_key_choice(),
        };
        let threshold_params = ThresholdLWEParameters {
            input_cipher_parameters: input_param,
            output_cipher_parameters: output_param,
        };
        let hl_client_key = to_hl_public_key(&threshold_params, lcpk);
        assert_eq!(hl_client_key.into_raw_parts(), pk.clone().into_raw_parts());
        let ct = FheUint8::encrypt(42_u8, &pk);
        let msg: u8 = ct.decrypt(&client_key);
        assert_eq!(42, msg);
    }

    // TODO does not work with test key. Enable if test keys get updated
    // // #[test]
    // fn sunshine_hl_keys_test() {
    //     sunshine_hl_keys(SMALL_TEST_KEY_PATH);
    // }

    #[test]
    fn sunshine_hl_keys_real() {
        sunshine_hl_keys(REAL_KEY_PATH);
    }

    /// Helper method for validating conversion to high level API keys.
    /// Method tries to encrypt using both public and client keys and validates
    /// that the results are correct and consistent.
    fn sunshine_hl_keys(path: &str) {
        let keyset: KeySet = read_element(path.to_string()).unwrap();
        let ct_a = FheUint8::encrypt(42_u8, &keyset.client_key);
        let decrypted_a: u8 = ct_a.decrypt(&keyset.client_key);
        assert_eq!(42, decrypted_a);
        set_server_key(keyset.server_key);
        let ct_b = FheUint8::encrypt(55_u8, &keyset.public_key);
        let ct_sum = ct_a.clone() + ct_b;
        let sum: u8 = ct_sum.decrypt(&keyset.client_key);
        assert_eq!(42 + 55, sum);
        let ct_c = FheUint8::encrypt(5_u8, &keyset.client_key);
        let ct_product = ct_a * ct_c;
        let product: u8 = ct_product.decrypt(&keyset.client_key);
        assert_eq!(42 * 5, product);
    }
}
