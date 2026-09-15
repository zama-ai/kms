//! MLKEM1024-P384 composite post-quantum KEM.
//!
//! This implements the MLKEM1024-P384 construction from section 4.3 of
//! <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html>.
//! It matches [`rust-hpke`](https://github.com/rozbb/rust-hpke/blob/024f006836ce2adbfc528b25e22b635065b16096/src/kem/mlkem_nistp.rs).
//!
//! While ML-KEM-1024 is NIST level 5 (256-bit security), it is paired with P384
//! to hedge against advances in cryptanalysis on lattice-based schemes. This
//! reasoning is all given in x-wing <https://eprint.iacr.org/2024/039.pdf>.

use crate::cryptography::error::CryptographyError;
use hybrid_array::{Array, typenum::Unsigned};
use ml_kem::{
    B32, EncodedSizeUser, KemCore, MlKem1024,
    kem::{Decapsulate, Encapsulate},
};
use p384::elliptic_curve::sec1::ToEncodedPoint;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, de::Visitor};
use sha3::{
    Sha3_256, Shake256,
    digest::{ExtendableOutput, FixedOutput, Output, Update, XofReader},
};
use tfhe::named::Named;
use tfhe_versionable::{
    Unversionize, UnversionizeError, Version, Versionize, VersionizeOwned, VersionsDispatch,
    derived_traits::VersionsDispatch as VersionsDispatchTrait,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const KEM_LABEL: &[u8] = b"MLKEM1024-P384";
const PRIVATE_KEY_LENGTH: usize = 32;
const ML_KEM_SEED_LENGTH: usize = 64;
const ML_KEM_POLY_VEC_LENGTH: usize = 1536;
const ML_KEM_MODULUS: u16 = 3329;
const P384_SCALAR_LENGTH: usize = 48;
const P384_PUBLIC_KEY_LENGTH: usize = 97;

/// Length of a serialized MLKEM1024-P384 public key.
pub(crate) const PUBLIC_KEY_LENGTH: usize = 1665;
/// Length of an MLKEM1024-P384 encapsulated key.
pub(crate) const CIPHERTEXT_LENGTH: usize = 1665;
/// Length of an MLKEM1024-P384 shared secret, fixed by the SHA3-256 combiner.
pub(crate) const SHARED_SECRET_LENGTH: usize = 32;

type MlKemPublicKey = <MlKem1024 as KemCore>::EncapsulationKey;
type MlKemPrivateKey = <MlKem1024 as KemCore>::DecapsulationKey;

// Both wire formats end in a P-384 point of a fixed length. `from_sec1_bytes`
// therefore sees an input that only an uncompressed point can fill, and it
// rejects every other SEC1 tag on its own.
const _: () = assert!(
    PUBLIC_KEY_LENGTH
        == <MlKemPublicKey as EncodedSizeUser>::EncodedSize::USIZE + P384_PUBLIC_KEY_LENGTH
);
const _: () = assert!(
    CIPHERTEXT_LENGTH == <MlKem1024 as KemCore>::CiphertextSize::USIZE + P384_PUBLIC_KEY_LENGTH
);

/// Public key for the MLKEM1024-P384 composite KEM.
#[derive(Clone, Debug)]
pub struct MlKem1024P384PublicKey {
    ml_kem_key: MlKemPublicKey,
    p384_key: p384::PublicKey,
}

impl PartialEq for MlKem1024P384PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.ml_kem_key.as_bytes() == other.ml_kem_key.as_bytes() && self.p384_key == other.p384_key
    }
}

impl Eq for MlKem1024P384PublicKey {}

impl MlKem1024P384PublicKey {
    /// Encode as the ML-KEM-1024 encapsulation key followed by the uncompressed
    /// SEC1 P-384 point.
    fn to_bytes(&self) -> Vec<u8> {
        let ml_kem_key = self.ml_kem_key.as_bytes();
        let p384_key = self.p384_key.to_encoded_point(false);
        debug_assert_eq!(ml_kem_key.len() + p384_key.len(), PUBLIC_KEY_LENGTH);

        [ml_kem_key.as_slice(), p384_key.as_bytes()].concat()
    }

    /// Parse the encoding that [MlKem1024P384PublicKey::to_bytes] produces.
    ///
    /// Returns an error when the length is wrong, when an ML-KEM-1024
    /// coefficient is out of range, or when the P-384 bytes are not a point on
    /// the curve.
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptographyError> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(CryptographyError::LengthError(format!(
                "MLKEM1024-P384 public key has length {}, expected {PUBLIC_KEY_LENGTH}",
                bytes.len()
            )));
        }

        let ml_kem_key_length = <MlKemPublicKey as EncodedSizeUser>::EncodedSize::USIZE;
        let (ml_kem_bytes, p384_bytes) = bytes.split_at(ml_kem_key_length);
        if !ml_kem_public_key_is_canonical(ml_kem_bytes) {
            return Err(CryptographyError::MlKem1024P384Error(
                "ML-KEM-1024 public key contains a non-canonical coefficient".to_string(),
            ));
        }

        let ml_kem_bytes = ml_kem_bytes.try_into().map_err(|_| {
            CryptographyError::LengthError(
                "ML-KEM-1024 public key has the wrong length".to_string(),
            )
        })?;
        let ml_kem_key = MlKemPublicKey::from_bytes(ml_kem_bytes);
        let p384_key = p384::PublicKey::from_sec1_bytes(p384_bytes).map_err(|_| {
            CryptographyError::MlKem1024P384Error(
                "P-384 public key is not a valid curve point".to_string(),
            )
        })?;

        Ok(Self {
            ml_kem_key,
            p384_key,
        })
    }
}

/// Report whether every ML-KEM-1024 coefficient is below the FIPS 203 modulus.
///
/// FIPS 203 encodes two 12-bit coefficients in each three-byte block. The
/// ml-kem 0.2 decoding API does not expose this check.
fn ml_kem_public_key_is_canonical(bytes: &[u8]) -> bool {
    bytes.len() >= ML_KEM_POLY_VEC_LENGTH
        && bytes[..ML_KEM_POLY_VEC_LENGTH]
            .chunks_exact(3)
            .all(|chunk| {
                let first = u16::from(chunk[0]) | (u16::from(chunk[1] & 0x0f) << 8);
                let second = (u16::from(chunk[1]) >> 4) | (u16::from(chunk[2]) << 4);
                first < ML_KEM_MODULUS && second < ML_KEM_MODULUS
            })
}

impl Serialize for MlKem1024P384PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for MlKem1024P384PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(MlKem1024P384PublicKeyVisitor)
    }
}

struct MlKem1024P384PublicKeyVisitor;

impl Visitor<'_> for MlKem1024P384PublicKeyVisitor {
    type Value = MlKem1024P384PublicKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            formatter,
            "a {PUBLIC_KEY_LENGTH}-byte MLKEM1024-P384 public key"
        )
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        MlKem1024P384PublicKey::from_bytes(value).map_err(E::custom)
    }
}

impl Named for MlKem1024P384PublicKey {
    const NAME: &'static str = "MlKem1024P384PublicKey";
}

// The `Version` and `Versionize` derives build a versioned mirror of every field.
// `ml_kem_key` and `p384_key` come from other crates and are not versionable, so
// both traits are written out here. They serialize the key through its own
// `Serialize` implementation, which encodes the 1665-byte wire format.
#[derive(Serialize, Deserialize)]
pub struct MlKem1024P384PublicKeyOwned(MlKem1024P384PublicKey);

impl From<MlKem1024P384PublicKey> for MlKem1024P384PublicKeyOwned {
    fn from(key: MlKem1024P384PublicKey) -> Self {
        Self(key)
    }
}

impl TryFrom<MlKem1024P384PublicKeyOwned> for MlKem1024P384PublicKey {
    type Error = UnversionizeError;

    fn try_from(versioned: MlKem1024P384PublicKeyOwned) -> Result<Self, Self::Error> {
        Ok(versioned.0)
    }
}

impl Version for MlKem1024P384PublicKey {
    type Ref<'vers> = &'vers MlKem1024P384PublicKey;
    type Owned = MlKem1024P384PublicKeyOwned;
}

#[derive(VersionsDispatch)]
pub enum MlKem1024P384PublicKeyVersions {
    V0(MlKem1024P384PublicKey),
}

impl Versionize for MlKem1024P384PublicKey {
    type Versioned<'vers> =
        <MlKem1024P384PublicKeyVersions as VersionsDispatchTrait<Self>>::Ref<'vers>;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.into()
    }
}

impl VersionizeOwned for MlKem1024P384PublicKey {
    type VersionedOwned = <MlKem1024P384PublicKeyVersions as VersionsDispatchTrait<Self>>::Owned;

    fn versionize_owned(self) -> Self::VersionedOwned {
        self.into()
    }
}

impl Unversionize for MlKem1024P384PublicKey {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        versioned.try_into()
    }
}

/// Private key for the MLKEM1024-P384 composite KEM.
///
/// The 32-byte seed is the canonical private-key encoding. The component keys
/// are re-derived when they are needed, keeping the serialized key compact.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop, Versionize)]
#[versionize(MlKem1024P384PrivateKeyVersions)]
pub struct MlKem1024P384PrivateKey([u8; PRIVATE_KEY_LENGTH]);

impl std::fmt::Debug for MlKem1024P384PrivateKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MlKem1024P384PrivateKey")
            .field("seed", &"omitted")
            .finish()
    }
}

impl Serialize for MlKem1024P384PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for MlKem1024P384PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(MlKem1024P384PrivateKeyVisitor)
    }
}

struct MlKem1024P384PrivateKeyVisitor;

impl Visitor<'_> for MlKem1024P384PrivateKeyVisitor {
    type Value = MlKem1024P384PrivateKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            formatter,
            "a {PRIVATE_KEY_LENGTH}-byte MLKEM1024-P384 private key seed"
        )
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let seed: [u8; PRIVATE_KEY_LENGTH] = value.try_into().map_err(|_| {
            E::custom(format!(
                "MLKEM1024-P384 private key has length {}, expected {PRIVATE_KEY_LENGTH}",
                value.len()
            ))
        })?;
        // Any 32-byte string is a valid seed except when the P-384 scalar that it
        // expands to is zero or above the group order. RandomScalar in section 3.1.1
        // of the draft gets a single attempt for P-384, because the group constants
        // set Nseed == Nscalar == 48. That branch is taken with probability below
        // 2^-192, and `decapsulate` reports it, so expanding the seed here would
        // only move a full ML-KEM-1024 key generation onto the deserialization path.
        Ok(MlKem1024P384PrivateKey(seed))
    }
}

impl Named for MlKem1024P384PrivateKey {
    const NAME: &'static str = "MlKem1024P384PrivateKey";
}

#[derive(VersionsDispatch)]
pub enum MlKem1024P384PrivateKeyVersions {
    V0(MlKem1024P384PrivateKey),
}

/// Generate a fresh MLKEM1024-P384 key pair.
pub(crate) fn keygen(
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<(MlKem1024P384PrivateKey, MlKem1024P384PublicKey), CryptographyError> {
    loop {
        let mut seed = Zeroizing::new([0_u8; PRIVATE_KEY_LENGTH]);
        rng.fill_bytes(&mut *seed);
        if let Ok((_, public_key, _)) = expand_key(&seed) {
            return Ok((MlKem1024P384PrivateKey(*seed), public_key));
        }
    }
}

/// Encapsulate a shared secret to an MLKEM1024-P384 public key.
///
/// This is `Encaps` of section 5.5 of
/// <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-11.html>, and
/// [`encap_with_rng`](https://github.com/rozbb/rust-hpke/blob/024f006836ce2adbfc528b25e22b635065b16096/src/kem/mlkem_nistp.rs#L313) in `rust-hpke`.
pub(crate) fn encapsulate(
    rng: &mut (impl CryptoRng + RngCore),
    public_key: &MlKem1024P384PublicKey,
) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_SECRET_LENGTH]>), CryptographyError> {
    let (ml_kem_ct, ml_kem_shared_secret) = public_key
        .ml_kem_key
        .encapsulate(rng)
        .map_err(|_| CryptographyError::MlKemError)?;
    let ml_kem_shared_secret = Zeroizing::new(ml_kem_shared_secret);

    let ephemeral_secret = p384::ecdh::EphemeralSecret::random(rng);
    let ephemeral_public = ephemeral_secret.public_key().to_encoded_point(false);
    let p384_shared_secret = ephemeral_secret.diffie_hellman(&public_key.p384_key);
    let recipient_public = public_key.p384_key.to_encoded_point(false);
    let shared_secret = combine_shared_secrets(
        &ml_kem_shared_secret,
        p384_shared_secret.raw_secret_bytes(),
        ephemeral_public.as_bytes(),
        recipient_public.as_bytes(),
    );

    let kem_ciphertext = [ml_kem_ct.as_slice(), ephemeral_public.as_bytes()].concat();
    debug_assert_eq!(kem_ciphertext.len(), CIPHERTEXT_LENGTH);
    Ok((kem_ciphertext, shared_secret))
}

/// Decapsulate an MLKEM1024-P384 shared secret.
///
/// This is `Decaps` of section 5.5 of
/// <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-11.html>, and
/// [`decap`](https://github.com/rozbb/rust-hpke/blob/024f006836ce2adbfc528b25e22b635065b16096/src/kem/mlkem_nistp.rs#L258) in `rust-hpke`.
pub(crate) fn decapsulate(
    ciphertext: &[u8],
    private_key: &MlKem1024P384PrivateKey,
) -> Result<Zeroizing<[u8; SHARED_SECRET_LENGTH]>, CryptographyError> {
    if ciphertext.len() != CIPHERTEXT_LENGTH {
        return Err(CryptographyError::LengthError(format!(
            "MLKEM1024-P384 ciphertext has length {}, expected {CIPHERTEXT_LENGTH}",
            ciphertext.len()
        )));
    }

    let ml_kem_ct_length = <MlKem1024 as KemCore>::CiphertextSize::USIZE;
    let (ml_kem_ct, p384_ct) = ciphertext.split_at(ml_kem_ct_length);

    let mut ml_kem_ct_array: Array<u8, <MlKem1024 as KemCore>::CiphertextSize> = Array::default();
    ml_kem_ct_array.copy_from_slice(ml_kem_ct);
    let p384_public = p384::PublicKey::from_sec1_bytes(p384_ct).map_err(|_| {
        CryptographyError::MlKem1024P384Error(
            "P-384 encapsulated key is not a valid curve point".to_string(),
        )
    })?;

    let (ml_kem_private, recipient_public, p384_private) = expand_key(&private_key.0)?;
    let ml_kem_shared_secret = ml_kem_private
        .decapsulate(&ml_kem_ct_array)
        .map_err(|_| CryptographyError::MlKemError)?;
    let ml_kem_shared_secret = Zeroizing::new(ml_kem_shared_secret);
    let p384_shared_secret =
        p384::ecdh::diffie_hellman(p384_private.to_nonzero_scalar(), p384_public.as_affine());
    let recipient_public = recipient_public.p384_key.to_encoded_point(false);

    Ok(combine_shared_secrets(
        &ml_kem_shared_secret,
        p384_shared_secret.raw_secret_bytes(),
        p384_ct,
        recipient_public.as_bytes(),
    ))
}

/// Expand a private key seed into the ML-KEM-1024 and P-384 component keys.
///
/// SHAKE-256 is the PRG, and the ML-KEM-1024 seed takes the first 64 bytes.
/// This is `expandDecapsKeyG` of section 5.1.2 of
/// <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-11.html>, and
/// [`expand_key`](https://github.com/rozbb/rust-hpke/blob/024f006836ce2adbfc528b25e22b635065b16096/src/kem/mlkem_nistp.rs#L362) in `rust-hpke`.
///
/// Returns an error when the P-384 scalar that the seed expands to is zero or
/// above the group order.
fn expand_key(
    seed: &[u8; PRIVATE_KEY_LENGTH],
) -> Result<(MlKemPrivateKey, MlKem1024P384PublicKey, p384::SecretKey), CryptographyError> {
    let mut ml_kem_seed = Zeroizing::new([0_u8; ML_KEM_SEED_LENGTH]);
    let mut p384_seed = Zeroizing::new([0_u8; P384_SCALAR_LENGTH]);
    let mut xof = Shake256::default();
    xof.update(seed);
    let mut reader = xof.finalize_xof();
    reader.read(&mut *ml_kem_seed);
    reader.read(&mut *p384_seed);

    // Borrow the halves of the guarded seed. `B32::try_from` on a slice copies,
    // which would leave the ML-KEM seed and the implicit-rejection secret in
    // unwiped temporaries.
    let d = <&B32>::try_from(&ml_kem_seed[..32]).expect("ML-KEM seed has a fixed length");
    let z = <&B32>::try_from(&ml_kem_seed[32..]).expect("ML-KEM seed has a fixed length");
    let (ml_kem_private, ml_kem_public) = MlKem1024::generate_deterministic(d, z);
    let p384_private = p384::SecretKey::from_slice(&*p384_seed).map_err(|_| {
        CryptographyError::MlKem1024P384Error("P-384 scalar rejection sampling failed".to_string())
    })?;
    let p384_public = p384_private.public_key();

    Ok((
        ml_kem_private,
        MlKem1024P384PublicKey {
            ml_kem_key: ml_kem_public,
            p384_key: p384_public,
        },
        p384_private,
    ))
}

/// Derive the composite shared secret from the two component shared secrets.
///
/// This is `C2PRICombiner` of section 5.1.3 of
/// <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-11.html> with
/// SHA3-256 as the KDF, and [`combine_ss`](https://github.com/rozbb/rust-hpke/blob/024f006836ce2adbfc528b25e22b635065b16096/src/kem/mlkem_nistp.rs#L425) in `rust-hpke`.
fn combine_shared_secrets(
    ml_kem_shared_secret: &[u8],
    p384_shared_secret: &[u8],
    ephemeral_public: &[u8],
    recipient_public: &[u8],
) -> Zeroizing<[u8; SHARED_SECRET_LENGTH]> {
    let mut digest = Sha3_256::default();
    digest.update(ml_kem_shared_secret);
    digest.update(p384_shared_secret);
    digest.update(ephemeral_public);
    digest.update(recipient_public);
    digest.update(KEM_LABEL);

    // Finalize into the guarded buffer. `finalize()` would return the shared
    // secret in an unwiped temporary.
    let mut shared_secret = Zeroizing::new([0_u8; SHARED_SECRET_LENGTH]);
    let output = <&mut Output<Sha3_256>>::try_from(&mut shared_secret[..])
        .expect("the shared secret buffer has the SHA3-256 output length");
    digest.finalize_into(output);
    shared_secret
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Digest;

    use aes_prng::AesRng;
    use rand::{Error, SeedableRng};

    struct RepeatingByteRng(u8);

    impl RngCore for RepeatingByteRng {
        fn next_u32(&mut self) -> u32 {
            u32::from_ne_bytes([self.0; 4])
        }

        fn next_u64(&mut self) -> u64 {
            u64::from_ne_bytes([self.0; 8])
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(self.0);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for RepeatingByteRng {}

    #[test]
    fn round_trip_and_key_sizes() {
        let mut rng = AesRng::seed_from_u64(42);
        let (private_key, public_key) = keygen(&mut rng).unwrap();
        let (ciphertext, sender_secret) = encapsulate(&mut rng, &public_key).unwrap();
        let receiver_secret = decapsulate(&ciphertext, &private_key).unwrap();

        assert_eq!(public_key.to_bytes().len(), PUBLIC_KEY_LENGTH);
        assert_eq!(private_key.0.len(), PRIVATE_KEY_LENGTH);
        assert_eq!(ciphertext.len(), CIPHERTEXT_LENGTH);
        assert_eq!(*sender_secret, *receiver_secret);
    }

    #[test]
    fn key_serialization_round_trip() {
        let mut rng = AesRng::seed_from_u64(42);
        let (private_key, public_key) = keygen(&mut rng).unwrap();

        let private_bytes = bc2wrap::serialize(&private_key).unwrap();
        let public_bytes = bc2wrap::serialize(&public_key).unwrap();
        assert_eq!(private_bytes.len(), PRIVATE_KEY_LENGTH + 8);
        assert_eq!(public_bytes.len(), PUBLIC_KEY_LENGTH + 8);

        let private_key_2 = bc2wrap::deserialize_slice(&private_bytes).unwrap();
        let public_key_2 = bc2wrap::deserialize_slice(&public_bytes).unwrap();
        assert_eq!(private_key, private_key_2);
        assert_eq!(public_key, public_key_2);
    }

    #[test]
    fn malformed_p384_ciphertext_is_rejected() {
        let mut rng = AesRng::seed_from_u64(42);
        let (private_key, public_key) = keygen(&mut rng).unwrap();
        let (mut ciphertext, _) = encapsulate(&mut rng, &public_key).unwrap();
        let p384_offset = <MlKem1024 as KemCore>::CiphertextSize::USIZE;
        ciphertext[p384_offset] = 0x02;

        assert!(matches!(
            decapsulate(&ciphertext, &private_key),
            Err(CryptographyError::MlKem1024P384Error(_))
        ));
    }

    #[test]
    fn non_canonical_ml_kem_public_key_is_rejected() {
        let mut rng = AesRng::seed_from_u64(42);
        let (_, public_key) = keygen(&mut rng).unwrap();
        let mut bytes = public_key.to_bytes();
        bytes[..3].fill(0xff);

        assert!(matches!(
            MlKem1024P384PublicKey::from_bytes(&bytes),
            Err(CryptographyError::MlKem1024P384Error(_))
        ));
    }

    #[test]
    fn matches_rust_hpke_known_answer() {
        // First MLKEM1024-P384 vector in rust-hpke's test vectors:
        // https://github.com/rozbb/rust-hpke/blob/024f006836ce2adbfc528b25e22b635065b16096/test-vectors/hybrid-defafa2.json
        let seed = [0_u8; PRIVATE_KEY_LENGTH];
        let (_, public_key, p384_private) = expand_key(&seed).unwrap();
        assert_eq!(
            hex::encode(p384_private.to_bytes()),
            "e00b3f9d338de90488973787b0916a4a9ae8bebf4e2bc07a7bc18f1a6221518238c5c4b1760c4ea8a9e47beb174f12d2"
        );
        assert_eq!(
            hex::encode(Sha3_256::digest(public_key.to_bytes())),
            "d1fd12cff1800199702d0f727113dc44c91fdc2e1c59bc40c5fba53a59f407b8"
        );

        let mut rng = RepeatingByteRng(0x64);
        let (ciphertext, shared_secret) = encapsulate(&mut rng, &public_key).unwrap();
        assert_eq!(
            hex::encode(Sha3_256::digest(&ciphertext)),
            "60445c7ec401dd023931587d848b108198eb36a51d75f3ef319babf36b15f381"
        );
        assert_eq!(
            hex::encode(*shared_secret),
            "8c028c6ea72a1c59408e2b15dd8fed8008517e861cd2329b159bda1919ea656c"
        );

        // The ciphertext is byte-identical to the vector, so this also pins
        // decapsulation against the reference implementation.
        let private_key = MlKem1024P384PrivateKey(seed);
        let decapsulated = decapsulate(&ciphertext, &private_key).unwrap();
        assert_eq!(*decapsulated, *shared_secret);
    }

    #[test]
    fn a_wrong_private_key_gives_a_different_secret() {
        let mut rng = AesRng::seed_from_u64(42);
        let (_, public_key) = keygen(&mut rng).unwrap();
        let (other_private_key, _) = keygen(&mut rng).unwrap();
        let (ciphertext, sender_secret) = encapsulate(&mut rng, &public_key).unwrap();

        // ML-KEM rejects implicitly, so decapsulation succeeds with a secret that
        // the AEAD layer above then fails to open.
        let receiver_secret = decapsulate(&ciphertext, &other_private_key).unwrap();
        assert_ne!(*sender_secret, *receiver_secret);
    }

    #[test]
    fn a_tampered_ml_kem_ciphertext_gives_a_different_secret() {
        let mut rng = AesRng::seed_from_u64(42);
        let (private_key, public_key) = keygen(&mut rng).unwrap();
        let (mut ciphertext, sender_secret) = encapsulate(&mut rng, &public_key).unwrap();
        ciphertext[0] ^= 1;

        let receiver_secret = decapsulate(&ciphertext, &private_key).unwrap();
        assert_ne!(*sender_secret, *receiver_secret);
    }

    #[test]
    fn a_wrong_length_ciphertext_is_rejected() {
        let mut rng = AesRng::seed_from_u64(42);
        let (private_key, public_key) = keygen(&mut rng).unwrap();
        let (mut ciphertext, _) = encapsulate(&mut rng, &public_key).unwrap();
        ciphertext.pop();

        assert!(matches!(
            decapsulate(&ciphertext, &private_key),
            Err(CryptographyError::LengthError(_))
        ));
    }

    #[test]
    fn a_wrong_length_private_key_seed_is_rejected() {
        let short_seed = vec![0_u8; PRIVATE_KEY_LENGTH - 1];
        let bytes = bc2wrap::serialize(&short_seed).unwrap();
        assert!(bc2wrap::deserialize_slice::<MlKem1024P384PrivateKey>(&bytes).is_err());
    }

    #[test]
    fn a_wrong_length_public_key_is_rejected() {
        let mut rng = AesRng::seed_from_u64(42);
        let (_, public_key) = keygen(&mut rng).unwrap();
        let mut bytes = public_key.to_bytes();
        bytes.pop();

        assert!(matches!(
            MlKem1024P384PublicKey::from_bytes(&bytes),
            Err(CryptographyError::LengthError(_))
        ));
    }

    #[test]
    fn an_off_curve_p384_public_key_is_rejected() {
        let mut rng = AesRng::seed_from_u64(42);
        let (_, public_key) = keygen(&mut rng).unwrap();
        let mut bytes = public_key.to_bytes();
        // Keep the 0x04 SEC1 tag and corrupt the affine x coordinate.
        let last = bytes.len() - 1;
        bytes[last] ^= 1;

        assert!(matches!(
            MlKem1024P384PublicKey::from_bytes(&bytes),
            Err(CryptographyError::MlKem1024P384Error(_))
        ));
    }
}
