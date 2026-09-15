//! MLKEM1024-P384 composite post-quantum KEM.
//!
//! This implements the MLKEM1024-P384 construction from section 4.3 of
//! <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html>.
//! It matches [`rust-hpke`](https://github.com/rozbb/rust-hpke/blob/024f006836ce2adbfc528b25e22b635065b16096/src/kem/mlkem_nistp.rs).
//!
//! We use the term "composite" to mean post-quantum+classical, which can be
//! applied to both signing and encryption. We use the term "hybrid" to mean
//! KEM+DEM (i.e., asymmetric+symmetric) encryption. This is a bit different
//! from the IETF draft above since we do not want to load the word "hybrid" to
//! mean two different things.
//!
//! While ML-KEM-1024 is NIST level 5 (256-bit security), it is paired with P384
//! to hedge against advances in cryptanalysis on lattice-based schemes. This
//! reasoning is all given in x-wing <https://eprint.iacr.org/2024/039.pdf>.

use crate::cryptography::{error::CryptographyError, rand_compat::RandCore010Adapter};
use hpke::{Deserializable, HpkeError, Kem, Serializable, kem::MlKem1024P384 as HpkeMlKem1024P384};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, de::Visitor};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use tfhe::named::Named;
use tfhe_versionable::{
    Unversionize, UnversionizeError, Version, Versionize, VersionizeOwned, VersionsDispatch,
    derived_traits::VersionsDispatch as VersionsDispatchTrait,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Length of the seed that is the canonical MLKEM1024-P384 private key.
pub(crate) const PRIVATE_KEY_LENGTH: usize = 32;
const ML_KEM_SEED_LENGTH: usize = 64;
const P384_SCALAR_LENGTH: usize = 48;
const EXPANDED_SEED_LENGTH: usize = ML_KEM_SEED_LENGTH + P384_SCALAR_LENGTH;
const ML_KEM_1024_PUBLIC_KEY_OR_CIPHERTEXT_LENGTH: usize = 1568;
const P384_PUBLIC_KEY_LENGTH: usize = 97;

/// Length of a serialized MLKEM1024-P384 public key.
pub(crate) const PUBLIC_KEY_LENGTH: usize =
    ML_KEM_1024_PUBLIC_KEY_OR_CIPHERTEXT_LENGTH + P384_PUBLIC_KEY_LENGTH;
/// Length of an MLKEM1024-P384 encapsulated key.
pub(crate) const CIPHERTEXT_LENGTH: usize =
    ML_KEM_1024_PUBLIC_KEY_OR_CIPHERTEXT_LENGTH + P384_PUBLIC_KEY_LENGTH;
/// Length of an MLKEM1024-P384 shared secret, fixed by the SHA3-256 combiner.
pub(crate) const SHARED_SECRET_LENGTH: usize = 32;

type HpkePublicKey = <HpkeMlKem1024P384 as Kem>::PublicKey;
type HpkePrivateKey = <HpkeMlKem1024P384 as Kem>::PrivateKey;
type HpkeEncappedKey = <HpkeMlKem1024P384 as Kem>::EncappedKey;

/// Public key for the MLKEM1024-P384 composite KEM.
#[derive(Clone, Debug)]
pub struct MlKem1024P384PublicKey {
    key: HpkePublicKey,
}

impl PartialEq for MlKem1024P384PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for MlKem1024P384PublicKey {}

impl MlKem1024P384PublicKey {
    /// Encode as the ML-KEM-1024 encapsulation key followed by the uncompressed
    /// SEC1 P-384 point.
    fn to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes().to_vec()
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
        let key = HpkePublicKey::from_bytes(bytes)
            .map_err(|error| map_hpke_error("MLKEM1024-P384 public key", error))?;
        Ok(Self { key })
    }
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

// The HPKE key type is not versionable, so these traits serialize it through
// the KMS-owned wrapper's `Serialize` implementation, which encodes the
// 1665-byte composite wire format.
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
        let seed = Zeroizing::new(value.try_into().map_err(|_| {
            E::custom(format!(
                "MLKEM1024-P384 private key has length {}, expected {PRIVATE_KEY_LENGTH}",
                value.len()
            ))
        })?);
        validate_private_key_seed(&seed).map_err(E::custom)?;
        Ok(MlKem1024P384PrivateKey(*seed))
    }
}

impl Named for MlKem1024P384PrivateKey {
    const NAME: &'static str = "MlKem1024P384PrivateKey";
}

#[derive(VersionsDispatch)]
pub enum MlKem1024P384PrivateKeyVersions {
    V0(MlKem1024P384PrivateKey),
}

/// Derive an MLKEM1024-P384 key pair from a seed.
///
/// The seed *is* the private key, so a caller deriving a key deterministically (from a BIP-39
/// mnemonic, say) should reach the key pair through here rather than seeding an intermediate RNG,
/// which would cap the reachable key space at that RNG's own seed width.
pub(crate) fn keygen_from_seed(
    seed: &[u8; PRIVATE_KEY_LENGTH],
) -> Result<(MlKem1024P384PrivateKey, MlKem1024P384PublicKey), CryptographyError> {
    // `rust-hpke` panics instead of erroring when its single P-384 scalar candidate is rejected,
    // so screen the seed before handing it over. The rejection has probability below 2^-192 for a
    // uniformly random seed:
    // <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-3.1.1>.
    // A caller that derives its seed deterministically cannot draw a fresh one, so the rejection
    // has to reach it as an error.
    validate_private_key_seed(seed)?;
    let hpke_private_key = HpkePrivateKey::from_bytes(seed)
        .map_err(|error| map_hpke_error("MLKEM1024-P384 private key", error))?;
    let public_key = MlKem1024P384PublicKey {
        key: HpkeMlKem1024P384::sk_to_pk(&hpke_private_key),
    };

    Ok((MlKem1024P384PrivateKey(*seed), public_key))
}

/// Generate a fresh MLKEM1024-P384 key pair.
pub(crate) fn keygen(
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<(MlKem1024P384PrivateKey, MlKem1024P384PublicKey), CryptographyError> {
    let mut seed = Zeroizing::new([0_u8; PRIVATE_KEY_LENGTH]);
    rng.fill_bytes(&mut *seed);
    keygen_from_seed(&seed)
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
    let mut rng = RandCore010Adapter::new(rng);
    let (hpke_shared_secret, hpke_encapped_key) =
        HpkeMlKem1024P384::encap_with_rng(&public_key.key, None, &mut rng)
            .map_err(|error| map_hpke_error("MLKEM1024-P384 encapsulation", error))?;

    let kem_ciphertext = hpke_encapped_key.to_bytes().to_vec();
    debug_assert_eq!(kem_ciphertext.len(), CIPHERTEXT_LENGTH);
    let mut shared_secret = Zeroizing::new([0_u8; SHARED_SECRET_LENGTH]);
    shared_secret.copy_from_slice(&hpke_shared_secret.0);
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
    // Versioned deserialization does not necessarily pass through the custom
    // Serde visitor, so validate again at the boundary before HPKE expands it.
    validate_private_key_seed(&private_key.0)?;
    let hpke_private_key = HpkePrivateKey::from_bytes(&private_key.0)
        .map_err(|error| map_hpke_error("MLKEM1024-P384 private key", error))?;
    let hpke_encapped_key = HpkeEncappedKey::from_bytes(ciphertext)
        .map_err(|error| map_hpke_error("MLKEM1024-P384 ciphertext", error))?;
    let hpke_shared_secret = HpkeMlKem1024P384::decap(&hpke_private_key, None, &hpke_encapped_key)
        .map_err(|error| map_hpke_error("MLKEM1024-P384 decapsulation", error))?;

    let mut shared_secret = Zeroizing::new([0_u8; SHARED_SECRET_LENGTH]);
    shared_secret.copy_from_slice(&hpke_shared_secret.0);
    Ok(shared_secret)
}

/// Validate the P-384 scalar derived by rust-hpke before calling its expansion
/// routine, which panics when rejection sampling exhausts its single attempt.
fn validate_private_key_seed(seed: &[u8; PRIVATE_KEY_LENGTH]) -> Result<(), CryptographyError> {
    let mut expanded_seed = Zeroizing::new([0_u8; EXPANDED_SEED_LENGTH]);
    let mut xof = Shake256::default();
    xof.update(seed);
    let mut reader = xof.finalize_xof();
    reader.read(&mut *expanded_seed);

    validate_p384_scalar(&expanded_seed[ML_KEM_SEED_LENGTH..])
}

/// Apply the range check that rust-hpke's `random_scalar` will apply, rejecting
/// zero and anything at or above the group order.
///
/// This goes through `p384_hpke`, which is pinned to the same version rust-hpke
/// depends on, so this is literally the check hpke runs rather than a second
/// crate's implementation of the same rule.
fn validate_p384_scalar(scalar: &[u8]) -> Result<(), CryptographyError> {
    if scalar.len() != P384_SCALAR_LENGTH {
        return Err(CryptographyError::LengthError(format!(
            "P-384 scalar has length {}, expected {P384_SCALAR_LENGTH}",
            scalar.len()
        )));
    }
    p384_hpke::SecretKey::from_slice(scalar)
        .map(|_| ())
        .map_err(|_| {
            CryptographyError::MlKem1024P384Error(
                "P-384 scalar rejection sampling failed".to_string(),
            )
        })
}

fn map_hpke_error(subject: &str, error: HpkeError) -> CryptographyError {
    match error {
        HpkeError::IncorrectInputLength(expected, actual) => CryptographyError::LengthError(
            format!("{subject} has length {actual}, expected {expected}"),
        ),
        error => CryptographyError::MlKem1024P384Error(format!("{subject}: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use sha2::Digest;

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
    fn p384_scalar_validation_rejects_zero_and_out_of_range_values() {
        assert!(matches!(
            validate_p384_scalar(&[0_u8; P384_SCALAR_LENGTH]),
            Err(CryptographyError::MlKem1024P384Error(_))
        ));
        assert!(matches!(
            validate_p384_scalar(&[u8::MAX; P384_SCALAR_LENGTH]),
            Err(CryptographyError::MlKem1024P384Error(_))
        ));

        let mut one = [0_u8; P384_SCALAR_LENGTH];
        one[P384_SCALAR_LENGTH - 1] = 1;
        validate_p384_scalar(&one).unwrap();
    }

    #[test]
    fn the_guard_checks_the_scalar_that_hpke_derives() {
        use p384_hpke::elliptic_curve::sec1::ToSec1Point;

        // `validate_private_key_seed` reimplements rust-hpke's `expand_key`, so agreeing on the
        // range check is not enough: the guard also has to read the same 48 bytes hpke reads. Take
        // the scalar the guard inspects, derive its public key, and check that it is the P-384 half
        // of the public key hpke derived from the same seed. Boundary values alone would not catch
        // the guard drifting onto the wrong slice of the expanded seed.
        let seed = [7_u8; PRIVATE_KEY_LENGTH];
        let hpke_public_key = MlKem1024P384PublicKey {
            key: HpkeMlKem1024P384::sk_to_pk(&HpkePrivateKey::from_bytes(&seed).unwrap()),
        };

        let mut expanded_seed = Zeroizing::new([0_u8; EXPANDED_SEED_LENGTH]);
        let mut xof = Shake256::default();
        xof.update(&seed);
        let mut reader = xof.finalize_xof();
        reader.read(&mut *expanded_seed);
        let scalar =
            p384_hpke::SecretKey::from_slice(&expanded_seed[ML_KEM_SEED_LENGTH..]).unwrap();

        assert_eq!(
            scalar.public_key().to_sec1_point(false).as_bytes(),
            &hpke_public_key.to_bytes()[ML_KEM_1024_PUBLIC_KEY_OR_CIPHERTEXT_LENGTH..]
        );
    }

    #[test]
    fn key_serialization_round_trip() {
        let mut rng = AesRng::seed_from_u64(42);
        let (private_key, public_key) = keygen(&mut rng).unwrap();

        let private_bytes = bc2wrap::serialize(&private_key).unwrap();
        let public_bytes = bc2wrap::serialize(&public_key).unwrap();
        assert_eq!(private_bytes.len(), PRIVATE_KEY_LENGTH + 8);
        assert_eq!(public_bytes.len(), PUBLIC_KEY_LENGTH + 8);
        // Keep fixed fingerprints for both key encodings so dependency upgrades cannot silently
        // change the serialized representation.
        assert_eq!(
            hex::encode(&private_bytes),
            "20000000000000005e13331a9235d9a1fdfd9534e0a65d04aef86e6358fd3c5d4f040f1f26607ac9"
        );
        // NOTE: using sha2 instead of sha3 because we don't need to add an extra direct dependency
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&public_bytes)),
            "a7e73738d532cda528eeace7bbfe8b02c9a86ce5ad2f37d73998792cdb6b089f"
        );

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
        let p384_offset = CIPHERTEXT_LENGTH - P384_PUBLIC_KEY_LENGTH;
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
        // Keep the 0x04 SEC1 tag and corrupt the affine y coordinate.
        let last = bytes.len() - 1;
        bytes[last] ^= 1;

        assert!(matches!(
            MlKem1024P384PublicKey::from_bytes(&bytes),
            Err(CryptographyError::MlKem1024P384Error(_))
        ));
    }
}
