use crypto_bigint::Limb;
use crypto_bigint::NonZero;
use lazy_static::lazy_static;

/// log_2 of parameter BMult, computed from values in the paper
pub(crate) const LOG_B_MULT: u32 = 38;

/// log_2 of BGV plaintext mod - which is fixed as Z_{65537}.
pub(crate) const LOG_PLAINTEXT: u32 = 17;

lazy_static! {
    pub static ref PLAINTEXT_MODULUS: NonZero<Limb> = NonZero::new(Limb(65537)).unwrap();
}
