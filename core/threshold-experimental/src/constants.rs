use crate::algebra::levels::GenericModulus;
use crate::algebra::levels::LevelEll;
use crypto_bigint::Limb;
use crypto_bigint::NonZero;
use crypto_bigint::U768;
use std::sync::LazyLock;

/// log_2 of parameter BMult, computed from values in the paper
pub(crate) const LOG_B_MULT: u32 = 38;

/// log_2 of BGV plaintext mod - which is fixed as Z_{65537}.
pub(crate) const LOG_PLAINTEXT: u32 = 17;

/// B bound for the NewHope distribution.
pub(crate) const NEW_HOPE_BOUND: usize = 1;

/// Input party acting as dealer in the (dummy) keygen protocol.
pub const INPUT_PARTY_ID: usize = 1;

pub static PLAINTEXT_MODULUS: LazyLock<NonZero<Limb>> =
    LazyLock::new(|| NonZero::new(Limb(65537)).unwrap());
/// Delta = (Q-1) / P. This will always be an integer as Q = 1 mod P. Data living at LevelEll is mod Q.
pub static DELTA: LazyLock<LevelEll> = LazyLock::new(|| LevelEll {
    value: GenericModulus(U768::from_be_hex(
        "000043e7d82c161e10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    )),
});
