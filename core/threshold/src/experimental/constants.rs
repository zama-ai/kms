use crate::experimental::algebra::levels::GenericModulus;
use crate::experimental::algebra::levels::LevelEll;
use crypto_bigint::Limb;
use crypto_bigint::NonZero;
use crypto_bigint::U768;
use lazy_static::lazy_static;

/// log_2 of parameter BMult, computed from values in the paper
pub(crate) const LOG_B_MULT: u32 = 38;

/// log_2 of BGV plaintext mod - which is fixed as Z_{65537}.
pub(crate) const LOG_PLAINTEXT: u32 = 17;

/// B bound for the NewHope distribution.
pub(crate) const NEW_HOPE_BOUND: usize = 1;

/// Input party acting as dealer in the (dummy) keygen protocol.
pub(crate) const INPUT_PARTY_ID: usize = 1;

lazy_static! {
    pub static ref PLAINTEXT_MODULUS: NonZero<Limb> = NonZero::new(Limb(65537)).unwrap();
    /// Delta = (Q-1) / P. This will always be an integer as Q = 1 mod P. Data living at LevelEll is mod Q.
    pub static ref DELTA: LevelEll = LevelEll {
        value: GenericModulus(U768::from_be_hex("000000012229d6eb0d4661ce91439ae10feb70a8f335e557040f6772bfc1a63cf0474ff1b9c4436769a5dabf95a6a2f8192d445dfad29269ca2f85bcecc176ac08e41079869e1bb4a82a6ee109b72168faa3e44daafea645e6dfa743102e0000"))
    };
}
