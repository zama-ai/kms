//! Backward-compatibility facade for the signing types.
//!
//! The signing implementation now lives under [`crate::cryptography::signing`]:
//! ECDSA key/EIP-712 types in [`crate::cryptography::signing::ecdsa`], and the
//! scheme vocabulary / scheme-tagged [`Signature`] in
//! [`crate::cryptography::signing`]. This module re-exports the public surface
//! under its historic `cryptography::signatures::…` paths so existing callers
//! (and the `core-client` / WASM / backward-compatibility consumers) are
//! unaffected. Prefer the `signing` paths in new code.

// TODO I think we should just do the refactor
pub use crate::cryptography::signing::ecdsa::{
    ERR_EXT_USER_DECRYPTION_SIG_BAD_LENGTH, PrivateSigKey, PrivateSigKeyVersions, PublicSigKey,
    PublicSigKeyVersions, SIG_SIZE, compute_eip712_signature, gen_sig_keys,
    recover_address_from_ext_signature,
};
pub use crate::cryptography::signing::{
    HasSigningScheme, Signature, SignatureVersions, SigningSchemeType, SigningSchemeTypeVersions,
};

pub(crate) use crate::cryptography::signing::ecdsa::{
    check_normalized, internal_sign, internal_verify_sig,
};
