use lazy_static::lazy_static;

use crate::hashing::DomainSep;

// We default to the maximum number of bits for the largest
// type that we support, which is `Euint2048`.
pub const ZK_DEFAULT_MAX_NUM_BITS: usize = 2048;

// Ceremony proof domain separators
pub const ZK_DSEP_HASH: DomainSep = *b"ZKHASH__";
pub const ZK_DSEP_HASH_P: DomainSep = *b"ZKHASH_p";
// Ciphertext proof domain separators
pub const ZK_DSEP_T: DomainSep = *b"ZKHASH_T";
pub const ZK_DSEP_AGG: DomainSep = *b"ZK_AGGRE";
pub const ZK_DSEP_LMAP: DomainSep = *b"ZKLINMAP";
pub const ZK_DSEP_Z: DomainSep = *b"ZKHASH_Z";
pub const ZK_DSEP_W: DomainSep = *b"ZKHASH_W";
pub const ZK_DSEP_R: DomainSep = *b"ZKHASH_R";
pub const ZK_DSEP_PHI: DomainSep = *b"ZKHA_PHI";
pub const ZK_DSEP_XI: DomainSep = *b"ZKHAS_XI";
pub const ZK_DSEP_CHI: DomainSep = *b"ZKHA_CHI";

// Turn the above constants into types suitable for zk api from tfhe-rs
const ZK_DSEP_SIZE: usize = 256;
lazy_static! {
    pub(crate) static ref ZK_DSEP_HASH_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_HASH.len()].copy_from_slice(&ZK_DSEP_HASH);
        array
    };
    pub(crate) static ref ZK_DSEP_T_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_T.len()].copy_from_slice(&ZK_DSEP_T);
        array
    };
    pub(crate) static ref ZK_DSEP_AGG_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_AGG.len()].copy_from_slice(&ZK_DSEP_AGG);
        array
    };
    pub(crate) static ref ZK_DSEP_LMAP_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_LMAP.len()].copy_from_slice(&ZK_DSEP_LMAP);
        array
    };
    pub(crate) static ref ZK_DSEP_Z_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_Z.len()].copy_from_slice(&ZK_DSEP_Z);
        array
    };
    pub(crate) static ref ZK_DSEP_W_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_W.len()].copy_from_slice(&ZK_DSEP_W);
        array
    };
    pub(crate) static ref ZK_DSEP_R_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_R.len()].copy_from_slice(&ZK_DSEP_R);
        array
    };
    pub(crate) static ref ZK_DSEP_PHI_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_PHI.len()].copy_from_slice(&ZK_DSEP_PHI);
        array
    };
    pub(crate) static ref ZK_DSEP_XI_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_XI.len()].copy_from_slice(&ZK_DSEP_XI);
        array
    };
    pub(crate) static ref ZK_DSEP_CHI_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_CHI.len()].copy_from_slice(&ZK_DSEP_CHI);
        array
    };
}
