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
pub const ZK_DSEP_GAMMA: DomainSep = *b"VCProve2";
pub const ZK_DSEP_CRS_UPDA: DomainSep = *b"CRS_UPDA";
