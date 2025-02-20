use lazy_static::lazy_static;

// We default to the maximum number of bits for the largest
// type that we support, which is `Euint2048`.
pub const ZK_DEFAULT_MAX_NUM_BITS: usize = 2048;

//Need to be careful that one DSEP isn't the prefix of another
pub const ZK_DSEP_HASH: [u8; 12] = *b"ZK_DSEP_HASH";
pub const ZK_DSEP_HASH_T: [u8; 9] = *b"ZK_DSEP_T";
pub const ZK_DSEP_HASH_AGG: [u8; 11] = *b"ZK_DSEP_AGG";
pub const ZK_DSEP_HASH_LMAP: [u8; 12] = *b"ZK_DSEP_LMAP";
pub const ZK_DSEP_HASH_Z: [u8; 9] = *b"ZK_DSEP_Z";
pub const ZK_DSEP_HASH_W: [u8; 9] = *b"ZK_DSEP_W";
pub const ZK_DSEP_HASH_R: [u8; 9] = *b"ZK_DSEP_R";
pub const ZK_DSEP_HASH_PHI: [u8; 11] = *b"ZK_DSEP_PHI";
pub const ZK_DSEP_HASH_XI: [u8; 10] = *b"ZK_DSEP_XI";
pub const ZK_DSEP_HASH_CHI: [u8; 11] = *b"ZK_DSEP_CHI";

// Turn the above constants into types suitable for zk api
const ZK_DSEP_SIZE: usize = 256;
lazy_static! {
    pub(crate) static ref ZK_DSEP_HASH_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_HASH.len()].copy_from_slice(&ZK_DSEP_HASH);
        array
    };
    pub(crate) static ref ZK_DSEP_HASH_T_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_HASH_T.len()].copy_from_slice(&ZK_DSEP_HASH_T);
        array
    };
    pub(crate) static ref ZK_DSEP_HASH_AGG_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_HASH_AGG.len()].copy_from_slice(&ZK_DSEP_HASH_AGG);
        array
    };
    pub(crate) static ref ZK_DSEP_HASH_LMAP_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_HASH_LMAP.len()].copy_from_slice(&ZK_DSEP_HASH_LMAP);
        array
    };
    pub(crate) static ref ZK_DSEP_HASH_Z_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_HASH_Z.len()].copy_from_slice(&ZK_DSEP_HASH_Z);
        array
    };
    pub(crate) static ref ZK_DSEP_HASH_W_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_HASH_W.len()].copy_from_slice(&ZK_DSEP_HASH_W);
        array
    };
    pub(crate) static ref ZK_DSEP_HASH_R_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_HASH_R.len()].copy_from_slice(&ZK_DSEP_HASH_R);
        array
    };
    pub(crate) static ref ZK_DSEP_HASH_PHI_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_HASH_PHI.len()].copy_from_slice(&ZK_DSEP_HASH_PHI);
        array
    };
    pub(crate) static ref ZK_DSEP_HASH_XI_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_HASH_XI.len()].copy_from_slice(&ZK_DSEP_HASH_XI);
        array
    };
    pub(crate) static ref ZK_DSEP_HASH_CHI_PADDED: [u8; ZK_DSEP_SIZE] = {
        let mut array = [0_u8; ZK_DSEP_SIZE];
        array[..ZK_DSEP_HASH_CHI.len()].copy_from_slice(&ZK_DSEP_HASH_CHI);
        array
    };
}
