use lazy_static::lazy_static;

//Need to be careful that one DSEP isn't the prefix of another
pub const ZK_DSEP_HASH: [u8; 12] = *b"ZK_DSEP_HASH";
pub const ZK_DSEP_HASH_T: [u8; 9] = *b"ZK_DSEP_T";
pub const ZK_DSEP_HASH_AGG: [u8; 11] = *b"ZK_DSEP_AGG";
pub const ZK_DSEP_HASH_LMAP: [u8; 12] = *b"ZK_DSEP_LMAP";
pub const ZK_DSEP_HASH_Z: [u8; 9] = *b"ZK_DSEP_Z";
pub const ZK_DSEP_HASH_W: [u8; 9] = *b"ZK_DSEP_W";

//Turn the above constants into types suitable for zk api
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
}
