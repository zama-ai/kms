///Limits the size of the message that is sent during robust open,
/// if above this, then we split the big batch to open into smaller ones
pub(crate) const MAX_MESSAGE_BYTE_SIZE: usize = 1024 * 1024 * 1024;
