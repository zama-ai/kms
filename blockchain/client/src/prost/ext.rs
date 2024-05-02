//! Support traits for Cosmos SDK protobufs.

pub use prost::Message;

use prost::EncodeError;

/// Extension trait for [`Message`].
pub trait MessageExt: Message {
    /// Serialize this protobuf message as a byte vector.
    fn to_bytes(&self) -> Result<Vec<u8>, EncodeError>;
}

impl<M> MessageExt for M
where
    M: prost::Message,
{
    fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut bytes = Vec::new();
        Message::encode(self, &mut bytes)?;
        Ok(bytes)
    }
}
