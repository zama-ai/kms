use anyhow::anyhow;
use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};
use std::hash::Hash;

pub const TAG_BYTES: usize = 128 / 8;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub u128);

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)?;
        Ok(())
    }
}

impl From<u128> for SessionId {
    fn from(id: u128) -> Self {
        SessionId(id)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Eq, Hash)]
pub struct RendezvousKey(pub(crate) [u8; TAG_BYTES]);

impl std::fmt::Display for RendezvousKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02X}")?
        }
        Ok(())
    }
}

impl From<u128> for RendezvousKey {
    fn from(v: u128) -> RendezvousKey {
        let mut raw = [0; TAG_BYTES];
        LittleEndian::write_u128(&mut raw, v);
        RendezvousKey(raw)
    }
}

impl TryFrom<String> for RendezvousKey {
    type Error = anyhow::Error;
    fn try_from(s: String) -> Result<RendezvousKey, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl TryFrom<&str> for RendezvousKey {
    type Error = anyhow::Error;
    fn try_from(s: &str) -> Result<RendezvousKey, Self::Error> {
        let s_bytes = s.as_bytes();
        if s_bytes.len() > TAG_BYTES {
            return Err(anyhow!("Unexpected(None)")); // TODO more helpful error message
        }
        let mut raw: [u8; TAG_BYTES] = [0; TAG_BYTES];
        for (idx, byte) in s_bytes.iter().enumerate() {
            raw[idx] = *byte;
        }
        Ok(RendezvousKey(raw))
    }
}
