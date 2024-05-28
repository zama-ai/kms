use cosmwasm_schema::schemars;
use cosmwasm_schema::schemars::JsonSchema;
use serde::{Serialize, Serializer};

#[derive(Eq, PartialEq, Default, Clone, Debug, JsonSchema)]
pub struct HexVector(pub Vec<u8>);

impl From<&HexVector> for Vec<u8> {
    fn from(value: &HexVector) -> Self {
        value.0.clone()
    }
}

impl From<HexVector> for Vec<u8> {
    fn from(value: HexVector) -> Self {
        value.0
    }
}

impl From<Vec<u8>> for HexVector {
    fn from(value: Vec<u8>) -> Self {
        HexVector(value)
    }
}

impl HexVector {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.as_slice())
    }

    pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
        Ok(HexVector(hex::decode(hex)?))
    }
}

impl Serialize for HexVector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_hex().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for HexVector {
    fn deserialize<D>(deserializer: D) -> Result<HexVector, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        HexVector::from_hex(&s).map_err(serde::de::Error::custom)
    }
}
