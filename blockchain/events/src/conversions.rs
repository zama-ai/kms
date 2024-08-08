use std::fmt::Debug;
use std::ops::Deref;

use cosmwasm_schema::schemars;
use cosmwasm_schema::schemars::JsonSchema;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Eq, Hash, PartialEq, Default, Clone, Debug, JsonSchema)]
pub struct HexVector(pub Vec<u8>);

impl Deref for HexVector {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&HexVector> for Vec<u8> {
    fn from(value: &HexVector) -> Self {
        value.0.clone()
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

#[derive(Eq, PartialEq, Default, Clone, JsonSchema, Deserialize, Serialize)]
pub struct RedactedHexVector(HexVector);

impl Debug for RedactedHexVector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<REDACTED>")
    }
}

impl Deref for RedactedHexVector {
    type Target = HexVector;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<HexVector> for RedactedHexVector {
    fn from(value: HexVector) -> Self {
        RedactedHexVector(value)
    }
}

impl From<Vec<u8>> for RedactedHexVector {
    fn from(value: Vec<u8>) -> Self {
        RedactedHexVector(HexVector(value))
    }
}

#[derive(Eq, PartialEq, Default, Clone, JsonSchema, Deserialize, Serialize)]
pub struct RedactedHexVectorList(pub Vec<HexVector>);

impl Debug for RedactedHexVectorList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<REDACTED>")
    }
}

impl From<Vec<HexVector>> for RedactedHexVectorList {
    fn from(value: Vec<HexVector>) -> Self {
        RedactedHexVectorList(value)
    }
}

impl From<Vec<Vec<u8>>> for RedactedHexVectorList {
    fn from(values: Vec<Vec<u8>>) -> Self {
        let hvs = values.iter().map(|v| HexVector(v.clone())).collect();
        RedactedHexVectorList(hvs)
    }
}
