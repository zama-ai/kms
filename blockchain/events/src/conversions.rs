use std::fmt::Debug;
use std::ops::Deref;

use cosmwasm_schema::schemars;
use cosmwasm_schema::schemars::JsonSchema;
use serde::{Deserialize, Serialize, Serializer};
use tfhe_versionable::{Versionize, VersionsDispatch};

#[derive(Serialize, Deserialize, Debug, Clone, VersionsDispatch)]
pub enum HexVectorVersioned {
    V0(HexVector),
}

#[derive(Eq, Hash, PartialEq, Default, Clone, Debug, JsonSchema, Versionize)]
#[versionize(HexVectorVersioned)]
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

#[derive(Clone, Debug, Deserialize, Serialize, VersionsDispatch)]
pub enum RedactedHexVectorVersioned {
    V0(RedactedHexVector),
}

#[derive(Eq, PartialEq, Default, Clone, JsonSchema, Deserialize, Serialize, Versionize)]
#[versionize(RedactedHexVectorVersioned)]
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

#[derive(Clone, Debug, Deserialize, Serialize, VersionsDispatch)]
pub enum RedactedHexVectorListVersioned {
    V0(RedactedHexVectorList),
}

#[derive(Eq, PartialEq, Default, Clone, JsonSchema, Deserialize, Serialize, Versionize)]
#[versionize(RedactedHexVectorListVersioned)]
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

#[derive(Clone, Debug, Deserialize, Serialize, VersionsDispatch)]
pub enum HexVectorListVersioned {
    V0(HexVectorList),
}

#[derive(Eq, PartialEq, Default, Debug, Clone, JsonSchema, Deserialize, Serialize, Versionize)]
#[versionize(HexVectorListVersioned)]
pub struct HexVectorList(pub Vec<HexVector>);

impl From<Vec<HexVector>> for HexVectorList {
    fn from(value: Vec<HexVector>) -> Self {
        HexVectorList(value)
    }
}

impl From<Vec<Vec<u8>>> for HexVectorList {
    fn from(values: Vec<Vec<u8>>) -> Self {
        let hvs = values.iter().map(|v| HexVector(v.clone())).collect();
        HexVectorList(hvs)
    }
}

impl From<HexVectorList> for Vec<Vec<u8>> {
    fn from(value: HexVectorList) -> Self {
        value
            .0
            .into_iter()
            .map(|inner_value| inner_value.0)
            .collect()
    }
}

impl HexVectorList {
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn contains(&self, x: &HexVector) -> bool {
        self.0.contains(x)
    }
}
