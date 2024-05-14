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

#[macro_export]
macro_rules! field_to_attr {
    (tohex; $value:expr, $name:ident) => {
        Attribute::new(stringify!($name).to_string(), $value.$name.to_hex())
    };
    (tostr; $value:expr, $name:ident) => {
        Attribute::new(stringify!($name).to_string(), $value.$name.to_string())
    };
    (same; $value:expr, $name:ident) => {
        Attribute::new(stringify!($name).to_string(), $value.$name)
    };
}

#[macro_export]
macro_rules! attrs_to_optionals {
    ($attributes:expr; same $($str_name:ident),*;
        bytes $($byte_name:ident),*;
        generics $($generic_name:ident),*) => {

        $(
            let mut $str_name = None;
        )*
        $(
            let mut $byte_name = None;
        )*
        $(
            let mut $generic_name = None;
        )*
        for attribute in $attributes {
            match attribute.key.as_str() {
                $(
                    stringify!($str_name) => {
                        $str_name = Some(attribute.value)
                    }
                )*
                $(
                    stringify!($byte_name) => {
                        $byte_name = Some(hex::decode(attribute.value)?.into())
                    }
                )*
                $(
                    stringify!($generic_name) => {
                        $generic_name = Some(attribute.value.parse()?)
                    }
                )*
                _ => (),
            }
        }
        $(
            let $str_name = $str_name.ok_or(anyhow::anyhow!("Missing attribute '{}'", stringify!($str_name)))?;
        )*
        $(
            let $byte_name = $byte_name.ok_or(anyhow::anyhow!("Missing attribute '{}'", stringify!($byte_name)))?;
        )*
        $(
            let $generic_name = $generic_name.ok_or(anyhow::anyhow!("Missing attribute '{}'", stringify!($generic_name)))?;
        )*
    };
}
