use ethers::abi::Token;
use ethers::types::{Address, U256};
use thiserror::Error;

// Define a custom error type for TryFrom implementations
#[derive(Debug, Error)]
pub enum ConversionError {
    #[error("Invalid conversion from Token")]
    InvalidConversion,
    #[error("Value exceeds 4 bits")]
    Uint4Overflow,
}

// Define a custom trait for converting to Token
pub trait TokenizableFrom {
    fn to_token(self) -> Token;
}

// Define a custom trait for converting from Token
pub trait TryTokenizable: Sized {
    type Error;

    fn from_token(token: Token) -> Result<Self, Self::Error>;
}

// Define the custom Uint4 type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U4(u8);

impl U4 {
    pub fn new(value: u8) -> Result<Self, &'static str> {
        if value <= 0x0F {
            Ok(U4(value))
        } else {
            Err("Value exceeds 4 bits")
        }
    }

    pub fn value(self) -> u8 {
        self.0
    }
}

// Implement TokenizableFrom for converting U160 to Token
impl TokenizableFrom for Address {
    fn to_token(self) -> Token {
        Token::Address(self)
    }
}

// Implement TokenizableFrom for converting primitive types and Uint4 to Token
impl TokenizableFrom for bool {
    fn to_token(self) -> Token {
        Token::Bool(self)
    }
}

impl TokenizableFrom for u8 {
    fn to_token(self) -> Token {
        Token::Uint(U256::from(self))
    }
}

impl TokenizableFrom for u16 {
    fn to_token(self) -> Token {
        Token::Uint(U256::from(self))
    }
}

impl TokenizableFrom for u32 {
    fn to_token(self) -> Token {
        Token::Uint(U256::from(self))
    }
}

impl TokenizableFrom for u64 {
    fn to_token(self) -> Token {
        Token::Uint(U256::from(self))
    }
}

impl TokenizableFrom for u128 {
    fn to_token(self) -> Token {
        Token::Uint(U256::from(self))
    }
}

impl TokenizableFrom for U256 {
    fn to_token(self) -> Token {
        Token::Uint(self)
    }
}

impl TokenizableFrom for U4 {
    fn to_token(self) -> Token {
        Token::Uint(U256::from(self.value()))
    }
}

// Implement TryTokenizable for converting Token to primitive types and Uint4

impl TryTokenizable for bool {
    type Error = ConversionError;

    fn from_token(token: Token) -> Result<Self, Self::Error> {
        if let Token::Bool(value) = token {
            Ok(value)
        } else {
            Err(ConversionError::InvalidConversion)
        }
    }
}

impl TryTokenizable for u8 {
    type Error = ConversionError;

    fn from_token(token: Token) -> Result<Self, Self::Error> {
        if let Token::Uint(value) = token {
            if value <= U256::from(u8::MAX) {
                Ok(value.as_u32() as u8)
            } else {
                Err(ConversionError::InvalidConversion)
            }
        } else {
            Err(ConversionError::InvalidConversion)
        }
    }
}

impl TryTokenizable for u16 {
    type Error = ConversionError;

    fn from_token(token: Token) -> Result<Self, Self::Error> {
        if let Token::Uint(value) = token {
            if value <= U256::from(u16::MAX) {
                Ok(value.as_u32() as u16)
            } else {
                Err(ConversionError::InvalidConversion)
            }
        } else {
            Err(ConversionError::InvalidConversion)
        }
    }
}

impl TryTokenizable for u32 {
    type Error = ConversionError;

    fn from_token(token: Token) -> Result<Self, Self::Error> {
        if let Token::Uint(value) = token {
            if value <= U256::from(u32::MAX) {
                Ok(value.as_u32())
            } else {
                Err(ConversionError::InvalidConversion)
            }
        } else {
            Err(ConversionError::InvalidConversion)
        }
    }
}

impl TryTokenizable for u64 {
    type Error = ConversionError;

    fn from_token(token: Token) -> Result<Self, Self::Error> {
        if let Token::Uint(value) = token {
            if value <= U256::from(u64::MAX) {
                Ok(value.as_u64())
            } else {
                Err(ConversionError::InvalidConversion)
            }
        } else {
            Err(ConversionError::InvalidConversion)
        }
    }
}

impl TryTokenizable for u128 {
    type Error = ConversionError;

    fn from_token(token: Token) -> Result<Self, Self::Error> {
        if let Token::Uint(value) = token {
            if value <= U256::from(u128::MAX) {
                Ok(value.as_u128())
            } else {
                Err(ConversionError::InvalidConversion)
            }
        } else {
            Err(ConversionError::InvalidConversion)
        }
    }
}

impl TryTokenizable for U256 {
    type Error = ConversionError;

    fn from_token(token: Token) -> Result<Self, Self::Error> {
        if let Token::Uint(value) = token {
            Ok(value)
        } else {
            Err(ConversionError::InvalidConversion)
        }
    }
}

impl TryTokenizable for Address {
    type Error = ConversionError;

    fn from_token(token: Token) -> Result<Self, Self::Error> {
        if let Token::Address(value) = token {
            Ok(value)
        } else {
            Err(ConversionError::InvalidConversion)
        }
    }
}

impl TryTokenizable for U4 {
    type Error = ConversionError;

    fn from_token(token: Token) -> Result<Self, Self::Error> {
        if let Token::Uint(value) = token {
            let value_as_u8 = value.as_u32() as u8;
            if value_as_u8 <= 0x0F {
                Ok(U4(value_as_u8))
            } else {
                Err(ConversionError::Uint4Overflow)
            }
        } else {
            Err(ConversionError::InvalidConversion)
        }
    }
}
