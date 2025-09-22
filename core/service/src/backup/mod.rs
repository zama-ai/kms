pub mod custodian;
pub mod error;
pub mod operator;
pub mod secretsharing;
pub mod seed_phrase;
pub mod traits;

#[cfg(test)]
mod tests;

pub const KMS_CUSTODIAN: &str = "kms-custodian";
pub const SEED_PHRASE_DESC: &str = "The SECRET seed phrase for the custodian keys is: ";
