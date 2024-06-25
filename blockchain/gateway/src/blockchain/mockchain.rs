use crate::blockchain::Blockchain;
use crate::blockchain::KmsEventSubscriber;
use crate::util::conversion::TokenizableFrom;
use crate::util::conversion::U4;
use async_trait::async_trait;
use ethers::abi::Token;
use ethers::prelude::*;
use events::kms::FheType;
use events::kms::KmsEvent;
use events::kms::ReencryptResponseValues;

pub(crate) struct MockchainImpl;

#[async_trait]
impl KmsEventSubscriber for MockchainImpl {
    async fn receive(&self, event: KmsEvent) -> anyhow::Result<()> {
        tracing::info!("🐛 Mockchain received event: {:#?}", event);
        Ok(())
    }
}

#[async_trait]
impl Blockchain for MockchainImpl {
    async fn decrypt(&self, _ctxt_handle: Vec<u8>, fhe_type: FheType) -> anyhow::Result<Token> {
        let res = match fhe_type {
            FheType::Ebool => true.to_token(),
            FheType::Euint4 => U4::new(3_u8).unwrap().to_token(),
            FheType::Euint8 => 42_u8.to_token(),
            FheType::Euint16 => 42_u16.to_token(),
            FheType::Euint32 => 42_u32.to_token(),
            FheType::Euint64 => 42_u64.to_token(),
            FheType::Euint128 => 42_u128.to_token(),
            FheType::Euint160 => Address::zero().to_token(),
            FheType::Euint256 => Address::zero().to_token(),
            events::kms::FheType::Euint512 | events::kms::FheType::Euint1024 => todo!(),
            FheType::Euint2048 => Address::zero().to_token(),
            FheType::Unknown => anyhow::bail!("Invalid ciphertext type"),
        };
        tracing::info!("🍊 plaintext: {:#?}", res);
        Ok(res)
    }

    async fn reencrypt(
        &self,
        signature: Vec<u8>,
        verification_key: Vec<u8>,
        enc_key: Vec<u8>,
        fhe_type: FheType,
        ciphertext: Vec<u8>,
        eip712_verifying_contract: String,
    ) -> anyhow::Result<Vec<ReencryptResponseValues>> {
        tracing::debug!("🐛 Mockchain reencrypting ciphertext");
        tracing::debug!("🐛 signature: {:?}", signature);
        tracing::debug!("🐛 verification_key: {:?}", verification_key);
        tracing::debug!("🐛 enc_key: {:?}", enc_key);
        tracing::debug!("🐛 fhe_type: {:?}", fhe_type);
        tracing::debug!("🐛 ciphertext: {:?}", ciphertext);
        tracing::debug!(
            "🐛 eip712_verifying_contract: {:?}",
            eip712_verifying_contract
        );

        Ok(vec![])
    }
}
