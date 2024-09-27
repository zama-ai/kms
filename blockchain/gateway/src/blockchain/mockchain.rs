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
use events::kms::ZkpResponseValues;
use kms_lib::kms::Eip712DomainMsg;

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
    async fn decrypt(
        &self,
        typed_cts: Vec<(Vec<u8>, FheType, Vec<u8>)>,
        eip712_domain: Eip712DomainMsg,
        acl_address: String,
    ) -> anyhow::Result<(Vec<Token>, Vec<Vec<u8>>)> {
        let mut ptxts = Vec::new();

        for (_ct, fhe_type, _external_ct_handle) in typed_cts {
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
            ptxts.push(res);
        }

        tracing::debug!("🍊 eip712_domain: {:?}", eip712_domain);
        tracing::debug!("🍊 acl_address: {:?}", acl_address);

        let mock_sig = vec![0u8; 65];
        Ok((ptxts, vec![mock_sig]))
    }

    async fn reencrypt(
        &self,
        signature: Vec<u8>,
        client_address: String,
        enc_key: Vec<u8>,
        fhe_type: FheType,
        ciphertext: Vec<u8>,
        eip712_verifying_contract: String,
        chain_id: U256,
    ) -> anyhow::Result<Vec<ReencryptResponseValues>> {
        tracing::debug!("🐛 Mockchain reencrypting ciphertext");
        tracing::debug!("🐛 signature: {:?}", signature);
        tracing::debug!("🐛 client_address: {:?}", client_address);
        tracing::debug!("🐛 enc_key: {:?}", enc_key);
        tracing::debug!("🐛 fhe_type: {:?}", fhe_type);
        tracing::debug!("🐛 ciphertext: {:?}", ciphertext);
        tracing::debug!(
            "🐛 eip712_verifying_contract: {:?}",
            eip712_verifying_contract
        );
        tracing::debug!("🐛 chain_id: {:?}", chain_id);

        Ok(vec![])
    }

    async fn zkp(
        &self,
        client_address: String,
        caller_address: String,
        ct_proof: Vec<u8>,
        max_num_bits: u32,
        chain_id: U256,
        eip712_domain: Eip712DomainMsg,
        acl_address: String,
    ) -> anyhow::Result<Vec<ZkpResponseValues>> {
        tracing::debug!("🐛 Mockchain zkp");
        tracing::debug!("🐛 client_address: {:?}", client_address);
        tracing::debug!("🐛 caller_address: {:?}", caller_address);
        tracing::debug!("🐛 ct_proof: {:?}", ct_proof);
        tracing::debug!("🐛 max_num_bits: {:?}", max_num_bits);
        tracing::debug!("🐛 chain_id: {:?}", chain_id);
        tracing::debug!("🐛 eip712_domain: {:?}", eip712_domain);
        tracing::debug!("🐛 acl_address: {:?}", acl_address);

        Ok(vec![])
    }
}
