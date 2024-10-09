use crate::blockchain::Blockchain;
use crate::blockchain::KmsEventSubscriber;
use crate::util::conversion::TokenizableFrom;
use crate::util::conversion::U4;
use async_trait::async_trait;
use ethers::abi::Token;
use ethers::prelude::*;
use events::kms::FheType;
use events::kms::KeyUrlResponseValues;
use events::kms::KmsEvent;
use events::kms::ReencryptResponseValues;
use events::HexVectorList;
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
        key_id_str: String,
        enc_key: Vec<u8>,
        fhe_type: FheType,
        ciphertext: Vec<u8>,
        eip712_verifying_contract: String,
        chain_id: U256,
        acl_address: String,
    ) -> anyhow::Result<Vec<ReencryptResponseValues>> {
        tracing::debug!("🐛 Mockchain reencrypting ciphertext");
        tracing::debug!("🐛 signature: {:?}", signature);
        tracing::debug!("🐛 client_address: {:?}", client_address);
        tracing::debug!("🐛 key_id_str: {:?}", key_id_str);
        tracing::debug!("🐛 enc_key: {:?}", enc_key);
        tracing::debug!("🐛 fhe_type: {:?}", fhe_type);
        tracing::debug!("🐛 ciphertext: {:?}", ciphertext);
        tracing::debug!(
            "🐛 eip712_verifying_contract: {:?}",
            eip712_verifying_contract
        );
        tracing::debug!("🐛 chain_id: {:?}", chain_id);
        tracing::debug!("🐛 acl_address: {:?}", acl_address);

        Ok(vec![])
    }

    async fn verify_proven_ct(
        &self,
        client_address: String,
        caller_address: String,
        key_id_str: String,
        crs_id_str: String,
        ct_proof: Vec<u8>,
        eip712_domain: Eip712DomainMsg,
        acl_address: String,
    ) -> anyhow::Result<HexVectorList> {
        tracing::debug!("🐛 Mockchain verify proven ct");
        tracing::debug!("🐛 client_address: {:?}", client_address);
        tracing::debug!("🐛 caller_address: {:?}", caller_address);
        tracing::debug!("🐛 key_id_str: {:?}", key_id_str);
        tracing::debug!("🐛 crs_id_str: {:?}", crs_id_str);
        tracing::debug!("🐛 ct_proof: {:?}", ct_proof);
        tracing::debug!("🐛 eip712_domain: {:?}", eip712_domain);
        tracing::debug!("🐛 acl_address: {:?}", acl_address);

        Ok(HexVectorList::default())
    }

    async fn keyurl(&self) -> anyhow::Result<KeyUrlResponseValues> {
        tracing::debug!("🐛 Mockchain keyurl called");
        Ok(serde_json::from_str(
            r#"{
        "crs": {
             "256": {
                 "data_id": "d8d94eb3a23d22d3eb6b5e7b694e8afcd571d906",
                 "param_choice": 1,
                 "signatures": [
                     "0011223344556677889900112233445566778899",
                     "0011223344556677889900112233445566778899",
                     "0011223344556677889900112233445566778899",
                     "0011223344556677889900112233445566778899"
                 ],
                 "urls": [
                     "https://s3.amazonaws.com/bucket-name-1/PUB-p1/CRS/d8d94eb3a23d22d3eb6b5e7b694e8afcd571d906",
                     "https://s3.amazonaws.com/bucket-name-4/PUB-p4/CRS/d8d94eb3a23d22d3eb6b5e7b694e8afcd571d906",
                     "https://s3.amazonaws.com/bucket-name-2/PUB-p2/CRS/d8d94eb3a23d22d3eb6b5e7b694e8afcd571d906",
                     "https://s3.amazonaws.com/bucket-name-3/PUB-p3/CRS/d8d94eb3a23d22d3eb6b5e7b694e8afcd571d906"
                 ]
             }
         },
         "fhe_key_info": [
             {
                 "fhe_public_key": {
                     "data_id": "408d8cbaa51dece7f782fe04ba0b1c1d017b1088",
                     "param_choice": 1,
                     "signatures": [
                         "0011223344556677889900112233445566778899",
                         "0011223344556677889900112233445566778899",
                         "0011223344556677889900112233445566778899",
                         "0011223344556677889900112233445566778899"
                     ],
                     "urls": [
                         "https://s3.amazonaws.com/bucket-name-1/PUB-p1/PublicKey/408d8cbaa51dece7f782fe04ba0b1c1d017b1088",
                         "https://s3.amazonaws.com/bucket-name-4/PUB-p4/PublicKey/408d8cbaa51dece7f782fe04ba0b1c1d017b1088",
                         "https://s3.amazonaws.com/bucket-name-2/PUB-p2/PublicKey/408d8cbaa51dece7f782fe04ba0b1c1d017b1088",
                         "https://s3.amazonaws.com/bucket-name-3/PUB-p3/PublicKey/408d8cbaa51dece7f782fe04ba0b1c1d017b1088"
                     ]
                 },
                 "fhe_server_key": {
                     "data_id": "408d8cbaa51dece7f782fe04ba0b1c1d017b1088",
                     "param_choice": 1,
                     "signatures": [
                         "0011223344556677889900112233445566778899",
                         "0011223344556677889900112233445566778899",
                         "0011223344556677889900112233445566778899",
                         "0011223344556677889900112233445566778899"
                     ],
                     "urls": [
                         "https://s3.amazonaws.com/bucket-name-1/PUB-p1/ServerKey/408d8cbaa51dece7f782fe04ba0b1c1d017b1088",
                         "https://s3.amazonaws.com/bucket-name-4/PUB-p4/ServerKey/408d8cbaa51dece7f782fe04ba0b1c1d017b1088",
                         "https://s3.amazonaws.com/bucket-name-2/PUB-p2/ServerKey/408d8cbaa51dece7f782fe04ba0b1c1d017b1088",
                         "https://s3.amazonaws.com/bucket-name-3/PUB-p3/ServerKey/408d8cbaa51dece7f782fe04ba0b1c1d017b1088"
                     ]
                 }
             }
         ],
         "verf_public_key": [
             {
                 "key_id": "408d8cbaa51dece7f782fe04ba0b1c1d017b1088",
                 "server_id": 1,
                 "verf_public_key_address": "https://s3.amazonaws.com/bucket-name-1/PUB-p1/VerfAddress/408d8cbaa51dece7f782fe04ba0b1c1d017b1088",
                 "verf_public_key_url": "https://s3.amazonaws.com/bucket-name-1/PUB-p1/VerfKey/408d8cbaa51dece7f782fe04ba0b1c1d017b1088"
             },
             {
                 "key_id": "408d8cbaa51dece7f782fe04ba0b1c1d017b1088",
                 "server_id": 4,
                 "verf_public_key_address": "https://s3.amazonaws.com/bucket-name-4/PUB-p4/VerfAddress/408d8cbaa51dece7f782fe04ba0b1c1d017b1088",
                 "verf_public_key_url": "https://s3.amazonaws.com/bucket-name-4//PUB-p4/VerfKey/408d8cbaa51dece7f782fe04ba0b1c1d017b1088"
             },
             {
                 "key_id": "408d8cbaa51dece7f782fe04ba0b1c1d017b1088",
                 "server_id": 2,
                 "verf_public_key_address": "https://s3.amazonaws.com/bucket-name-2/PUB-p2/VerfAddress/408d8cbaa51dece7f782fe04ba0b1c1d017b1088",
                 "verf_public_key_url": "https://s3.amazonaws.com/bucket-name-2/PUB-p2/VerfKey/408d8cbaa51dece7f782fe04ba0b1c1d017b1088"
             },
             {
                 "key_id": "408d8cbaa51dece7f782fe04ba0b1c1d017b1088",
                 "server_id": 3,
                 "verf_public_key_address": "https://s3.amazonaws.com/bucket-name-3/PUB-p3/VerfAddress/408d8cbaa51dece7f782fe04ba0b1c1d017b1088",
                 "verf_public_key_url": "https://s3.amazonaws.com/bucket-name-3/PUB-p3/VerfKey/408d8cbaa51dece7f782fe04ba0b1c1d017b1088"
             }
         ]}"#,
        ).unwrap())
    }
}
