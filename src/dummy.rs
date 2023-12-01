use tendermint::AppHash;
use tfhe::{
    integer::{ciphertext::BaseRadixCiphertext, IntegerCiphertext, RadixClientKey},
    shortint::{
        ciphertext::Degree, CarryModulus, Ciphertext, ClassicPBSParameters, MessageModulus,
        PBSOrder,
    },
};

use tfhe::{core_crypto::entities::LweCiphertext, integer::RadixCiphertext};
use tonic::{Code, Request, Response, Status};

use crate::{
    kms::{
        kms_endpoint_server::KmsEndpoint, DecryptionRequest, DecryptionResponse, Proof,
        ReencryptionRequest, ReencryptionResponse,
    },
    types::{FHEType, Kms, Signature},
};

use crate::types::LightClientCommitResponse;

#[derive(Clone, Debug)]
pub struct CipherMeta {
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub pbs_order: PBSOrder,
}
impl Default for CipherMeta {
    fn default() -> Self {
        Self {
            degree: Degree(3),
            message_modulus: MessageModulus(4),
            carry_modulus: CarryModulus(4),
            pbs_order: PBSOrder::BootstrapKeyswitch,
        }
    }
}

pub type InternalCipher = Vec<LweCiphertext<Vec<u64>>>;

#[derive(Clone, Default, Debug)]
pub struct DummyKms {}

impl Kms for DummyKms {
    // TODO: perform decryption
    fn decrypt(&self, _ct: &[u8], ct_type: FHEType) -> anyhow::Result<DecryptionResponse> {
        // let dec_cipher: Cipher = from_bytes(ct).unwrap();
        // let plaintext = validate_and_decrypt(dec_cipher, ct, ct)?;
        let plaintext: u32 = 1337;
        let signature = self.sign(&plaintext.to_le_bytes());

        Ok(DecryptionResponse {
            plaintext,
            signature,
        })
    }

    // TODO: perform reencryption
    fn reencrypt(&self, ct: &[u8], ct_type: FHEType) -> anyhow::Result<ReencryptionResponse> {
        let reencrypted_ciphertext = ct.to_vec();
        let signature = self.sign(ct);

        Ok(ReencryptionResponse {
            reencrypted_ciphertext,
            signature,
        })
    }
}

/// KMS which does not do signatures or encryption of requests or responses but only does FHE decryption
#[derive(Clone, Debug)]
pub struct InsecureKms {
    pub params: ClassicPBSParameters,
    secret_key: RadixClientKey,
}

impl Kms for InsecureKms {
    // TODO: perform decryption
    fn decrypt(&self, ct: &[u8], ct_type: FHEType) -> anyhow::Result<DecryptionResponse> {
        let internal_ct = self.deserialize(ct, ct_type)?;
        match ct_type {
            FHEType::Uint8 => {
                let plain_text: u8 = self.secret_key.decrypt::<u8>(&internal_ct);
            }
            FHEType::Uint16 => todo!(),
            FHEType::Uint32 => todo!(),
            FHEType::Uint64 => todo!(),
            FHEType::Uint128 => todo!(),
        }

        // let dec_cipher: Cipher = from_bytes(ct).unwrap();
        // let plaintext = validate_and_decrypt(dec_cipher, ct, ct)?;
        let plaintext: u32 = 1337;
        let signature = self.sign(&plaintext.to_le_bytes());

        Ok(DecryptionResponse {
            plaintext,
            signature,
        })
    }

    // TODO: perform reencryption
    fn reencrypt(&self, ct: &[u8], ct_type: FHEType) -> anyhow::Result<ReencryptionResponse> {
        let reencrypted_ciphertext = ct.to_vec();
        let signature = self.sign(ct);

        Ok(ReencryptionResponse {
            reencrypted_ciphertext,
            signature,
        })
    }
}

impl InsecureKms {
    pub fn new(secret_key: RadixClientKey, params: ClassicPBSParameters) -> Self {
        InsecureKms {
            params: params,
            secret_key: secret_key,
        }
    }

    /// Deserialize serialized highlevel FHE ciphertext into a vector of [LweCiphertext] that can be decrypted using the low level functions
    fn deserialize(
        &self,
        highlevel_ct: &[u8],
        fhe_type: FHEType,
    ) -> anyhow::Result<(InternalCipher, CipherMeta)> {
        let radix_cipher = match fhe_type {
            FHEType::Uint8 => {
                // TODO convert high level to low level
                bincode::deserialize::<RadixCiphertext>(highlevel_ct)?
            }
            FHEType::Uint16 => {
                // TODO convert high level to low level
                bincode::deserialize::<RadixCiphertext>(highlevel_ct)?
            }
            FHEType::Uint32 => {
                // TODO convert high level to low level
                bincode::deserialize::<RadixCiphertext>(highlevel_ct)?
            }
            FHEType::Uint64 => {
                // TODO convert high level to low level
                bincode::deserialize::<RadixCiphertext>(highlevel_ct)?
            }
            FHEType::Uint128 => {
                // TODO convert high level to low level
                bincode::deserialize::<RadixCiphertext>(highlevel_ct)?
            }
        };
        Ok(Self::from_tfhe_cipher(radix_cipher))
    }

    // Helper method to convert between the format we use for decryption and the one used by the tfhe-rs API
    fn to_tfhe_cipher(internal_cipher: InternalCipher, meta: CipherMeta) -> RadixCiphertext {
        let mut blocks = Vec::with_capacity(internal_cipher.len());
        for cur_block in internal_cipher {
            let cur_ct = Ciphertext {
                ct: cur_block,
                degree: meta.degree,
                message_modulus: meta.message_modulus,
                carry_modulus: meta.carry_modulus,
                pbs_order: meta.pbs_order,
            };
            blocks.push(cur_ct)
        }
        BaseRadixCiphertext::from(blocks)
    }
    fn from_tfhe_cipher(tfhe_cipher: RadixCiphertext) -> (InternalCipher, CipherMeta) {
        let mut cipher_meta = CipherMeta::default();
        let mut res = Vec::new();
        for (i, cur_block) in tfhe_cipher.blocks().iter().enumerate() {
            res.push(cur_block.ct.to_owned());
            // TODO can we assume it is the same for each block?
            if i == 0 {
                cipher_meta.degree = cur_block.degree;
                cipher_meta.message_modulus = cur_block.message_modulus;
                cipher_meta.carry_modulus = cur_block.carry_modulus;
                cipher_meta.pbs_order = cur_block.pbs_order;
            }
        }
        (res, cipher_meta)
    }

    // TODO: sign the message
    fn sign(&self, _msg: &[u8]) -> Signature {
        Vec::from("sig")
    }
}

#[tonic::async_trait]
impl KmsEndpoint for DummyKms {
    async fn decrypt(
        &self,
        request: Request<DecryptionRequest>,
    ) -> Result<Response<DecryptionResponse>, Status> {
        let req = request.into_inner();

        verify_proof(req.proof.unwrap()).await?;
        // TODO the request needs to have the type
        let res = Kms::decrypt(self, &req.ciphertext, FHEType::Uint8);

        Ok(Response::new(res.unwrap()))
    }

    async fn reencrypt(
        &self,
        request: Request<ReencryptionRequest>,
    ) -> Result<Response<ReencryptionResponse>, Status> {
        let req = request.into_inner();

        verify_proof(req.proof.unwrap()).await?;

        let res = Kms::reencrypt(self, &req.ciphertext, FHEType::Uint8);

        Ok(Response::new(res.unwrap()))
    }
}

impl DummyKms {
    // TODO: sign the message
    fn sign(&self, _msg: &[u8]) -> Signature {
        Vec::from("sig")
    }
}

async fn verify_proof(proof: Proof) -> Result<(), Status> {
    let _root: AppHash = get_state_root(proof.height).await?;
    // TODO: verify `proof` against `root`
    Ok(())
}

async fn get_state_root(height: u32) -> Result<AppHash, Status> {
    let response = reqwest::get(format!("http://127.0.0.1:8888/commit?height={}", height)) // assumes light client local service is up and running
        .await
        .or(Err(Status::new(
            Code::Unavailable,
            "unable to reach light client",
        )))?
        .json::<LightClientCommitResponse>()
        .await
        .or(Err(Status::new(
            Code::Unavailable,
            "unable to deserialize light client response",
        )))?;

    Ok(response.result.signed_header.header.app_hash)
}

#[cfg(test)]
mod tests {
    use tfhe::{integer::gen_keys_radix, shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS};

    use crate::dummy::{FHEType, InsecureKms};

    #[test]
    fn parsing() {
        let msg = 42_u8;
        let kms = InsecureKms {
            params: PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        };
        let num_block = 4;
        // TODO change to high level. I.e.
        // let config = ConfigBuilder::all_disabled()
        //     .enable_default_integers()
        //     .build();
        // let (client_key, server_key) = generate_keys(config);
        // let ct = FheUint8::encrypt(msg, &client_key);
        let (client_key, _server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block);
        let ct = client_key.encrypt(msg);
        assert_eq!(client_key.decrypt::<u8>(&ct), msg);
        let mut serialized_data = Vec::new();
        bincode::serialize_into(&mut serialized_data, &ct).unwrap();

        let (deserialized_ct, meta) = kms.deserialize(&serialized_data, FHEType::Uint8).unwrap();
        let cp = InsecureKms::to_tfhe_cipher(deserialized_ct, meta);
        assert_eq!(cp, ct);
        let output: u8 = client_key.decrypt::<u8>(&cp);
        assert_eq!(output, msg);
    }
}
