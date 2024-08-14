use super::state::ProofStorage;
use crate::proof::strategy::TendermintProofStrategy;
use aipsc::contract::InclusionProofContract;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{CustomMsg, Response, StdError, StdResult};
use events::HexVector;
use schemars::{
    gen::SchemaGenerator,
    schema::{InstanceType, Schema, SchemaObject},
    JsonSchema,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, ops::Deref};
use sylvia::{contract, types::ExecCtx};
use tendermint::merkle::proof::ProofOps;

#[cw_serde]
pub struct TendermintUpdateHeader {
    pub new_header: NewHeader,
    pub new_validator_set: Option<NewValidatorSet>,
}

#[cw_serde]
pub struct NewValidatorSet {
    pub new_validators: Vec<HexVector>,
    pub sign_with_old_validators: Vec<HexVector>,
}

#[cw_serde]
pub struct NewHeader {
    pub signatures: Vec<HexVector>,
    pub root_hash: HexVector,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq)]
pub struct ProofTendermint {
    proof: ProofOps,
    keypath: String,
}

impl ProofTendermint {
    pub fn proof(&self) -> &ProofOps {
        &self.proof
    }

    pub fn keypath(&self) -> &str {
        &self.keypath
    }
}

impl JsonSchema for ProofTendermint {
    fn schema_name() -> String {
        "ProofTendermint".to_owned()
    }

    fn schema_id() -> Cow<'static, str> {
        Cow::Borrowed("events::kms::ProofTendermint")
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        let mut schema = SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            ..Default::default()
        };
        let obj = schema.object();
        obj.required.insert("proof".to_owned());
        obj.required.insert("keypath".to_owned());
        let mut schema_proof = SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            ..Default::default()
        };
        let obj_proof = schema_proof.object();
        obj_proof.required.insert("ops".to_owned());

        let mut schema_op = SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            ..Default::default()
        };
        let obj_op = schema_op.object();
        obj_op.required.insert("field_type".to_owned());
        obj_op.required.insert("key".to_owned());
        obj_op.required.insert("data".to_owned());
        obj_op
            .properties
            .insert("field_type".to_owned(), <String>::json_schema(gen));
        obj_op
            .properties
            .insert("key".to_owned(), <Vec<u8>>::json_schema(gen));
        obj_op
            .properties
            .insert("data".to_owned(), <Vec<u8>>::json_schema(gen));

        let mut schema_array_op = SchemaObject {
            instance_type: Some(InstanceType::Array.into()),
            ..Default::default()
        };
        let obj_array_op = schema_array_op.array();
        obj_array_op.items = Some(schemars::schema::SingleOrVec::Single(Box::new(
            schema_op.into(),
        )));
        obj_proof
            .properties
            .insert("ops".to_owned(), schema_array_op.into());
        obj.properties
            .insert("proof".to_owned(), schema_proof.into());
        obj.properties
            .insert("keypath".to_owned(), <String>::json_schema(gen));
        schema.into()
    }
}

#[derive(Default)]
pub struct ProofContract {
    pub(crate) storage: ProofStorage,
}

#[contract]
#[sv::messages(aipsc::contract as InclusionProofContract)]
impl ProofContract {
    pub fn new() -> Self {
        Self {
            storage: ProofStorage::default(),
        }
    }
    #[sv::msg(instantiate)]
    pub fn instantiate(&self, ctx: ExecCtx, validator_set: Vec<HexVector>) -> StdResult<Response> {
        self.storage
            .set_validators(ctx.deps.storage, validator_set)?;
        Ok(Response::default())
    }
}

impl CustomMsg for TendermintUpdateHeader {}
impl CustomMsg for ProofTendermint {}

impl InclusionProofContract for ProofContract {
    type Error = StdError;
    type UpdateHeader = TendermintUpdateHeader;

    fn update_header(
        &self,
        ctx: ExecCtx,
        update_header: TendermintUpdateHeader,
    ) -> StdResult<Response> {
        // if there are new validators, update the validator set_validators
        if let Some(validators) = update_header.new_validator_set {
            let old_validators = self.storage.get_validators(ctx.deps.storage)?;
            let msg = validators
                .new_validators
                .iter()
                .flat_map(|v: &HexVector| v.deref().clone())
                .collect::<Vec<u8>>();
            TendermintProofStrategy::verify_signatures(
                validators.sign_with_old_validators,
                old_validators,
                &msg,
            )?;
            self.storage
                .set_validators(ctx.deps.storage, validators.new_validators)?;
        }

        // verify the signatures
        let validators = self.storage.get_validators(ctx.deps.storage)?;
        TendermintProofStrategy::verify_signatures(
            update_header.new_header.signatures,
            validators,
            update_header.new_header.root_hash.deref().as_slice(),
        )?;

        // update root hash
        self.storage
            .set_last_root_hash(ctx.deps.storage, update_header.new_header.root_hash)
            .map(|_| Response::default())
    }

    fn verify_proof(&self, ctx: ExecCtx, proof: Vec<u8>, value: Vec<u8>) -> StdResult<Response> {
        let proof_tendermint = bincode::deserialize(&proof[..]).unwrap();
        println!("verify_proof: {:?}", proof_tendermint);
        let root_hash = self.storage.get_last_root_hash(ctx.deps.storage)?;
        TendermintProofStrategy::verify(proof_tendermint, root_hash, &value)?;
        Ok(Response::default())
    }
}
