use crate::{
    backup::{
        custodian::Custodian,
        seed_phrase::{custodian_from_seed_phrase, seed_phrase_from_rng},
    },
    client::client_wasm::Client,
};
use aes_prng::AesRng;
use kms_grpc::{
    kms::v1::{CustodianContext, CustodianSetupMessage, NewCustodianContextRequest},
    RequestId,
};
use threshold_fhe::execution::runtime::party::Role;

impl Client {
    pub fn new_custodian_context_request(
        &mut self,
        request_id: &RequestId,
        amount_custodians: usize,
        threshold: u32,
    ) -> anyhow::Result<(NewCustodianContextRequest, Vec<String>)> {
        let (custodian_setup_msgs, mnemonics) =
            custodian_setup_msgs(&mut self.rng, amount_custodians)?;
        Ok((
            NewCustodianContextRequest {
                active_context: None, // TODO(#2748) not used now
                new_context: Some(CustodianContext {
                    custodian_nodes: custodian_setup_msgs,
                    context_id: Some((*request_id).into()),
                    previous_context_id: None, // TODO(#2748) not used now
                    threshold,
                }),
            },
            mnemonics,
        ))
    }
}

fn custodian_setup_msgs(
    rng: &mut AesRng,
    amount_custodians: usize,
) -> anyhow::Result<(Vec<CustodianSetupMessage>, Vec<String>)> {
    let mut setup_msgs = Vec::new();
    let mut mnemonics = Vec::new();
    for cur_idx in 1..=amount_custodians {
        let role = Role::indexed_from_one(cur_idx);
        let mnemonic = seed_phrase_from_rng(rng).expect("Failed to generate seed phrase");
        let custodian: Custodian = custodian_from_seed_phrase(&mnemonic, role)?;
        let setup_msg = custodian.generate_setup_message(rng, format!("Custodian-{cur_idx}"))?;
        setup_msgs.push(setup_msg.try_into()?);
        mnemonics.push(mnemonic);
    }
    Ok((setup_msgs, mnemonics))
}
