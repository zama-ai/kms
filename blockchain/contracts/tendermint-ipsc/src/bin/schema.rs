#[cfg(feature = "schema")]
fn main() {
    use cosmwasm_schema::write_api;
    use tendermint_ipsc::contract::sv::{ContractExecMsg, ContractQueryMsg, InstantiateMsg};

    write_api! {
        instantiate: InstantiateMsg,
        execute: ContractExecMsg,
        query: ContractQueryMsg,
    }

    #[cfg(feature = "mock")]
    use tendermint_ipsc::mock::sv::{
        ContractExecMsg as MockContractExecMsg, InstantiateMsg as MockInstantiateMsg,
    };

    #[cfg(feature = "mock")]
    write_api! {
        instantiate: MockInstantiateMsg,
        execute: MockContractExecMsg,
    }
}

#[cfg(not(feature = "schema"))]
fn main() {
    // You can perform alternative actions here or simply leave it empty if there's nothing to do.
    println!("The 'schema' feature is not enabled. No actions performed.");
}
