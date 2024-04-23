#[cfg(feature = "schema")]
fn main() {
    use asc::contract::sv::{ContractExecMsg, ContractQueryMsg, InstantiateMsg};
    use cosmwasm_schema::write_api;

    write_api! {
        instantiate: InstantiateMsg,
        execute: ContractExecMsg,
        query: ContractQueryMsg,
    }
}

#[cfg(not(feature = "schema"))]
fn main() {
    // You can perform alternative actions here or simply leave it empty if there's nothing to do.
    println!("The 'schema' feature is not enabled. No actions performed.");
}
