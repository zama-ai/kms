# ASC

The application smart contract which is the main entry-point of the KMS blockchain.


# Migration: Upgrade the ASC code

Migration allows to upgrade the ASC code without changing its address and state. 
There are different strategies to do so and we chose to directly use CosmWasm's migration feature.
This is because it has the advantage of not having to implement a custom proxy contract ourselves while
being easy to use.

## Steps
Whenever the ASC code is updated of the address changes, the ASC needs to be migrated using the following steps:

1. If code in [`contract.rs`](src/contract.rs) have been updated:
    1. Make sure no function have been removed
    2. If needed, update the `migrate` entrypoint with a new signature and or logic. Note that this entrypoint is generally only used to update the contract's state. In our case, that might not be necessary thanks to state versioning.
2. Compile the new contract to wasm (steps from [`ci.dockerfile`](../../contracts/operations/docker/ci.dockerfile))
3. Upload the new contract (full command in [`bootstrap_asc.sh`](../../scripts/bootstrap_asc.sh)): 
```
wasmd tx wasm store <asc_wasm_path>
```

4. Get the new contract's code ID:
```
`wasmd query tx --output json <new_asc_tx_hash> | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value'`
```
- `<new_asc_tx_hash>`: the transaction hash of the new ASC. Take example from the instantiation step in [`bootstrap_asc.sh`](../../scripts/bootstrap_asc.sh) if needed.
5. **IMPORTANT:** Do not instantiate the contract ❌
6. Migrate the contract (additional arguments might be needed, see [wasm CLI doc](https://docs.cosmwasm.com/wasmd/getting-started/cli)): 
```
wasmd tx wasm migrate <asc_contract_address> <new_asc_code_id> <migration_args> --from <admin_address>
```
- `<asc_contract_address>`: the (persistent) ASC contract address.
- `<new_asc_code_id>`: the new ASC code ID retrieved in step 4.
- `<migration_args>`: the contract's migration entrypoint arguments. Currently, there are none: `'{}'`. Take example from the instantiation step in [`bootstrap_asc.sh`](../../scripts/bootstrap_asc.sh) if needed.
- `<admin_address>`: the contract's current admin address. See below for how to get ot change it.

## Admin management for migration
**IMPORTANT:** Migration can only be performed by the _admin_ of the contract, the `validator` account (initially).

Admin management is directly handled by an internal proxy contract from CosmWasm. It is possible to get or even change this admin. At in instantiation, in [`bootstrap_asc.sh`](../../scripts/bootstrap_asc.sh), the admin is set to the `validator` account.

### Get the contract's current admin
```
wasmd query wasm contract <asc_contract_address> --output json | jq -r '.contract_info.admin'
```

### Change the contract's admin
The following command can only be performed by the contract's current admin.
```
wasmd tx wasm set-contract-admin <asc_contract_address> <new_admin_address>
```
- `<asc_contract_address>`: the (persistent) ASC contract address.
- `<new_admin_address>`: the new admin address.


## Links
- [wasm CLI doc](https://docs.cosmwasm.com/wasmd/getting-started/cli)
- [wasm CLI source](https://github.com/CosmWasm/wasmd/blob/main/x/wasm/client/cli/new_tx.go)
- [wasmd example script](https://github.com/CosmWasm/wasmd/blob/main/scripts/contrib/local/02-contracts.sh#L81)
- [CosmWasm migration doc](https://book.cosmwasm.com/actor-model/contract-as-actor.html#migrations)
