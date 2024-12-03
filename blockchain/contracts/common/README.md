# Migration: Upgrade a contract's code

Migration allows to upgrade a contract's code without changing its address and state.
There are different strategies to do so and we chose to directly use CosmWasm's migration feature.
This is because it has the advantage of not having to implement a custom proxy contract ourselves while
being easy to use.

## Steps

Whenever a contract's code is updated of the address changes, the contract needs to be migrated using the following steps:

0. Go to the contract's directory (example: `asc/contract.rs`)
1. If code in `contract.rs` have been updated:
   1. Make sure no function have been removed
   2. If needed, update the `migrate` entrypoint with a new signature and or logic. Note that this entrypoint is generally only used to update the contract's state. In our case, that might not be necessary thanks to state versioning.
2. Compile the new contract to wasm (steps defined in the contract's readme)
3. Upload the new contract (steps defined in the contract's readme):

```
wasmd tx wasm store <contract_wasm_path>
```

4. Get the new contract's code ID:

```
`wasmd query tx --output json <new_contract_tx_hash> | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value'`
```

- `<new_contract_tx_hash>`: the transaction hash of the new contract. Take example from the instantiation step the contract's readme if needed.

5. **IMPORTANT:** Do not instantiate the contract ❌
6. Migrate the contract (additional arguments might be needed, see [wasm CLI doc](https://docs.cosmwasm.com/wasmd/getting-started/cli)):

```
wasmd tx wasm migrate <contract_address> <new_contract_code_id> <migration_args> --from <admin_address>
```

- `<contract_address>`: the (persistent) contract's address.
- `<new_contract_code_id>`: the new contract's code ID retrieved in step 4.
- `<migration_args>`: the contract's migration entrypoint arguments. Currently, there are none: `'{}'`.
- `<admin_address>`: the contract's current admin address allowed to migrate. See below for how to get ot change it.

## Admin management for migration

**IMPORTANT:** Migration can only be performed by the _admin_ of the contract, the `validator` account (initially).

Admin management is directly handled by an internal proxy contract from CosmWasm. It is possible to get or even change this admin. The admin is first set at instantiation, see the contract's readme for more details.

### Get the contract's current admin

```
wasmd query wasm contract <contract_address> --output json | jq -r '.contract_info.admin'
```

### Change the contract's admin

The following command can only be performed by the contract's current admin.

```
wasmd tx wasm set-contract-admin <contract_address> <new_admin_address>
```

- `<contract_address>`: the (persistent) contract's address.
- `<new_admin_address>`: the new admin address.

## Links

- [wasm CLI doc](https://docs.cosmwasm.com/wasmd/getting-started/cli)
- [wasm CLI source](https://github.com/CosmWasm/wasmd/blob/main/x/wasm/client/cli/new_tx.go)
- [wasmd example script](https://github.com/CosmWasm/wasmd/blob/main/scripts/contrib/local/02-contracts.sh#L81)
- [CosmWasm migration doc](https://book.cosmwasm.com/actor-model/contract-as-actor.html#migrations)
