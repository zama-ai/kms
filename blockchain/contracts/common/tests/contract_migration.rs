use cosmwasm_std::{Addr, Binary};
use cw_multi_test::{App as CwApp, Executor, IntoAddr as _};
use sylvia::multitest::App;

// Provide an "old" dummy versioned smart contract implementation
mod v0 {
    use cosmwasm_std::{Addr, Response, StdResult};
    use cw2::set_contract_version;
    use sylvia::types::{InstantiateCtx, QueryCtx};
    use sylvia::{contract, entry_points};

    use contracts_common::versioned_test_utils::v0::{MyStruct, VersionedStorage};

    // Info for migration
    const CONTRACT_NAME: &str = "my_contract_name";
    const CONTRACT_VERSION: &str = "1.0.0";

    #[derive(Default)]
    pub struct MyContract {
        pub storage: VersionedStorage,
    }

    #[entry_points]
    #[contract]
    impl MyContract {
        pub fn new() -> Self {
            Self::default()
        }

        // Entrypoint for instantiating the contract
        // It also sets the contract name and version in the storage
        #[sv::msg(instantiate)]
        pub fn instantiate(&self, ctx: InstantiateCtx) -> StdResult<Response> {
            set_contract_version(ctx.deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

            self.storage
                .my_versioned_item
                .save(ctx.deps.storage, &MyStruct::new("v0"))?;
            Ok(Response::default())
        }

        // Entrypoint for querying the contract
        #[sv::msg(query)]
        pub fn load_my_struct(&self, ctx: QueryCtx) -> StdResult<MyStruct> {
            self.storage.my_versioned_item.load(ctx.deps.storage)
        }

        // Get the contract's address
        #[sv::msg(query)]
        pub fn get_address(&self, ctx: QueryCtx) -> StdResult<Addr> {
            Ok(ctx.env.contract.address)
        }

        // Note that there is no entrypoint for migrating the contract since this is the first
        // version
    }
}

// Provide a "new" dummy versioned smart contract implementation with a migrate entrypoint
mod v1 {
    use cosmwasm_std::{Addr, Binary, Response, StdError, StdResult};
    use cw2::{ensure_from_older_version, get_contract_version, set_contract_version};
    use sylvia::types::{InstantiateCtx, MigrateCtx, QueryCtx};
    use sylvia::{contract, entry_points};

    use contracts_common::versioned_test_utils::v1::{MyStruct, VersionedStorage};

    // Info for migration
    const CONTRACT_NAME: &str = "my_contract_name";
    const CONTRACT_VERSION: &str = "2.0.0";

    #[derive(Default)]
    pub struct MyContract {
        pub storage: VersionedStorage,
    }

    #[entry_points]
    #[contract]
    impl MyContract {
        pub fn new() -> Self {
            Self::default()
        }

        // Entrypoint for instantiating the contract
        // It also sets the contract name and version in the storage
        // None: since we are going to migrate the old contract to this new code, this
        // instantiation entrypoint should not be called
        #[sv::msg(instantiate)]
        pub fn instantiate(&self, ctx: InstantiateCtx) -> StdResult<Response> {
            set_contract_version(ctx.deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

            self.storage
                .my_versioned_item
                .save(ctx.deps.storage, &MyStruct::new("v1"))?;
            Ok(Response::default())
        }

        // Entrypoint for querying the contract
        #[sv::msg(query)]
        pub fn load_my_struct(&self, ctx: QueryCtx) -> StdResult<MyStruct<u8>> {
            self.storage.my_versioned_item.load(ctx.deps.storage)
        }

        // Entrypoint for migrating the contract from old to new version
        // Use a `_test` parameter for testing purposes only
        // It also checks that the given storage (representing the old contract's storage) is
        // compatible with the new version
        #[allow(unused_variables)]
        #[sv::msg(migrate)]
        pub fn migrate(&self, ctx: MigrateCtx, _test: Binary) -> StdResult<Response> {
            let contract_info = get_contract_version(ctx.deps.storage)
                .map_err(|_| StdError::generic_err("Contract version info not found"))?;

            let _original_version = ensure_from_older_version(
                ctx.deps.storage,
                &contract_info.contract,
                &contract_info.version,
            )?;
            Ok(Response::default())
        }

        // Get the contract's address
        #[sv::msg(query)]
        pub fn get_address(&self, ctx: QueryCtx) -> StdResult<Addr> {
            Ok(ctx.env.contract.address)
        }
    }
}

#[test]
fn test_contract_migration() {
    use contracts_common::versioned_test_utils::v1::MyStruct as MyNewStruct;
    use v0::sv::mt::MyContractProxy;

    // Define the blockchain application simulator
    let cw_app = CwApp::default();
    let sylvia_app = App::new(cw_app);

    // Define the contract's owner
    let owner = "owner".into_addr();

    // Instantiate the old contract
    let old_code_id = v0::sv::mt::CodeId::store_code(&sylvia_app);
    let old_contract = old_code_id
        .instantiate()
        .with_admin(owner.as_str())
        .call(&owner)
        .unwrap();

    // Load the old struct. This requires `MyContractProxy` to be in scope
    let old_item = old_contract.load_my_struct().unwrap();
    assert_eq!(old_item.attribute_0, "v0");

    // Get the old contract's address and make sure it matches the address of CosmWasm's proxy contract
    let old_address = old_contract.get_address().unwrap();
    assert_eq!(old_address, old_contract.contract_addr);

    // Store the new code and get its code id
    // Note that the new contract must not be instantiated at any time
    let new_code_id = v1::sv::mt::CodeId::store_code(&sylvia_app);

    // Build the migrate message for the new code
    // There might be a way to automatically build this message (via the `Sylvia` framework)
    let migrate_msg = v1::sv::MigrateMsg {
        _test: Binary::default(),
    };

    // Define a fake owner for the contract
    let fake_owner = "fake_owner".into_addr();

    // Check that the migration fails when using the wrong owner as the sender. This is because
    // this fake owner has not been registered as an admin when instantiating the old contract.
    // Note that CosmWasm does provide a way to update admins for a contract
    sylvia_app
        .app_mut()
        .migrate_contract(
            fake_owner.clone(),
            old_contract.contract_addr.clone(),
            &migrate_msg,
            new_code_id.code_id(),
        )
        .unwrap_err();

    // Define a fake code id
    let fake_code_id = new_code_id.code_id() + 10;

    // Check that the migration fails when using a non-registered code id. This is because this
    // `fake_code_id` has not been stored in the blockchain app at any time
    sylvia_app
        .app_mut()
        .migrate_contract(
            fake_owner.clone(),
            old_contract.contract_addr.clone(),
            &migrate_msg,
            fake_code_id,
        )
        .unwrap_err();

    // Migrate the old contract to the new code using the underlying CosmWasm app
    // The `Sylvia` framework does provide a migrate feature but does not seem to fully support
    // it when testing it. More specifically, it does not allow migrate a contract to a new code
    // without having the old contract exposing a migrate entrypoint. Additionally, it will pass
    // the old contract's migrate message (after building it automatically) instead of the new one,
    // which does not make much sense. This is why we directly use the underlying CosmWasm app to
    // perform the migration
    // Note that this requires the `Executor` trait from `cw_multi_test` to be in scope
    sylvia_app
        .app_mut()
        .migrate_contract(
            owner.clone(),
            old_contract.contract_addr.clone(),
            &migrate_msg,
            new_code_id.code_id(),
        )
        .unwrap();

    // Build the new query message for the new contract
    // Similarly, there might be a way to automatically build this message (via the `Sylvia`
    // framework)
    let query_msg = v1::sv::QueryMsg::LoadMyStruct {};

    // Query the new contract to load the new struct
    // Similarly, the `Sylvia` framework does not support querying the new contract after
    // migration. Because the new contract is never really built, meaning we need to keep using
    // the old contract instance, which does not provide the right methods and/or signatures
    // (i.e. the ones of the new contract). This is why we directly use the underlying CosmWasm
    // app to query the new contract
    let new_item: MyNewStruct<u8> = sylvia_app
        .app()
        .wrap()
        .query_wasm_smart(&old_contract.contract_addr, &query_msg)
        .unwrap();

    // Test that the old struct has been loaded and updated to its new version
    assert_eq!(new_item.attribute_0, "v0");
    assert_eq!(new_item.attribute_1, 0);

    // Get the new contract's address and make sure it matches the old contract's one
    let query_msg = v1::sv::QueryMsg::GetAddress {};
    let new_address: Addr = sylvia_app
        .app()
        .wrap()
        .query_wasm_smart(&old_contract.contract_addr, &query_msg)
        .unwrap();

    assert_eq!(new_address, old_address);
}
