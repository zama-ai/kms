use cosmwasm_std::{Event, Response, StdError, StdResult, Storage};
use cw2::{ensure_from_older_version, get_contract_version};
use events::kms::MigrationEvent;

/// Trait for handling contract migrations
///
/// Note: we cannot use sylvia's `Interface` because it currently does not support migration entrypoint
/// Doc on interfaces : https://cosmwasm.github.io/sylvia-book/basics/reusability.html
pub trait Migration {
    /// Custom migration logic specific to each contract's state
    ///
    /// This step might be optional. Thanks to versioning, updating the state might never be needed
    #[allow(unused_variables)]
    fn migrate_state(&self, storage: &mut dyn Storage) -> StdResult<()> {
        // Since there no real migration logic for now, we do nothing
        Ok(())
    }

    /// Core migration logic shared across contracts
    fn apply_migration(&self, storage: &mut dyn Storage) -> StdResult<Response> {
        let contract_info = get_contract_version(storage)
            .map_err(|_| StdError::generic_err("Contract version info not found"))?;

        // Check that the given storage (representing the old contract's storage) is compatible with
        // the new version of the ASC by :
        // - checking that the new contract name is the same
        // - checking that the new contract version is more recent than the current version
        // If both conditions are met, the storage is updated with the new contract version
        let original_version =
            ensure_from_older_version(storage, &contract_info.contract, &contract_info.version)
                .map_err(|e| {
                    StdError::generic_err(format!(
                        "Migration failed while checking version compatibility: {}",
                        e
                    ))
                })?;

        // Perform contract-specific state migrations
        self.migrate_state(storage)?;

        // Create migration event
        let mut migration_event =
            MigrationEvent::new(original_version.to_string(), contract_info.version);

        // Since there no real migration logic for now, we set it to successful
        migration_event.set_success();

        // Return the response with the migration event
        let response = Response::new().add_event(Into::<Event>::into(migration_event));
        Ok(response)
    }
}
