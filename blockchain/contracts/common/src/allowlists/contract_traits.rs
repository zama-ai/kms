use crate::allowlists::{state_traits::AllowlistsStateManager, AllowlistsManager, GetAdminType};
use cosmwasm_std::{Event, Response, StdError, StdResult};
use events::kms::{SenderAllowedEvent, UpdateAllowlistsEvent};
use serde::{de::DeserializeOwned, Serialize};
use sylvia::types::ExecCtx;
use tfhe_versionable::Unversionize;

/// Trait for checking that the sender's address is allowed to trigger a given operation type
///
/// Note that this trait is not implemented as an interface because its structure conflicts with
/// Sylvia (some traits are not recognized)
pub trait AllowlistsContractManager {
    type Allowlists: AllowlistsManager
        + DeserializeOwned
        + Unversionize
        + Clone
        + Serialize
        + std::fmt::Debug;

    // Note that we do not add a type alias for `AllowlistType` because associated types defaults
    // are currently unstable in Rust: https://github.com/rust-lang/rust/issues/29661

    fn storage(&self) -> &dyn AllowlistsStateManager<Allowlists = Self::Allowlists>;

    /// Check that the sender's address is allowed to trigger the given operation type.
    fn check_sender_is_allowed(
        &self,
        ctx: &ExecCtx,
        operation_type: <Self::Allowlists as AllowlistsManager>::AllowlistType,
        operation: &str,
    ) -> StdResult<SenderAllowedEvent> {
        self.storage()
            .check_address_is_allowed(
                ctx.deps.storage,
                ctx.info.sender.as_str(),
                operation_type.clone(),
            )
            .map_err(|e| StdError::generic_err(format!("Operation `{}`: {}", operation, e)))?;
        Ok(SenderAllowedEvent::new(
            operation.to_string(),
            ctx.info.sender.to_string(),
        ))
    }

    /// Allow an address to trigger the given operation type.
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    fn impl_add_allowlist(
        &self,
        ctx: ExecCtx,
        address: String,
        operation_type: <Self::Allowlists as AllowlistsManager>::AllowlistType,
    ) -> StdResult<Response> {
        let operation = "add_allowlist";

        self.check_sender_is_allowed(
            &ctx,
            <Self::Allowlists as AllowlistsManager>::AllowlistType::get_admin_type(),
            operation,
        )?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        self.storage().add_allowlist(
            ctx.deps.storage,
            &address,
            operation_type.clone(),
            ctx.deps.api,
        )?;

        let update_allowlists_event = UpdateAllowlistsEvent {
            new_addresses: vec![address.to_string()],
            operation: operation.to_string(),
            operation_type,
            sender: ctx.info.sender.to_string(),
        };

        let response = Response::new()
            .add_event(Into::<Event>::into(sender_allowed_event))
            .add_event(Into::<Event>::into(update_allowlists_event));
        Ok(response)
    }

    /// Forbid an address from triggering the given operation type.
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    fn impl_remove_allowlist(
        &self,
        ctx: ExecCtx,
        address: String,
        operation_type: <Self::Allowlists as AllowlistsManager>::AllowlistType,
    ) -> StdResult<Response> {
        let operation = "remove_allowlist";

        self.check_sender_is_allowed(
            &ctx,
            <Self::Allowlists as AllowlistsManager>::AllowlistType::get_admin_type(),
            operation,
        )?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        self.storage()
            .remove_allowlist(ctx.deps.storage, &address, operation_type.clone())?;

        let update_allowlists_event = UpdateAllowlistsEvent {
            new_addresses: vec![address.to_string()],
            operation: operation.to_string(),
            operation_type,
            sender: ctx.info.sender.to_string(),
        };

        let response = Response::new()
            .add_event(Into::<Event>::into(sender_allowed_event))
            .add_event(Into::<Event>::into(update_allowlists_event));
        Ok(response)
    }

    /// Replace all of the allowlists for the given operation type.
    ///
    /// This call is restricted to specific addresses defined at instantiation (`Allowlists`).
    fn impl_replace_allowlists(
        &self,
        ctx: ExecCtx,
        addresses: Vec<String>,
        operation_type: <Self::Allowlists as AllowlistsManager>::AllowlistType,
    ) -> StdResult<Response> {
        let operation = "replace_allowlists";

        self.check_sender_is_allowed(
            &ctx,
            <Self::Allowlists as AllowlistsManager>::AllowlistType::get_admin_type(),
            operation,
        )?;

        let sender_allowed_event =
            SenderAllowedEvent::new(operation.to_string(), ctx.info.sender.to_string());

        self.storage().replace_allowlists(
            ctx.deps.storage,
            addresses.clone(),
            operation_type.clone(),
            ctx.deps.api,
        )?;

        let update_allowlists_event = UpdateAllowlistsEvent {
            new_addresses: addresses,
            operation: operation.to_string(),
            operation_type,
            sender: ctx.info.sender.to_string(),
        };

        let response = Response::new()
            .add_event(Into::<Event>::into(sender_allowed_event))
            .add_event(Into::<Event>::into(update_allowlists_event));
        Ok(response)
    }
}
