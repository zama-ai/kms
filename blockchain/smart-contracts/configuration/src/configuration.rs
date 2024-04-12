use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Response, StdResult};
use cw_storage_plus::Map;
use sylvia::types::{ExecCtx, InstantiateCtx, QueryCtx};
use sylvia::{contract, entry_points};

pub struct ConfigurationContract {
    pub(crate) config: Map<String, String>,
}

impl Default for ConfigurationContract {
    fn default() -> Self {
        Self {
            config: Map::new("config"),
        }
    }
}

#[cw_serde]
pub struct ConfigurationResponse {
    pub value: String,
}

#[entry_points]
#[contract]
impl ConfigurationContract {
    pub fn new() -> Self {
        Self::default()
    }

    #[sv::msg(instantiate)]
    pub fn instantiate(
        &self,
        ctx: InstantiateCtx,
        key: String,
        value: String,
    ) -> StdResult<Response> {
        self.config.save(ctx.deps.storage, key, &value)?;
        Ok(Response::default())
    }

    #[sv::msg(query)]
    pub fn get(&self, ctx: QueryCtx, key: String) -> StdResult<ConfigurationResponse> {
        let value = self.config.load(ctx.deps.storage, key)?;
        Ok(ConfigurationResponse { value })
    }

    #[sv::msg(exec)]
    pub fn set(&self, ctx: ExecCtx, key: String, value: String) -> StdResult<Response> {
        self.config
            .update(ctx.deps.storage, key, |_| -> StdResult<String> {
                Ok(value)
            })?;
        Ok(Response::default())
    }
}

#[cfg(test)]
mod tests {
    use sylvia::cw_multi_test::IntoAddr as _;
    use sylvia::multitest::App;

    use crate::configuration::sv::mt::{CodeId, ConfigurationContractProxy as _};

    #[test]
    fn test_instantiate() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);

        let owner = "owner".into_addr();

        let contract = code_id
            .instantiate("name".to_owned(), "lodge".to_owned())
            .call(&owner)
            .unwrap();

        let value = contract.get("name".to_owned()).unwrap().value;
        assert_eq!(value, "lodge");
    }

    #[test]
    fn test_increment_explicit() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);

        let owner = "owner".into_addr();

        let contract = code_id
            .instantiate("name".to_owned(), "lodge".to_owned())
            .call(&owner)
            .unwrap();

        let value = contract.get("name".to_owned()).unwrap().value;
        assert_eq!(value, "lodge");

        contract
            .set("name".to_owned(), "juan".to_owned())
            .call(&owner)
            .unwrap();

        let value = contract.get("name".to_owned()).unwrap().value;
        assert_eq!(value, "juan");
    }

    #[test]
    fn test_add_multiple_entries() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);

        let owner = "owner".into_addr();

        let contract = code_id
            .instantiate("name".to_owned(), "lodge".to_owned())
            .call(&owner)
            .unwrap();

        let value = contract.get("name".to_owned()).unwrap().value;
        assert_eq!(value, "lodge");

        contract
            .set("name".to_owned(), "juan".to_owned())
            .call(&owner)
            .unwrap();

        let value = contract.get("name".to_owned()).unwrap().value;
        assert_eq!(value, "juan");

        contract
            .set("name".to_owned(), "jose".to_owned())
            .call(&owner)
            .unwrap();

        let value = contract.get("name".to_owned()).unwrap().value;
        assert_eq!(value, "jose");
    }
}
