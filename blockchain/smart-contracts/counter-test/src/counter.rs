use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Response, StdResult};
use cw_storage_plus::Item;
use sylvia::types::{ExecCtx, InstantiateCtx, QueryCtx};
use sylvia::{contract, entry_points};

pub struct CounterContract {
    pub(crate) count: Item<u32>,
}

impl Default for CounterContract {
    fn default() -> Self {
        Self {
            count: Item::new("count"),
        }
    }
}

#[cw_serde]
pub struct CountResponse {
    pub count: u32,
}

#[entry_points]
#[contract]
impl CounterContract {
    pub fn new() -> Self {
        Self::default()
    }

    #[sv::msg(instantiate)]
    pub fn instantiate(&self, ctx: InstantiateCtx, count: u32) -> StdResult<Response> {
        self.count.save(ctx.deps.storage, &count)?;
        Ok(Response::default())
    }

    #[sv::msg(query)]
    pub fn count(&self, ctx: QueryCtx) -> StdResult<CountResponse> {
        let count = self.count.load(ctx.deps.storage)?;
        Ok(CountResponse { count })
    }

    #[sv::msg(exec)]
    pub fn increment_count(&self, ctx: ExecCtx, count_param: Option<u32>) -> StdResult<Response> {
        self.count
            .update(ctx.deps.storage, |count| -> StdResult<u32> {
                Ok(count + count_param.unwrap_or(1))
            })?;
        Ok(Response::default())
    }
}

#[cfg(test)]
mod tests {
    use sylvia::cw_multi_test::IntoAddr as _;
    use sylvia::multitest::App;

    use crate::counter::sv::mt::{CodeId, CounterContractProxy as _};

    #[test]
    fn test_instantiate() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);

        let owner = "owner".into_addr();

        let contract = code_id.instantiate(42).call(&owner).unwrap();

        let count = contract.count().unwrap().count;
        assert_eq!(count, 42);
    }

    #[test]
    fn test_increment_explicit() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);

        let owner = "owner".into_addr();

        let contract = code_id.instantiate(42).call(&owner).unwrap();

        let count = contract.count().unwrap().count;
        assert_eq!(count, 42);

        contract.increment_count(Some(3)).call(&owner).unwrap();

        let count = contract.count().unwrap().count;
        assert_eq!(count, 45);
    }

    #[test]
    fn test_increment_implicit() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);

        let owner = "owner".into_addr();

        let contract = code_id.instantiate(42).call(&owner).unwrap();

        let count = contract.count().unwrap().count;
        assert_eq!(count, 42);

        contract.increment_count(None).call(&owner).unwrap();

        let count = contract.count().unwrap().count;
        assert_eq!(count, 43);
    }
}
