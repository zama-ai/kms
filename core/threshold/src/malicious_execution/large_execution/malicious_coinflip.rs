use tonic::async_trait;

use crate::{
    algebra::structure_traits::ErrorCorrect,
    execution::{
        large_execution::{coinflip::Coinflip, vss::Vss},
        runtime::sessions::large_session::LargeSessionHandles,
        sharing::open::RobustOpen,
    },
    ProtocolDescription,
};

///Performs the VSS and does nothing after that (returns its secret)
#[derive(Default, Clone)]
pub struct DroppingCoinflipAfterVss<V: Vss> {
    vss: V,
}

impl<V: Vss> DroppingCoinflipAfterVss<V> {
    pub fn new(vss_strategy: V) -> Self {
        Self { vss: vss_strategy }
    }
}

impl<V: Vss> ProtocolDescription for DroppingCoinflipAfterVss<V> {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!(
            "{}-DroppingCoinflipAfterVss:\n{}",
            indent,
            V::protocol_desc(depth + 1)
        )
    }
}

#[async_trait]
impl<V: Vss> Coinflip for DroppingCoinflipAfterVss<V> {
    async fn execute<Z: ErrorCorrect, L: LargeSessionHandles>(
        &self,
        session: &mut L,
    ) -> anyhow::Result<Z> {
        let my_secret = Z::sample(session.rng());

        let _ = self.vss.execute::<Z, L>(session, &my_secret).await?;

        Ok(my_secret)
    }
}

///Performs the coinflip, but does not send the correct shares for reconstruction
#[derive(Default, Clone)]
pub struct MaliciousCoinflipRecons<V: Vss, RO: RobustOpen> {
    vss: V,
    robust_open: RO,
}

impl<V: Vss, RO: RobustOpen> ProtocolDescription for MaliciousCoinflipRecons<V, RO> {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!(
            "{}-MaliciousCoinflipRecons:\n{}\n{}",
            indent,
            V::protocol_desc(depth + 1),
            RO::protocol_desc(depth + 1)
        )
    }
}

impl<V: Vss, RO: RobustOpen> MaliciousCoinflipRecons<V, RO> {
    pub fn new(vss_strategy: V, robust_open_strategy: RO) -> Self {
        Self {
            vss: vss_strategy,
            robust_open: robust_open_strategy,
        }
    }
}

#[async_trait]
impl<V: Vss, RO: RobustOpen> Coinflip for MaliciousCoinflipRecons<V, RO> {
    async fn execute<Z: ErrorCorrect, L: LargeSessionHandles>(
        &self,
        session: &mut L,
    ) -> anyhow::Result<Z> {
        let my_secret = Z::sample(session.rng());

        let shares_of_contributions = self.vss.execute::<Z, L>(session, &my_secret).await?;

        //Add an error to share_of_coins
        let mut share_of_coins = shares_of_contributions.into_iter().sum();
        share_of_coins += Z::sample(session.rng());

        let opening = self
            .robust_open
            .robust_open_to_all(session, share_of_coins, session.threshold() as usize)
            .await?;

        match opening {
            Some(v) => Ok(v),
            _ => Err(anyhow::anyhow!("Malicious error")),
        }
    }
}
