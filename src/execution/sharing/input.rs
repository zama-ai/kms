use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::runtime::{
        party::Role,
        session::{BaseSession, BaseSessionHandles, ParameterHandles},
    },
    networking::value::NetworkValue,
};
use rand::{CryptoRng, Rng};
use std::sync::Arc;
use tokio::{task::JoinSet, time::timeout_at};

use super::shamir::{ShamirRing, ShamirSharing};

pub async fn robust_input<Z: ShamirRing, R: Rng + CryptoRng>(
    session: &mut BaseSession,
    value: &Option<Z>,
    role: &Role,
    input_party_id: usize,
) -> anyhow::Result<Z> {
    session.network().increase_round_counter().await?;
    if role.one_based() == input_party_id {
        let threshold = session.threshold();
        let si = {
            match value {
                Some(v) => *v,
                None => {
                    return Err(anyhow_error_and_log(
                        "Expected Some(v) as an input argument for the input party, got None"
                            .to_string(),
                    ))
                }
            }
        };
        let num_parties = session.amount_of_parties();

        let shamir_sharings =
            ShamirSharing::share(session.rng(), si, num_parties, threshold as usize)?;
        let roles: Vec<_> = shamir_sharings
            .shares
            .iter()
            .map(|share| share.owner())
            .collect();
        let mut set = JoinSet::new();
        for (indexed_share, to_send_role) in shamir_sharings.shares.iter().zip(roles).skip(1) {
            let receiver = session.identity_from(&to_send_role)?;

            let networking = Arc::clone(session.network());
            let session_id = session.session_id();
            let share = indexed_share.value();
            set.spawn(async move {
                let _ = networking
                    .send(
                        NetworkValue::RingValue(share).to_network(),
                        &receiver,
                        &session_id,
                    )
                    .await;
            });
        }
        while (set.join_next().await).is_some() {}
        Ok(shamir_sharings.shares[0].value())
    } else {
        let sender = session.identity_from(&Role::indexed_by_one(input_party_id))?;

        let networking = Arc::clone(session.network());
        let session_id = session.session_id();
        let data = tokio::spawn(timeout_at(
            session.network().get_timeout_current_round()?,
            async move { networking.receive(&sender, &session_id).await },
        ))
        .await??;

        let data = match NetworkValue::from_network(data)? {
            NetworkValue::RingValue(rv) => rv,
            _ => Err(anyhow_error_and_log(
                "I have received sth different from a ring value!".to_string(),
            ))?,
        };

        Ok(data)
    }
}
