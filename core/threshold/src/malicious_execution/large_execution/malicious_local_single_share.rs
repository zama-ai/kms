use crate::{
    algebra::structure_traits::{Derive, ErrorCorrect, Invert},
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::broadcast::Broadcast,
        large_execution::{
            coinflip::Coinflip,
            local_single_share::{
                send_receive_pads, verify_sharing, LocalSingleShare, LOCAL_SINGLE_MAX_ITER,
            },
            share_dispute::ShareDispute,
        },
        runtime::{party::Role, session::LargeSessionHandles},
    },
    tests::helper::tests_and_benches::roles_from_idxs,
    ProtocolDescription,
};
use async_trait::async_trait;
use itertools::Itertools;
use std::collections::HashMap;

/// Lie in broadcast as sender
#[derive(Clone, Default)]
pub struct MaliciousSenderLocalSingleShare<C: Coinflip, S: ShareDispute, BCast: Broadcast> {
    coinflip: C,
    share_dispute: S,
    broadcast: BCast,
    roles_to_lie_to: Vec<Role>,
}

impl<C: Coinflip, S: ShareDispute, BCast: Broadcast> ProtocolDescription
    for MaliciousSenderLocalSingleShare<C, S, BCast>
{
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!(
            "{}-MaliciousSenderLocalSingleShare:\n{}\n{}\n{}",
            indent,
            C::protocol_desc(depth + 1),
            S::protocol_desc(depth + 1),
            BCast::protocol_desc(depth + 1)
        )
    }
}

impl<C: Coinflip, S: ShareDispute, BCast: Broadcast> MaliciousSenderLocalSingleShare<C, S, BCast> {
    pub fn new(
        coinflip_strategy: C,
        share_dispute_strategy: S,
        broadcast_strategy: BCast,
        roles_to_lie_to: &[usize],
    ) -> Self {
        Self {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
            broadcast: broadcast_strategy,
            roles_to_lie_to: roles_from_idxs(roles_to_lie_to),
        }
    }
}

#[async_trait]
impl<C: Coinflip, S: ShareDispute, BCast: Broadcast> LocalSingleShare
    for MaliciousSenderLocalSingleShare<C, S, BCast>
{
    async fn execute<Z: Derive + Invert + ErrorCorrect, L: LargeSessionHandles>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<HashMap<Role, Vec<Z>>> {
        //Keeps executing til verification passes
        for _ in 0..LOCAL_SINGLE_MAX_ITER {
            let mut shared_secrets;
            let mut x;
            let mut shared_pads;

            // The following loop is guaranteed to terminate.
            // We we will leave it once the corrupt set does not change.
            // This happens right away on the happy path or worst case after all parties are in there and no new parties can be added.
            loop {
                let corrupt_start = session.corrupt_roles().clone();
                //ShareDispute will fill shares from disputed parties with 0s
                shared_secrets = self.share_dispute.execute(session, secrets).await?;

                shared_pads = send_receive_pads::<Z, L, S>(session, &self.share_dispute).await?;

                x = self.coinflip.execute(session).await?;

                // if the corrupt roles have not changed, we can exit the loop and move on, otherwise start from the top
                if *session.corrupt_roles() == corrupt_start {
                    break;
                }
            }

            //Pretend I sent other shares to party in roles_to_lie_to
            for (sent_role, sent_shares) in shared_secrets.shares_own_secret.iter_mut() {
                if self.roles_to_lie_to.contains(sent_role) {
                    let modified_sent_shares = sent_shares
                        .iter()
                        .map(|share| *share + Z::ONE)
                        .collect_vec();
                    *sent_shares = modified_sent_shares;
                }
            }
            if verify_sharing(
                session,
                &mut shared_secrets,
                &shared_pads,
                &x,
                secrets.len(),
                &self.broadcast,
            )
            .await?
            {
                return Ok(shared_secrets.all_shares);
            }
        }
        Err(anyhow_error_and_log(
            format!(
                "Failed to verify sharing after {LOCAL_SINGLE_MAX_ITER} iterations for `MaliciousSenderLocalSingleShare`"
            )
        ))
    }
}

/// Lie in broadcast as receiver
#[derive(Clone, Default)]
pub struct MaliciousReceiverLocalSingleShare<C: Coinflip, S: ShareDispute, BCast: Broadcast> {
    coinflip: C,
    share_dispute: S,
    broadcast: BCast,
    roles_to_lie_to: Vec<Role>,
}

impl<C: Coinflip, S: ShareDispute, BCast: Broadcast> ProtocolDescription
    for MaliciousReceiverLocalSingleShare<C, S, BCast>
{
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!(
            "{}-MaliciousReceiverLocalSingleShare:\n{}\n{}\n{}",
            indent,
            C::protocol_desc(depth + 1),
            S::protocol_desc(depth + 1),
            BCast::protocol_desc(depth + 1)
        )
    }
}

impl<C: Coinflip, S: ShareDispute, BCast: Broadcast>
    MaliciousReceiverLocalSingleShare<C, S, BCast>
{
    pub fn new(
        coinflip_strategy: C,
        share_dispute_strategy: S,
        broadcast_strategy: BCast,
        roles_to_lie_to: &[usize],
    ) -> Self {
        Self {
            coinflip: coinflip_strategy,
            share_dispute: share_dispute_strategy,
            broadcast: broadcast_strategy,
            roles_to_lie_to: roles_from_idxs(roles_to_lie_to),
        }
    }
}

#[async_trait]
impl<C: Coinflip, S: ShareDispute, BCast: Broadcast> LocalSingleShare
    for MaliciousReceiverLocalSingleShare<C, S, BCast>
{
    async fn execute<Z: Derive + ErrorCorrect + Invert, L: LargeSessionHandles>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<HashMap<Role, Vec<Z>>> {
        for _ in 0..LOCAL_SINGLE_MAX_ITER {
            let mut shared_secrets;
            let mut x;
            let mut shared_pads;

            // The following loop is guaranteed to terminate.
            // We we will leave it once the corrupt set does not change.
            // This happens right away on the happy path or worst case after all parties are in there and no new parties can be added.
            loop {
                let corrupt_start = session.corrupt_roles().clone();

                //ShareDispute will fill shares from disputed parties with 0s
                shared_secrets = self.share_dispute.execute(session, secrets).await?;

                shared_pads = send_receive_pads::<Z, L, S>(session, &self.share_dispute).await?;

                x = self.coinflip.execute(session).await?;

                // if the corrupt roles have not changed, we can exit the loop and move on, otherwise start from the top
                if *session.corrupt_roles() == corrupt_start {
                    break;
                }
            }

            //Pretend I received other shares from party in roles_to_lie_to
            for (rcv_role, rcv_shares) in shared_secrets.all_shares.iter_mut() {
                if self.roles_to_lie_to.contains(rcv_role) {
                    let modified_rcv_shares =
                        rcv_shares.iter().map(|share| *share + Z::ONE).collect_vec();
                    *rcv_shares = modified_rcv_shares;
                }
            }
            if verify_sharing(
                session,
                &mut shared_secrets,
                &shared_pads,
                &x,
                secrets.len(),
                &self.broadcast,
            )
            .await?
            {
                return Ok(shared_secrets.all_shares);
            }
        }
        Err(anyhow_error_and_log(
                format!(
                    "Failed to verify sharing after {LOCAL_SINGLE_MAX_ITER} iterations for `MaliciousReceiverLocalSingleShare`",
                )
        ))
    }
}
