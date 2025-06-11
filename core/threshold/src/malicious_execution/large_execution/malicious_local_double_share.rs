use crate::{
    algebra::structure_traits::{Derive, ErrorCorrect, Invert, Ring, RingEmbed},
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::broadcast::Broadcast,
        large_execution::{
            coinflip::Coinflip,
            local_double_share::{
                format_output, send_receive_pads_double, verify_sharing, DoubleShares,
                LocalDoubleShare, LOCAL_DOUBLE_MAX_ITER,
            },
            share_dispute::ShareDispute,
        },
        runtime::{party::Role, session::LargeSessionHandles},
    },
    tests::helper::tests_and_benches::roles_from_idxs,
    ProtocolDescription,
};
use async_trait::async_trait;
use rand::{CryptoRng, Rng};
use std::collections::HashMap;

/// Lie in broadcast as sender
#[derive(Clone, Default)]
pub struct MaliciousSenderLocalDoubleShare<C: Coinflip, S: ShareDispute, BCast: Broadcast> {
    coinflip: C,
    share_dispute: S,
    broadcast: BCast,
    roles_to_lie_to: Vec<Role>,
}

impl<C: Coinflip, S: ShareDispute, BCast: Broadcast> ProtocolDescription
    for MaliciousSenderLocalDoubleShare<C, S, BCast>
{
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!(
            "{}-MaliciousSenderLocalDoubleShare:\n{}\n{}\n{}",
            indent,
            C::protocol_desc(depth + 1),
            S::protocol_desc(depth + 1),
            BCast::protocol_desc(depth + 1)
        )
    }
}

impl<C: Coinflip, S: ShareDispute, BCast: Broadcast> MaliciousSenderLocalDoubleShare<C, S, BCast> {
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

/// Lie in broadcast as receiver
#[derive(Clone, Default)]
pub struct MaliciousReceiverLocalDoubleShare<C: Coinflip, S: ShareDispute, BCast: Broadcast> {
    coinflip: C,
    share_dispute: S,
    broadcast: BCast,
    roles_to_lie_to: Vec<Role>,
}

impl<C: Coinflip, S: ShareDispute, BCast: Broadcast> ProtocolDescription
    for MaliciousReceiverLocalDoubleShare<C, S, BCast>
{
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!(
            "{}-MaliciousReceiverLocalDoubleShare:\n{}\n{}\n{}",
            indent,
            C::protocol_desc(depth + 1),
            S::protocol_desc(depth + 1),
            BCast::protocol_desc(depth + 1)
        )
    }
}

impl<C: Coinflip, S: ShareDispute, BCast: Broadcast>
    MaliciousReceiverLocalDoubleShare<C, S, BCast>
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
impl<C: Coinflip, S: ShareDispute, BCast: Broadcast> LocalDoubleShare
    for MaliciousSenderLocalDoubleShare<C, S, BCast>
{
    async fn execute<
        Z: Ring + RingEmbed + Derive + ErrorCorrect + Invert,
        R: Rng + CryptoRng,
        L: LargeSessionHandles<R>,
    >(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<HashMap<Role, DoubleShares<Z>>> {
        //Keeps executing til verification passes
        for _ in 0..LOCAL_DOUBLE_MAX_ITER {
            let mut shared_secrets_double;
            let mut x;
            let mut shared_pads;

            // The following loop is guaranteed to terminate.
            // We we will leave it once the corrupt set does not change.
            // This happens right away on the happy path or worst case after all parties are in there and no new parties can be added.
            loop {
                let corrupt_start = session.corrupt_roles().clone();

                //ShareDispute will fill shares from disputed parties with 0s
                shared_secrets_double = self.share_dispute.execute_double(session, secrets).await?;

                shared_pads =
                    send_receive_pads_double::<Z, R, L, S>(session, &self.share_dispute).await?;

                x = self.coinflip.execute(session).await?;

                // if the corrupt roles have not changed, we can exit the loop and move on, otherwise start from the top
                if *session.corrupt_roles() == corrupt_start {
                    break;
                }
            }

            //Pretend I sent other shares to party in roles_to_lie_to
            //Same deviation fro both degree t and 2t
            for role in self.roles_to_lie_to.iter() {
                let sent_shares_t = shared_secrets_double
                    .output_t
                    .shares_own_secret
                    .get_mut(role)
                    .unwrap();

                let sent_shares_2t = shared_secrets_double
                    .output_2t
                    .shares_own_secret
                    .get_mut(role)
                    .unwrap();

                for (share_t, share_2t) in sent_shares_t.iter_mut().zip(sent_shares_2t.iter_mut()) {
                    *share_t += Z::ONE;
                    *share_2t += Z::ONE;
                }
            }

            if verify_sharing(
                session,
                &mut shared_secrets_double,
                &shared_pads,
                &x,
                secrets.len(),
                &self.broadcast,
            )
            .await?
            {
                return format_output(shared_secrets_double);
            }
        }
        Err(anyhow_error_and_log(
                format!(
                    "Failed to verify sharing after {LOCAL_DOUBLE_MAX_ITER} iterations for `MaliciousSenderLocalDoubleShare`",
                )
        ))
    }
}

#[async_trait]
impl<C: Coinflip, S: ShareDispute, BCast: Broadcast> LocalDoubleShare
    for MaliciousReceiverLocalDoubleShare<C, S, BCast>
{
    async fn execute<
        Z: Ring + RingEmbed + Derive + ErrorCorrect + Invert,
        R: Rng + CryptoRng,
        L: LargeSessionHandles<R>,
    >(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<HashMap<Role, DoubleShares<Z>>> {
        let mut shared_secrets_double;
        let mut x;
        let mut shared_pads;

        //Keeps executing til verification passes
        for _ in 0..LOCAL_DOUBLE_MAX_ITER {
            loop {
                let corrupt_start = session.corrupt_roles().clone();

                //ShareDispute will fill shares from disputed parties with 0s
                shared_secrets_double = self.share_dispute.execute_double(session, secrets).await?;

                shared_pads =
                    send_receive_pads_double::<Z, R, L, S>(session, &self.share_dispute).await?;

                x = self.coinflip.execute(session).await?;

                // if the corrupt roles have not changed, we can exit the loop and move on, otherwise start from the top
                if *session.corrupt_roles() == corrupt_start {
                    break;
                }
            }
            //Pretend I received other shares from party in roles_to_lie_to
            //Same deviation fro both degree t and 2t
            for role in self.roles_to_lie_to.iter() {
                let sent_shares_t = shared_secrets_double
                    .output_t
                    .all_shares
                    .get_mut(role)
                    .unwrap();

                let sent_shares_2t = shared_secrets_double
                    .output_2t
                    .all_shares
                    .get_mut(role)
                    .unwrap();

                for (share_t, share_2t) in sent_shares_t.iter_mut().zip(sent_shares_2t.iter_mut()) {
                    *share_t += Z::ONE;
                    *share_2t += Z::ONE;
                }
            }

            if verify_sharing(
                session,
                &mut shared_secrets_double,
                &shared_pads,
                &x,
                secrets.len(),
                &self.broadcast,
            )
            .await?
            {
                return format_output(shared_secrets_double);
            }
        }
        Err(anyhow_error_and_log(
                format!(
                    "Failed to verify sharing after {LOCAL_DOUBLE_MAX_ITER} iterations for `MaliciousReceiverLocalDoubleShare`",
            )
        ))
    }
}
