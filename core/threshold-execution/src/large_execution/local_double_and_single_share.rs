//! Joint single + double local sharing.
//!
//! This protocol produces, in a *single* execution, the material for both a single sharing (a
//! batch of degree-t sharings) and a double sharing (a batch of paired degree-t / degree-2t
//! sharings). It does so by treating the single secrets as double secrets: `single_secrets ‖
//! double_secrets` are shared together through one [`LocalDoubleShare`], and afterwards each
//! party's shares are split back apart, keeping only the degree-t half for the single part.
//!
//! # Why (upside): rounds / latency
//!
//! Initialising the two sharings separately runs two full local-share protocols back-to-back,
//! i.e. two rounds of `ShareDispute + Coinflip + verify`. Sharing them jointly collapses that
//! into a single such round (one ShareDispute, one Coinflip, one verify broadcast). On the
//! critical path — a high-latency WAN where each round costs one network round-trip — this
//! roughly halves the offline-init latency and matches the round count the spec assumes. This
//! is the reason the protocol exists.
//!
//! # Cost (downsides): bandwidth and computation
//!
//! The saving is bought by over-sharing the single part:
//!
//! - **Bandwidth.** A genuine single sharing sends one degree-t share per secret per party. Here
//!   the single secrets ride the double machinery, so each also carries a degree-2t share on the
//!   wire (and through the verify broadcast). The single portion therefore transmits ~2x the data
//!   of a dedicated single sharing. The degree-2t half is discarded immediately after the split.
//! - **Computation.** For every single secret we additionally sample and evaluate a degree-2t
//!   sharing polynomial (in [`ShareDispute::execute_double`]) and compute/verify its degree-2t
//!   check values during verification — work that a dedicated single sharing never does.
//!
//! Both costs scale with the single batch size only; the double part is unchanged. Because the
//! goal is round/latency parity with the spec (not minimal bandwidth), this trade is deliberate:
//! we spend extra local computation and per-round bytes to remove a whole communication round.
//! Reusing [`LocalDoubleShare`] wholesale is also what lets every existing malicious
//! [`LocalDoubleShare`] test double and the dispute/verification handling apply here unchanged.
//!
//! A bandwidth/computation-minimal alternative would share the single part at degree-t only and
//! the double part at (t, 2t) within one combined message, but that requires a bespoke combined
//! ShareDispute wire format and a verify step generic over the two payload shapes.

use super::local_double_share::{DoubleShares, LocalDoubleShare, SecureLocalDoubleShare};
use crate::runtime::sessions::large_session::LargeSessionHandles;
use algebra::structure_traits::{Derive, ErrorCorrect, Invert};
use async_trait::async_trait;
use std::collections::HashMap;
use threshold_types::protocol::ProtocolDescription;
use threshold_types::role::Role;
use tracing::instrument;

pub type SecureLocalDoubleAndSingleShare = RealLocalDoubleAndSingleShare<SecureLocalDoubleShare>;

/// Output of a joint single+double local sharing.
///
/// `single` carries the degree-t shares for the single-sharing part (one entry per role, each
/// a vector of `l_single` shares), `double` the degree-(t, 2t) shares for the double-sharing
/// part (each a vector of `l_double` [`DoubleShares`]).
pub struct JointShares<Z> {
    pub single: HashMap<Role, Vec<Z>>,
    pub double: HashMap<Role, DoubleShares<Z>>,
}

#[async_trait]
pub trait LocalDoubleAndSingleShare: ProtocolDescription + Send + Sync + Clone {
    /// Jointly produce a single sharing of `single_secrets` and a double sharing of
    /// `double_secrets` in a *single* LocalDoubleShare execution (one ShareDispute round, one
    /// Coinflip, one verify broadcast), instead of running the two sharings back-to-back.
    ///
    /// Both secret sets are shared together as double sharings; the single part simply keeps
    /// its degree-t half and discards the degree-2t half. This trades a little bandwidth (the
    /// single secrets also travel as 2t shares) for collapsing the two inits into one, matching
    /// the spec's round count.
    async fn execute<Z: Derive + ErrorCorrect + Invert, L: LargeSessionHandles>(
        &self,
        session: &mut L,
        single_secrets: &[Z],
        double_secrets: &[Z],
    ) -> anyhow::Result<JointShares<Z>>;
}

/// Joint single+double local sharing built on top of an existing [`LocalDoubleShare`] strategy.
///
/// Reusing [`LocalDoubleShare`] means every malicious [`LocalDoubleShare`] test double plugs in
/// unchanged, and the single part inherits the double sharing's dispute/verification handling.
#[derive(Default, Clone)]
pub struct RealLocalDoubleAndSingleShare<S: LocalDoubleShare> {
    local_double_share: S,
}

impl<S: LocalDoubleShare> ProtocolDescription for RealLocalDoubleAndSingleShare<S> {
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!(
            "{}-RealLocalDoubleAndSingleShare:\n{}",
            indent,
            S::protocol_desc(depth + 1)
        )
    }
}

impl<S: LocalDoubleShare> RealLocalDoubleAndSingleShare<S> {
    pub fn new(local_double_share: S) -> Self {
        Self { local_double_share }
    }
}

#[async_trait]
impl<S: LocalDoubleShare> LocalDoubleAndSingleShare for RealLocalDoubleAndSingleShare<S> {
    #[instrument(name="LocalDoubleAndSingleShare",skip(self,session,single_secrets,double_secrets),fields(sid = ?session.session_id(),my_role=?session.my_role(),single_batch_size=?single_secrets.len(),double_batch_size=?double_secrets.len()))]
    async fn execute<Z: Derive + ErrorCorrect + Invert, L: LargeSessionHandles>(
        &self,
        session: &mut L,
        single_secrets: &[Z],
        double_secrets: &[Z],
    ) -> anyhow::Result<JointShares<Z>> {
        let l_single = single_secrets.len();

        // Share the single and double secrets together in one LocalDoubleShare, then split each
        // party's shares at `l_single` back into a single (degree-t only) and a double part.
        let all_secrets = [single_secrets, double_secrets].concat();
        let full = self
            .local_double_share
            .execute(session, &all_secrets)
            .await?;

        let mut single = HashMap::with_capacity(full.len());
        let mut double = HashMap::with_capacity(full.len());
        for (role, double_shares) in full {
            let DoubleShares {
                mut share_t,
                mut share_2t,
            } = double_shares;
            let double_share_t = share_t.split_off(l_single);
            let double_share_2t = share_2t.split_off(l_single);
            // The single part keeps only its degree-t half.
            single.insert(role, share_t);
            double.insert(
                role,
                DoubleShares {
                    share_t: double_share_t,
                    share_2t: double_share_2t,
                },
            );
        }

        Ok(JointShares { single, double })
    }
}
