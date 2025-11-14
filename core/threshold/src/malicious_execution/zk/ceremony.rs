cfg_if::cfg_if! {
    if #[cfg(test)] {
        use std::collections::HashSet;
        use itertools::Itertools;
        use tfhe_zk_pok::curve_api::bls12_446 as curve;
        use crate::{
            execution::{
                communication::broadcast::Broadcast,
                zk::{
                    ceremony::{
                        make_partial_proof_deterministic,
                        PartialProof,
                    }
                },
            },
            networking::value::BroadcastValue,
        };
    }
}

use crate::{
    algebra::structure_traits::Ring,
    execution::{
        runtime::sessions::base_session::BaseSessionHandles,
        zk::{
            ceremony::{Ceremony, FinalizedInternalPublicParameter, InternalPublicParameter},
            constants::ZK_DEFAULT_MAX_NUM_BITS,
        },
    },
};

#[derive(Clone, Default)]
pub struct InsecureCeremony {}

#[tonic::async_trait]
impl Ceremony for InsecureCeremony {
    async fn execute<Z: Ring, S: BaseSessionHandles>(
        &self,
        session: &mut S,
        witness_dim: usize,
        max_num_bits: Option<u32>,
    ) -> anyhow::Result<FinalizedInternalPublicParameter> {
        let max_num_bits = max_num_bits.unwrap_or(ZK_DEFAULT_MAX_NUM_BITS as u32) as usize;
        Ok(FinalizedInternalPublicParameter {
            inner: InternalPublicParameter::new_insecure(
                session.num_parties() as u64,
                max_num_bits,
                witness_dim,
            ),
            sid: session.session_id(),
        })
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct DroppingCeremony;

#[cfg(test)]
#[tonic::async_trait]
impl Ceremony for DroppingCeremony {
    async fn execute<Z: Ring, S: BaseSessionHandles>(
        &self,
        session: &mut S,
        _crs_size: usize,
        _max_num_bits: Option<u32>,
    ) -> anyhow::Result<FinalizedInternalPublicParameter> {
        // do nothing
        Ok(FinalizedInternalPublicParameter {
            inner: InternalPublicParameter::new(session.num_parties(), Some(1)),
            sid: session.session_id(),
        })
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct RushingCeremony<BCast: Broadcast> {
    pub(crate) broadcast: BCast,
}

#[cfg(test)]
#[tonic::async_trait]
impl<BCast: Broadcast + Default> Ceremony for RushingCeremony<BCast> {
    // this implements an adversary that rushes the protocol,
    // i.e., it starts before it is his turn to do run
    async fn execute<Z: Ring, S: BaseSessionHandles>(
        &self,
        session: &mut S,
        witness_dim: usize,
        _max_num_bits: Option<u32>,
    ) -> anyhow::Result<FinalizedInternalPublicParameter> {
        let mut all_roles_sorted = session.roles().iter().cloned().collect_vec();
        all_roles_sorted.sort();
        let my_role = session.my_role();

        let pp = InternalPublicParameter::new_insecure(0, 1, witness_dim);
        let sid = session.session_id();
        for (round, role) in all_roles_sorted.iter().enumerate() {
            let round = round as u64;
            let mut tau = curve::ZeroizeZp::ZERO;
            tau.rand_in_place(&mut session.rng());
            let mut r = curve::ZeroizeZp::ZERO;
            r.rand_in_place(&mut session.rng());
            let proof: PartialProof =
                make_partial_proof_deterministic(&pp, &tau, round + 1, &r, sid);
            let vi = BroadcastValue::PartialProof::<Z>(proof);
            if *role == my_role {
                let _ = self
                    .broadcast
                    .broadcast_w_corrupt_set_update(session, HashSet::from([my_role]), Some(vi))
                    .await?;
            } else {
                // the message sent by `my_role`, the adversary, should be ignored
                let _ = self
                    .broadcast
                    .broadcast_w_corrupt_set_update(
                        session,
                        HashSet::from([my_role, *role]),
                        Some(vi),
                    )
                    .await?;
            }
        }

        Ok(FinalizedInternalPublicParameter {
            inner: pp,
            sid: session.session_id(),
        })
    }
}
