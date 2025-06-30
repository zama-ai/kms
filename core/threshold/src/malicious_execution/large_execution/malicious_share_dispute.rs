use crate::{
    algebra::structure_traits::{Invert, Ring, RingEmbed},
    execution::{
        communication::p2p::send_to_honest_parties,
        large_execution::share_dispute::{
            compute_idx_dispute, send_and_receive_share_dispute_double,
            send_and_receive_share_dispute_single, share_secrets, ShareDispute, ShareDisputeOutput,
            ShareDisputeOutputDouble,
        },
        runtime::{party::Role, session::LargeSessionHandles},
    },
    networking::value::NetworkValue,
    tests::helper::tests_and_benches::roles_from_idxs,
    ProtocolDescription,
};
use async_trait::async_trait;
use itertools::Itertools;
use std::collections::HashMap;

///Dropout strategy
#[derive(Default, Clone)]
pub struct DroppingShareDispute {}

impl ProtocolDescription for DroppingShareDispute {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!("{indent}-DroppingShareDispute")
    }
}

#[async_trait]
impl ShareDispute for DroppingShareDispute {
    async fn execute<Z: Ring, L: LargeSessionHandles>(
        &self,
        _session: &mut L,
        _secrets: &[Z],
    ) -> anyhow::Result<ShareDisputeOutput<Z>> {
        Ok(ShareDisputeOutput::default())
    }

    async fn execute_double<Z: Ring, L: LargeSessionHandles>(
        &self,
        _session: &mut L,
        _secrets: &[Z],
    ) -> anyhow::Result<ShareDisputeOutputDouble<Z>> {
        Ok(ShareDisputeOutputDouble::default())
    }
}

///Send an incorrect amount
#[derive(Default, Clone)]
pub struct WrongShareDisputeRecons {}

impl ProtocolDescription for WrongShareDisputeRecons {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!("{indent}-WrongShareDisputeRecons")
    }
}

#[async_trait]
impl ShareDispute for WrongShareDisputeRecons {
    async fn execute<Z: Ring, L: LargeSessionHandles>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<ShareDisputeOutput<Z>> {
        //Sample random not enough shares
        let vec_polypoints: Vec<Vec<Z>> = (0..secrets.len() - 1)
            .map(|_secret_idx| {
                (0_usize..session.num_parties())
                    .map(|_party_idx| Z::sample(session.rng()))
                    .collect::<Vec<Z>>()
            })
            .collect_vec();

        //Map each parties' role with their shares (one share per secret)
        //Except its not of correct type, and we are sending one too few shares per party
        let mut polypoints_map: HashMap<Role, NetworkValue<Z>> = HashMap::new();
        for polypoints in vec_polypoints.into_iter() {
            for (role_id, polypoint) in polypoints.into_iter().enumerate() {
                let curr_role = Role::indexed_from_zero(role_id);
                match polypoints_map.get_mut(&curr_role) {
                    Some(NetworkValue::VecRingValue(v)) => v.push(polypoint),
                    None => {
                        let mut new_party_vec = Vec::with_capacity(secrets.len());
                        new_party_vec.push(polypoint);
                        polypoints_map.insert(curr_role, NetworkValue::VecRingValue(new_party_vec));
                    }
                    _ => {}
                }
            }
        }
        send_to_honest_parties(&polypoints_map, session)
            .await
            .unwrap();
        Ok(ShareDisputeOutput::default())
    }

    async fn execute_double<Z: Ring, L: LargeSessionHandles>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<ShareDisputeOutputDouble<Z>> {
        //Sample random and not enough shares
        let vec_polypoints: Vec<Vec<Z>> = (0..secrets.len() - 1)
            .map(|_secret_idx| {
                (0_usize..session.num_parties())
                    .map(|_party_idx| Z::sample(session.rng()))
                    .collect::<Vec<Z>>()
            })
            .collect_vec();

        //Map each parties' role with their shares (one share per secret)
        //Except its not of correct type, and we are sending one too few shares per party
        let mut polypoints_map: HashMap<Role, NetworkValue<Z>> = HashMap::new();
        for polypoints in vec_polypoints.into_iter() {
            for (role_id, polypoint) in polypoints.into_iter().enumerate() {
                let curr_role = Role::indexed_from_zero(role_id);
                match polypoints_map.get_mut(&curr_role) {
                    Some(NetworkValue::VecPairRingValue(v)) => v.push((polypoint, polypoint)),
                    None => {
                        let mut new_party_vec = Vec::with_capacity(secrets.len());
                        new_party_vec.push((polypoint, polypoint));
                        polypoints_map
                            .insert(curr_role, NetworkValue::VecPairRingValue(new_party_vec));
                    }
                    _ => {}
                }
            }
        }
        send_to_honest_parties(&polypoints_map, session)
            .await
            .unwrap();
        Ok(ShareDisputeOutputDouble::default())
    }
}

///Strategy of a malicious party that just sends BS (but correct amount of correct type)
/// Not really used to test ShareDispute itself, but rather higher level protocols
#[derive(Default, Clone)]
pub struct MaliciousShareDisputeRecons {
    roles_to_lie_to: Vec<Role>,
}

impl ProtocolDescription for MaliciousShareDisputeRecons {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!("{indent}-MaliciousShareDisputeRecons")
    }
}

impl MaliciousShareDisputeRecons {
    pub fn new(roles_from_zero: &[usize]) -> Self {
        Self {
            roles_to_lie_to: roles_from_idxs(roles_from_zero),
        }
    }
}

#[async_trait]
impl ShareDispute for MaliciousShareDisputeRecons {
    async fn execute_double<Z: Ring + RingEmbed + Invert, L: LargeSessionHandles>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<ShareDisputeOutputDouble<Z>> {
        let num_parties = session.num_parties();
        let degree_t = session.threshold() as usize;
        let degree_2t = 2 * degree_t;

        //Get the IDs of all parties I'm in dispute with (ignoring the fact that some might or might not be in the Corrupt set)
        let dispute_ids = compute_idx_dispute(session)?;

        //Sample one random polynomial of correct degree per secret
        //and evaluate it at the parties' points
        let vec_polypoints_t: Vec<Vec<Z>> =
            share_secrets(session.rng(), secrets, &dispute_ids, num_parties, degree_t)?;
        let vec_polypoints_2t: Vec<Vec<Z>> =
            share_secrets(session.rng(), secrets, &dispute_ids, num_parties, degree_2t)?;

        //Map each parties' role with their pairs of shares (one share of deg t and one of deg 2t per secret)
        let mut polypoints_map: HashMap<Role, NetworkValue<Z>> = HashMap::new();
        for (mut polypoints_t, mut polypoints_2t) in vec_polypoints_t
            .into_iter()
            .zip_eq(vec_polypoints_2t.into_iter())
        {
            for (role_id, (polypoint_t, polypoint_2t)) in polypoints_t
                .iter_mut()
                .zip_eq(polypoints_2t.iter_mut())
                .enumerate()
            {
                let curr_role = Role::indexed_from_zero(role_id);
                //Cheat if we should
                if self.roles_to_lie_to.contains(&curr_role) {
                    let cheating_poly = Z::sample(session.rng());
                    *polypoint_t += cheating_poly;
                    *polypoint_2t += cheating_poly;
                }
                match polypoints_map.get_mut(&curr_role) {
                    Some(NetworkValue::VecPairRingValue(v)) => {
                        v.push((*polypoint_t, *polypoint_2t))
                    }
                    None => {
                        let mut new_party_vec = Vec::with_capacity(secrets.len());
                        new_party_vec.push((*polypoint_t, *polypoint_2t));
                        polypoints_map
                            .insert(curr_role, NetworkValue::VecPairRingValue(new_party_vec));
                    }
                    _ => {}
                }
            }
        }

        send_and_receive_share_dispute_double(session, polypoints_map, secrets.len()).await
    }

    async fn execute<Z: Ring + RingEmbed + Invert, L: LargeSessionHandles>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<ShareDisputeOutput<Z>> {
        let num_parties = session.num_parties();
        let degree = session.threshold() as usize;
        //Get the IDs of all parties I'm in dispute with (ignoring the fact that some might or might not be in the Corrupt set)
        let dispute_ids: Vec<usize> = compute_idx_dispute(session)?;

        //Sample one random polynomial of correct degree per secret
        //and evaluate it at the parties' points
        let mut vec_polypoints: Vec<Vec<Z>> =
            share_secrets(session.rng(), secrets, &dispute_ids, num_parties, degree)?;

        //Map each parties' role with their shares (one share per secret)
        let mut polypoints_map: HashMap<Role, NetworkValue<Z>> = HashMap::new();
        for polypoints in vec_polypoints.iter_mut() {
            for (role_id, polypoint) in polypoints.iter_mut().enumerate() {
                let curr_role = Role::indexed_from_zero(role_id);
                if self.roles_to_lie_to.contains(&curr_role) {
                    let cheating_poly = Z::sample(session.rng());
                    *polypoint += cheating_poly;
                }
                match polypoints_map.get_mut(&curr_role) {
                    Some(NetworkValue::VecRingValue(v)) => v.push(*polypoint),
                    None => {
                        let mut new_party_vec = Vec::with_capacity(secrets.len());
                        new_party_vec.push(*polypoint);
                        polypoints_map.insert(curr_role, NetworkValue::VecRingValue(new_party_vec));
                    }
                    _ => {}
                }
            }
        }
        send_and_receive_share_dispute_single(session, polypoints_map, secrets.len()).await
    }
}
