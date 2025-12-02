use std::collections::HashMap;

use aes_prng::AesRng;
use tonic::async_trait;

use crate::{
    algebra::structure_traits::{ErrorCorrect, Ring},
    execution::{
        runtime::{
            party::TwoSetsRole,
            sessions::base_session::{BaseSessionHandles, GenericBaseSessionHandles},
        },
        sharing::open::{ExternalOpeningInfo, OpeningKind, RobustOpen, SecureRobustOpen},
    },
    ProtocolDescription,
};

/// Malicious implementation of the [`RobustOpen`] protocol
/// that simply does nothing
#[derive(Clone, Default)]
pub struct MaliciousRobustOpenDrop {}

impl ProtocolDescription for MaliciousRobustOpenDrop {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!("{indent}-MaliciousRobustOpenDrop")
    }
}

#[async_trait]
impl RobustOpen for MaliciousRobustOpenDrop {
    async fn execute<Z: ErrorCorrect, B: BaseSessionHandles>(
        &self,
        _session: &B,
        _shares: OpeningKind<Z>,
        _degree: usize,
    ) -> anyhow::Result<Option<Vec<Z>>> {
        Ok(None)
    }

    async fn robust_open_list_to_set<Z: ErrorCorrect, B: GenericBaseSessionHandles<TwoSetsRole>>(
        &self,
        _session: &B,
        _all_shares: Option<HashMap<TwoSetsRole, Vec<Z>>>,
        _degree: usize,
        _external_opening_info: Option<ExternalOpeningInfo>,
    ) -> anyhow::Result<Option<Vec<Z>>> {
        Ok(None)
    }
}

/// Malicious implementation of the [`RobustOpen`] protocol
/// where the party sends random to other parties during the opening
#[derive(Clone, Default)]
pub struct MaliciousRobustOpenLie {}

impl ProtocolDescription for MaliciousRobustOpenLie {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!("{indent}-MaliciousRobustOpenLie")
    }
}
#[async_trait]
impl RobustOpen for MaliciousRobustOpenLie {
    async fn execute<Z: Ring + ErrorCorrect, B: BaseSessionHandles>(
        &self,
        session: &B,
        shares: OpeningKind<Z>,
        degree: usize,
    ) -> anyhow::Result<Option<Vec<Z>>> {
        // Replace all the shares with random values
        let mut rng = AesRng::from_random_seed();
        let malicious_shares = match shares {
            OpeningKind::ToSome(hash_map) => OpeningKind::ToSome(
                hash_map
                    .into_iter()
                    .map(|(role, values)| {
                        (role, values.iter().map(|_| Z::sample(&mut rng)).collect())
                    })
                    .collect(),
            ),
            OpeningKind::ToAll(values) => {
                OpeningKind::ToAll(values.iter().map(|_| Z::sample(&mut rng)).collect())
            }
        };
        SecureRobustOpen::default()
            .execute(session, malicious_shares, degree)
            .await
    }

    async fn robust_open_list_to_set<Z: ErrorCorrect, B: GenericBaseSessionHandles<TwoSetsRole>>(
        &self,
        session: &B,
        all_shares: Option<HashMap<TwoSetsRole, Vec<Z>>>,
        degree: usize,
        external_opening_info: Option<ExternalOpeningInfo>,
    ) -> anyhow::Result<Option<Vec<Z>>> {
        // Replace all the shares with random values
        let mut rng = AesRng::from_random_seed();
        if let Some(all_shares) = all_shares {
            let malicious_shares: HashMap<TwoSetsRole, Vec<Z>> = all_shares
                .into_iter()
                .map(|(role, values)| (role, values.iter().map(|_| Z::sample(&mut rng)).collect()))
                .collect();
            SecureRobustOpen::default()
                .robust_open_list_to_set(
                    session,
                    Some(malicious_shares),
                    degree,
                    external_opening_info,
                )
                .await
        } else {
            SecureRobustOpen::default()
                .robust_open_list_to_set(session, None, degree, external_opening_info)
                .await
        }
    }
}
