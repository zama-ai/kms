use aes_prng::AesRng;
use tonic::async_trait;

use crate::{
    algebra::structure_traits::{ErrorCorrect, Ring},
    execution::{
        runtime::session::BaseSessionHandles,
        sharing::open::{OpeningKind, RobustOpen, SecureRobustOpen},
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
}
