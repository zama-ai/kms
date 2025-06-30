use crate::execution::config::BatchParams;
use crate::execution::online::preprocessing::memory::InMemoryBasePreprocessing;
use crate::execution::online::preprocessing::{RandomPreprocessing, TriplePreprocessing};
use crate::execution::small_execution::offline::Preprocessing;
use crate::{
    algebra::structure_traits::{Derive, ErrorCorrect, Ring},
    execution::{
        large_execution::{
            double_sharing::DoubleSharing, offline::next_random_batch,
            single_sharing::SingleSharing,
        },
        online::triple::Triple,
        runtime::session::LargeSessionHandles,
        sharing::{open::RobustOpen, share::Share},
    },
    ProtocolDescription,
};
use itertools::Itertools;
use tonic::async_trait;

///Malicious strategy that introduces an error in the reconstruction of beaver
#[derive(Clone)]
pub struct CheatingLargePreprocessing<
    Z: Ring,
    S: SingleSharing<Z>,
    D: DoubleSharing<Z>,
    RO: RobustOpen,
> {
    single_sharing: S,
    double_sharing: D,
    robust_open: RO,
    ring_marker: std::marker::PhantomData<Z>,
}

impl<Z: Ring, S: SingleSharing<Z>, D: DoubleSharing<Z>, RO: RobustOpen> ProtocolDescription
    for CheatingLargePreprocessing<Z, S, D, RO>
{
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!(
            "{}-CheatingLargePreprocessing:\n{}\n{}\n{}",
            indent,
            S::protocol_desc(depth + 1),
            D::protocol_desc(depth + 1),
            RO::protocol_desc(depth + 1)
        )
    }
}

impl<Z: Ring, S: SingleSharing<Z>, D: DoubleSharing<Z>, RO: RobustOpen>
    CheatingLargePreprocessing<Z, S, D, RO>
{
    pub fn new(single_sharing: S, double_sharing: D, robust_open: RO) -> Self {
        Self {
            single_sharing,
            double_sharing,
            robust_open,
            ring_marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<
        Z: Derive + ErrorCorrect,
        Ses: LargeSessionHandles,
        S: SingleSharing<Z>,
        D: DoubleSharing<Z>,
        RO: RobustOpen,
    > Preprocessing<Z, Ses> for CheatingLargePreprocessing<Z, S, D, RO>
{
    async fn execute(
        &mut self,
        large_session: &mut Ses,
        batch_sizes: BatchParams,
    ) -> anyhow::Result<InMemoryBasePreprocessing<Z>> {
        let mut base_preprocessing = InMemoryBasePreprocessing::<Z>::default();

        //Init single sharing, we need 2 calls per triple and 1 call per randomness
        self.single_sharing
            .init(large_session, 2 * batch_sizes.triples + batch_sizes.randoms)
            .await?;

        //Init double sharing, we need 1 call per triple
        self.double_sharing
            .init(large_session, batch_sizes.triples)
            .await?;

        if batch_sizes.triples > 0 {
            //Preprocess a batch of triples
            base_preprocessing.append_triples(
                self.next_triple_batch(batch_sizes.triples, large_session)
                    .await?,
            );
        }
        if batch_sizes.randoms > 0 {
            //Preprocess a batch of randomness using the secure implem
            base_preprocessing.append_randoms(
                next_random_batch(batch_sizes.randoms, &mut self.single_sharing, large_session)
                    .await?,
            );
        }

        Ok(base_preprocessing)
    }
}

impl<Z: Derive + ErrorCorrect, S: SingleSharing<Z>, D: DoubleSharing<Z>, RO: RobustOpen>
    CheatingLargePreprocessing<Z, S, D, RO>
{
    //Lie to other in reconstructing masked product
    async fn next_triple_batch<Ses: LargeSessionHandles>(
        &mut self,
        amount: usize,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<Triple<Z>>> {
        let mut vec_share_x = Vec::with_capacity(amount);
        let mut vec_share_y = Vec::with_capacity(amount);
        let mut vec_double_share_v = Vec::with_capacity(amount);
        for _ in 0..amount {
            vec_share_x.push(self.single_sharing.next(session).await?);
            vec_share_y.push(self.single_sharing.next(session).await?);
            vec_double_share_v.push(self.double_sharing.next(session).await?);
        }

        //Add random error to every d and remove one
        let mut network_vec_share_d = vec_share_x
            .iter()
            .zip_eq(vec_share_y.iter())
            .zip_eq(vec_double_share_v.iter())
            .map(|((x, y), v)| {
                let res = *x * *y + v.degree_2t + Z::sample(session.rng());
                res
            })
            .collect_vec();
        network_vec_share_d.pop();

        let recons_vec_share_d = self
            .robust_open
            .robust_open_list_to_all(
                session,
                network_vec_share_d,
                2 * session.threshold() as usize,
            )
            .await?
            .unwrap();

        let vec_share_z: Vec<_> = recons_vec_share_d
            .into_iter()
            .zip_eq(vec_double_share_v.iter())
            .map(|(d, v)| d - v.degree_t)
            .collect_vec();

        let my_role = session.my_role();
        let res = vec_share_x
            .into_iter()
            .zip_eq(vec_share_y)
            .zip_eq(vec_share_z)
            .map(|((x, y), z)| {
                Triple::new(
                    Share::new(my_role, x),
                    Share::new(my_role, y),
                    Share::new(my_role, z),
                )
            })
            .collect_vec();
        Ok(res)
    }
}
