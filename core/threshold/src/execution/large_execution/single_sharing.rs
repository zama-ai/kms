use super::local_single_share::{LocalSingleShare, SecureLocalSingleShare};
use crate::{
    algebra::{
        bivariate::{compute_powers, MatrixMul},
        structure_traits::{Derive, ErrorCorrect, Invert, Ring, RingEmbed},
    },
    error::error_handler::anyhow_error_and_log,
    execution::runtime::{party::Role, session::LargeSessionHandles},
    ProtocolDescription,
};
use async_trait::async_trait;
use itertools::Itertools;
use ndarray::{ArrayD, IxDyn};
use std::collections::HashMap;
use tracing::instrument;

pub type SecureSingleSharing<Z> = RealSingleSharing<Z, SecureLocalSingleShare>;

#[async_trait]
pub trait SingleSharing<Z: Ring>: ProtocolDescription + Send + Sync + Clone {
    async fn init<L: LargeSessionHandles>(
        &mut self,
        session: &mut L,
        l: usize,
    ) -> anyhow::Result<()>;
    async fn next<L: LargeSessionHandles>(&mut self, session: &mut L) -> anyhow::Result<Z>;
}

//Might want to store the dispute set at the output of the lsl call
//as that'll influence how to reconstruct stuff later on
pub struct RealSingleSharing<Z, S: LocalSingleShare> {
    local_single_share: S,
    available_lsl: Vec<ArrayD<Z>>,
    available_shares: Vec<Z>,
    max_num_iterations: usize,
    vdm_matrix: ArrayD<Z>,
}

impl<Z, S: LocalSingleShare> ProtocolDescription for RealSingleSharing<Z, S> {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!(
            "{}-RealSingleSharing:\n{}",
            indent,
            S::protocol_desc(depth + 1)
        )
    }
}

//Custom implementaiton of Clone to make sure we do not clone
//the internal state as that would be insecure.
//What we may want is to clone the underlying strategy
impl<Z: Default, S: LocalSingleShare> Clone for RealSingleSharing<Z, S> {
    fn clone(&self) -> Self {
        Self::new(self.local_single_share.clone())
    }
}

impl<Z: Default, S: LocalSingleShare> RealSingleSharing<Z, S> {
    pub fn new(local_single_share: S) -> Self {
        Self {
            local_single_share,
            available_lsl: Vec::default(),
            available_shares: Vec::default(),
            max_num_iterations: usize::default(),
            vdm_matrix: ArrayD::<Z>::default(IxDyn::default()),
        }
    }
}

impl<Z: Default, S: LocalSingleShare + Default> Default for RealSingleSharing<Z, S> {
    fn default() -> Self {
        Self::new(S::default())
    }
}

#[async_trait]
impl<Z: Ring + RingEmbed + Invert + Derive + ErrorCorrect, S: LocalSingleShare> SingleSharing<Z>
    for RealSingleSharing<Z, S>
{
    #[instrument(name="SingleSharing.Init",skip(self,session),fields(sid = ?session.session_id(),own_identity=?session.own_identity(), batch_size = ?l))]
    async fn init<L: LargeSessionHandles>(
        &mut self,
        session: &mut L,
        l: usize,
    ) -> anyhow::Result<()> {
        if l == 0 {
            return Ok(());
        }

        let my_secrets = (0..l).map(|_| Z::sample(session.rng())).collect_vec();

        let shares = self
            .local_single_share
            .execute(session, &my_secrets)
            .await?;

        // Prepare data from the map output by LocalSingleShare to the vector ready to be multiplied with the VDM matrix
        self.available_lsl = format_for_next(shares, l)?;
        self.max_num_iterations = l;

        //Init vdm matrix only once or when dim changes
        let shape = self.vdm_matrix.shape();
        let curr_height = session.num_parties();
        let curr_width = session.num_parties() - session.threshold() as usize;
        if self.vdm_matrix.is_empty() || curr_height != shape[0] || curr_width != shape[1] {
            self.vdm_matrix = init_vdm(
                session.num_parties(),
                session.num_parties() - session.threshold() as usize,
            )?;
        }
        Ok(())
    }

    //NOTE: This is instrumented by the caller function to use the same span for all calls
    async fn next<L: LargeSessionHandles>(&mut self, session: &mut L) -> anyhow::Result<Z> {
        //If there's no shares available we recompute a new batch
        if self.available_shares.is_empty() {
            //If there's no more randomness to extract we re init
            if self.available_lsl.is_empty() {
                self.init(session, self.max_num_iterations).await?;
            }
            //Extract randomness from the next available set of LocalSingleShares
            self.available_shares = compute_next_batch(&mut self.available_lsl, &self.vdm_matrix)?;
        }

        Ok(self
            .available_shares
            .pop()
            .ok_or_else(|| anyhow_error_and_log("Trying to pop an empty vector"))?)
    }
}

///Create the VDM matrix of dimension (height, width) such that
/// VDM_{i,j} = alpha_i^j, with alpha_i the ith element of the exceptional set
pub fn init_vdm<Z: Ring + RingEmbed>(height: usize, width: usize) -> anyhow::Result<ArrayD<Z>> {
    // We could actually probably take 0 in the VDM matrix, but to match the alpha indexing with the one we use for parties,
    //we skip it
    let exceptional_sequence: Vec<Z> = (0..height)
        .map(|idx| Z::embed_exceptional_set(idx + 1))
        .try_collect()?;

    let powers_of_exceptional_sequence: Vec<Z> = exceptional_sequence
        .into_iter()
        .fold(Vec::<Z>::new(), |acc, point| {
            [acc, compute_powers(point, width - 1)].concat()
        });

    Ok(ArrayD::from_shape_vec(IxDyn(&[height, width]), powers_of_exceptional_sequence)?.into_dyn())
}

///Have to be careful about ordering (e.g. cant just iterate over the set of key as its unordered)
///
///Format the map with keys role_i in Roles
///
///role_i -> [<x_1^{(i)}>_{self}, ... , <x_l^{(i)}>_{self}]
///
///to a vector appropriate fro the randomness extraction with keys j in [l]
///
/// j -> [<x_j^{(1)}>_{self}, ..., <x_j^{(n)}>_{self}]
fn format_for_next<Z: Ring>(
    local_single_shares: HashMap<Role, Vec<Z>>,
    l: usize,
) -> anyhow::Result<Vec<ArrayD<Z>>> {
    let num_parties = local_single_shares.len();
    let mut res = Vec::with_capacity(l);
    for i in 0..l {
        let mut vec = Vec::with_capacity(num_parties);
        for party_idx in 0..num_parties {
            vec.push(
                local_single_shares
                    .get(&Role::indexed_from_zero(party_idx))
                    .ok_or_else(|| {
                        anyhow_error_and_log(format!(
                            "Can not find shares for Party {}",
                            party_idx + 1
                        ))
                    })?[i],
            );
        }
        res.push(ArrayD::from_shape_vec(IxDyn(&[num_parties]), vec)?.into_dyn());
    }
    Ok(res)
}

///Extract randomness using the parties contributions and the VDM matrix
fn compute_next_batch<Z: Ring>(
    formatted_lsl: &mut Vec<ArrayD<Z>>,
    vdm: &ArrayD<Z>,
) -> anyhow::Result<Vec<Z>> {
    let res = formatted_lsl
        .pop()
        .ok_or_else(|| anyhow_error_and_log("Can not pop empty formatted_lsl vector"))?
        .matmul(vdm)?;
    Ok(res.into_raw_vec_and_offset().0)
}

#[cfg(test)]
pub(crate) mod tests {
    #[cfg(feature = "extension_degree_8")]
    use super::init_vdm;
    use crate::algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64};
    #[cfg(feature = "extension_degree_8")]
    use crate::algebra::galois_rings::degree_8::ResiduePolyF8;
    use crate::execution::large_execution::constants::DISPUTE_STAT_SEC;
    use crate::execution::runtime::session::BaseSessionHandles;
    use crate::execution::sharing::shamir::RevealOp;
    use crate::networking::NetworkMode;
    use crate::{
        algebra::structure_traits::{Derive, ErrorCorrect, Invert, Ring, RingEmbed, Sample},
        execution::{
            large_execution::{single_sharing::SecureSingleSharing, single_sharing::SingleSharing},
            runtime::party::Role,
            runtime::session::{LargeSession, ParameterHandles},
            sharing::{shamir::ShamirSharings, share::Share},
        },
        tests::helper::tests_and_benches::execute_protocol_large,
    };
    #[cfg(feature = "extension_degree_8")]
    use ndarray::Ix2;
    use num_integer::div_ceil;
    use rstest::rstest;
    #[cfg(feature = "extension_degree_8")]
    use std::num::Wrapping;

    fn test_singlesharing<
        Z: Ring + RingEmbed + Derive + ErrorCorrect + Invert,
        const EXTENSION_DEGREE: usize,
    >(
        parties: usize,
        threshold: usize,
    ) {
        let mut task = |mut session: LargeSession| async move {
            let lsl_batch_size = 10_usize;
            let extracted_size = session.num_parties() - session.threshold() as usize;
            let num_output = lsl_batch_size * extracted_size + 1;
            let mut res = Vec::<Z>::new();
            let mut single_sharing = SecureSingleSharing::<Z>::default();
            single_sharing
                .init(&mut session, lsl_batch_size)
                .await
                .unwrap();
            for _ in 0..num_output {
                res.push(single_sharing.next(&mut session).await.unwrap());
            }
            (session.my_role(), res)
        };

        // Rounds (only on the happy path here)
        // RealPreprocessing
        // init single sharing
        //      share dispute = 1 round
        //      pads =  1 round
        //      coinflip = vss + open = (1 + 3 + threshold) + 1
        //      verify = m reliable_broadcast = m*(3 + t) rounds
        // next() calls for the batch
        //      We're doing one more sharing than pre-computed in the initial init (see num_output)
        //      Thus we have one more call to init, and therefore we double the rounds from above
        // SingleSharing assumes Sync network
        let m = div_ceil(DISPUTE_STAT_SEC, Z::LOG_SIZE_EXCEPTIONAL_SET);
        let rounds = (1 + 1 + (1 + 3 + threshold) + 1 + m * (3 + threshold)) * 2;
        let result = execute_protocol_large::<_, _, Z, EXTENSION_DEGREE>(
            parties,
            threshold,
            Some(rounds),
            NetworkMode::Sync,
            None,
            &mut task,
        );

        //Check we can reconstruct
        let lsl_batch_size = 10_usize;
        let extracted_size = parties - threshold;
        let num_output = lsl_batch_size * extracted_size + 1;
        assert_eq!(result[0].1.len(), num_output);
        for value_idx in 0..num_output {
            let mut res_vec = Vec::new();
            for (role, res) in result.iter() {
                res_vec.push(Share::new(*role, res[value_idx]));
            }
            let shamir_sharing = ShamirSharings::create(res_vec);
            let res = shamir_sharing.reconstruct(threshold);
            assert!(res.is_ok());
        }
    }

    #[rstest]
    #[case(4, 1)]
    #[case(7, 2)]
    fn test_singlesharing_z128(#[case] num_parties: usize, #[case] threshold: usize) {
        test_singlesharing::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>(
            num_parties,
            threshold,
        );
    }

    #[rstest]
    #[case(4, 1)]
    #[case(7, 2)]
    fn test_singlesharing_z64(#[case] num_parties: usize, #[case] threshold: usize) {
        test_singlesharing::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }>(
            num_parties,
            threshold,
        );
    }
    //P2 dropout, but gives random value for reconstruction.
    // expect to see it as corrupt but able to reconstruct
    #[test]
    fn test_singlesharing_dropout() {
        let parties = 4;
        let threshold = 1;

        async fn task(mut session: LargeSession) -> (Role, Vec<ResiduePolyF4Z128>) {
            let lsl_batch_size = 10_usize;
            let extracted_size = session.num_parties() - session.threshold() as usize;
            let num_output = lsl_batch_size * extracted_size + 1;
            let mut res = Vec::<ResiduePolyF4Z128>::new();
            if session.my_role().one_based() != 2 {
                let mut single_sharing = SecureSingleSharing::<ResiduePolyF4Z128>::default();
                single_sharing
                    .init(&mut session, lsl_batch_size)
                    .await
                    .unwrap();
                for _ in 0..num_output {
                    res.push(single_sharing.next(&mut session).await.unwrap());
                }
                assert!(session.corrupt_roles().contains(&Role::indexed_from_one(2)));
            } else {
                for _ in 0..num_output {
                    res.push(ResiduePolyF4Z128::sample(session.rng()));
                }
            }
            (session.my_role(), res)
        }

        // SingleSharing assumes Sync network
        let result = execute_protocol_large::<
            _,
            _,
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >(parties, threshold, None, NetworkMode::Sync, None, &mut task);

        //Check we can reconstruct
        let lsl_batch_size = 10_usize;
        let extracted_size = parties - threshold;
        let num_output = lsl_batch_size * extracted_size + 1;
        assert_eq!(result[0].1.len(), num_output);
        for value_idx in 0..num_output {
            let mut res_vec = Vec::new();
            for (role, res) in result.iter() {
                res_vec.push(Share::new(*role, res[value_idx]));
            }
            let shamir_sharing = ShamirSharings::create(res_vec);
            //Expect max 1 error coming from dropout
            let res = shamir_sharing.err_reconstruct(threshold, 1);
            assert!(res.is_ok());
        }
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_vdm() {
        let vdm = init_vdm(4, 4).unwrap();
        let coefs = vec![
            ResiduePolyF8 {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //1
            ResiduePolyF8 {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //1
            ResiduePolyF8 {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //1
            ResiduePolyF8 {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //1
            ResiduePolyF8 {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //1
            ResiduePolyF8 {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //X
            ResiduePolyF8 {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //X^2
            ResiduePolyF8 {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //X^3
            ResiduePolyF8 {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //1
            ResiduePolyF8 {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //X + 1
            ResiduePolyF8 {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(2_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //X^2 + 2Y + 1
            ResiduePolyF8 {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(3_u128),
                    Wrapping(3_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //X^3 + 3*Y^2 + 3*Y + 1
            ResiduePolyF8 {
                coefs: [
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //1
            ResiduePolyF8 {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //X^2
            ResiduePolyF8 {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                ],
            }, //X^4
            ResiduePolyF8 {
                coefs: [
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(0_u128),
                    Wrapping(1_u128),
                    Wrapping(0_u128),
                ],
            }, //X^6
        ];

        let vdm = vdm.into_dimensionality::<Ix2>().unwrap();
        for i in 0..4 {
            for j in 0..4 {
                assert_eq!(coefs[4 * i + j], vdm[(i, j)]);
            }
        }
    }
}
