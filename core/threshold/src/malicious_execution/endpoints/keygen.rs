use aes_prng::AesRng;
use rand::SeedableRng;

use crate::{
    algebra::{base_ring::Z128, galois_rings::common::ResiduePoly, structure_traits::ErrorCorrect},
    execution::{
        endpoints::keygen::OnlineDistributedKeyGen,
        online::preprocessing::DKGPreprocessing,
        runtime::session::BaseSessionHandles,
        tfhe_internals::{
            parameters::DKGParams, private_keysets::PrivateKeySet, public_keysets::FhePubKeySet,
            test_feature::gen_key_set,
        },
    },
};

pub struct DroppingOnlineDistributedKeyGen128;

pub struct FailingOnlineDistributedKeyGen128;

#[tonic::async_trait]
impl OnlineDistributedKeyGen<Z128> for DroppingOnlineDistributedKeyGen128 {
    async fn keygen<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
        const EXTENSION_DEGREE: usize,
    >(
        _base_session: &mut S,
        _preprocessing: &mut P,
        params: DKGParams,
    ) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let mut rng = AesRng::seed_from_u64(42);
        let fhe_key_set = gen_key_set(params, &mut rng);

        // the private key set is initialized with dummy values
        // they do not correspond to the fhe_key_set
        let private_key_set = PrivateKeySet::<EXTENSION_DEGREE>::init_dummy(params);

        Ok((fhe_key_set.public_keys, private_key_set))
    }
}

#[tonic::async_trait]
impl OnlineDistributedKeyGen<Z128> for FailingOnlineDistributedKeyGen128 {
    async fn keygen<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
        const EXTENSION_DEGREE: usize,
    >(
        _base_session: &mut S,
        _preprocessing: &mut P,
        _params: DKGParams,
    ) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        Err(anyhow::anyhow!(
            "This keygen implementation is supposed to fail"
        ))
    }
}
