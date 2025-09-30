use aes_prng::AesRng;
use rand::SeedableRng;
use tfhe::xof_key_set::CompressedXofKeySet;

use crate::{
    algebra::{base_ring::Z128, galois_rings::common::ResiduePoly, structure_traits::ErrorCorrect},
    execution::{
        endpoints::keygen::OnlineDistributedKeyGen,
        online::preprocessing::DKGPreprocessing,
        runtime::session::BaseSessionHandles,
        tfhe_internals::{
            compression_decompression_key::CompressionPrivateKeyShares, parameters::DKGParams,
            private_keysets::PrivateKeySet, public_keysets::FhePubKeySet,
            test_feature::gen_key_set,
        },
    },
};

pub struct DroppingOnlineDistributedKeyGen128<const EXTENSION_DEGREE: usize>;

pub struct FailingOnlineDistributedKeyGen128<const EXTENSION_DEGREE: usize>;

#[tonic::async_trait]
impl<const EXTENSION_DEGREE: usize> OnlineDistributedKeyGen<Z128, EXTENSION_DEGREE>
    for DroppingOnlineDistributedKeyGen128<EXTENSION_DEGREE>
{
    async fn keygen<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        _base_session: &mut S,
        _preprocessing: &mut P,
        params: DKGParams,
        _existing_compression_sk: Option<&CompressionPrivateKeyShares<Z128, EXTENSION_DEGREE>>,
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

    //TODO: Need to do dummy stuff as above
    async fn compressed_keygen<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        _session: &mut S,
        _preprocessing: &mut P,
        _params: DKGParams,
        _existing_compression_sk: Option<&CompressionPrivateKeyShares<Z128, EXTENSION_DEGREE>>,
    ) -> anyhow::Result<(CompressedXofKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        Err(anyhow::anyhow!(
            "This keygen implementation is supposed to fail"
        ))
    }
}

#[tonic::async_trait]
impl<const EXTENSION_DEGREE: usize> OnlineDistributedKeyGen<Z128, EXTENSION_DEGREE>
    for FailingOnlineDistributedKeyGen128<EXTENSION_DEGREE>
{
    async fn keygen<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        _base_session: &mut S,
        _preprocessing: &mut P,
        _params: DKGParams,
        _existing_compression_sk: Option<&CompressionPrivateKeyShares<Z128, EXTENSION_DEGREE>>,
    ) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        Err(anyhow::anyhow!(
            "This keygen implementation is supposed to fail"
        ))
    }

    async fn compressed_keygen<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        _session: &mut S,
        _preprocessing: &mut P,
        _params: DKGParams,
        _existing_compression_sk: Option<&CompressionPrivateKeyShares<Z128, EXTENSION_DEGREE>>,
    ) -> anyhow::Result<(CompressedXofKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        Err(anyhow::anyhow!(
            "This keygen implementation is supposed to fail"
        ))
    }
}
