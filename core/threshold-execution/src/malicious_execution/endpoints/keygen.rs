use aes_prng::AesRng;
use rand::SeedableRng;
use std::sync::{LazyLock, Mutex};
use tfhe::xof_key_set::CompressedXofKeySet;
use tokio::sync::oneshot;

use crate::{
    endpoints::keygen::OnlineDistributedKeyGen,
    online::preprocessing::DKGPreprocessing,
    runtime::sessions::base_session::BaseSessionHandles,
    tfhe_internals::{
        parameters::DKGParams, private_keysets::PrivateKeySet, public_keysets::FhePubKeySet,
        test_feature::gen_key_set,
    },
};
use algebra::{base_ring::Z128, galois_rings::common::ResiduePoly, structure_traits::ErrorCorrect};

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
        tag: tfhe::Tag,
    ) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let mut rng = AesRng::seed_from_u64(42);
        let fhe_key_set = gen_key_set(params, tag, &mut rng);

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
        _tag: tfhe::Tag,
    ) -> anyhow::Result<(CompressedXofKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        Err(anyhow::anyhow!(
            "This keygen implementation is supposed to fail"
        ))
    }

    async fn compressed_keygen_from_existing_private_keyset<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        _session: &mut S,
        _preprocessing: &mut P,
        _params: DKGParams,
        _tag: tfhe::Tag,
        _existing_private_keyset: &PrivateKeySet<EXTENSION_DEGREE>,
    ) -> anyhow::Result<CompressedXofKeySet>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        Err(anyhow::anyhow!(
            "This keygen implementation is supposed to fail"
        ))
    }

    async fn keygen_from_existing_private_keyset<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        _session: &mut S,
        _preprocessing: &mut P,
        _params: DKGParams,
        _tag: tfhe::Tag,
        _existing_private_keyset: &PrivateKeySet<EXTENSION_DEGREE>,
    ) -> anyhow::Result<FhePubKeySet>
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
        _tag: tfhe::Tag,
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
        _tag: tfhe::Tag,
    ) -> anyhow::Result<(CompressedXofKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        Err(anyhow::anyhow!(
            "This keygen implementation is supposed to fail"
        ))
    }

    async fn compressed_keygen_from_existing_private_keyset<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        _session: &mut S,
        _preprocessing: &mut P,
        _params: DKGParams,
        _tag: tfhe::Tag,
        _existing_private_keyset: &PrivateKeySet<EXTENSION_DEGREE>,
    ) -> anyhow::Result<CompressedXofKeySet>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        Err(anyhow::anyhow!(
            "This keygen implementation is supposed to fail"
        ))
    }

    async fn keygen_from_existing_private_keyset<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        _session: &mut S,
        _preprocessing: &mut P,
        _params: DKGParams,
        _tag: tfhe::Tag,
        _existing_private_keyset: &PrivateKeySet<EXTENSION_DEGREE>,
    ) -> anyhow::Result<FhePubKeySet>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        Err(anyhow::anyhow!(
            "This keygen implementation is supposed to fail"
        ))
    }
}

/// Online DKG that pretends to be ongoing via a oneshot channel that never fires.
/// The first call to any of the keygen variants takes the receiver and awaits it
/// until the surrounding task is aborted. Subsequent calls find the receiver gone
/// and return an error immediately.
pub struct SlowOnlineDistributedKeyGen128<const EXTENSION_DEGREE: usize>;

// The sender is kept alive in the static so the receiver never resolves; it is intentionally unused.
static SLOW_KEYGEN_CHANNEL: LazyLock<(oneshot::Sender<()>, Mutex<Option<oneshot::Receiver<()>>>)> =
    LazyLock::new(|| {
        let (tx, rx) = oneshot::channel();
        (tx, Mutex::new(Some(rx)))
    });

async fn slow_abort_bail<T>() -> anyhow::Result<T> {
    let rx = SLOW_KEYGEN_CHANNEL.1.lock().unwrap().take();
    match rx {
        Some(rx) => {
            let _ = rx.await;
            anyhow::bail!(
                "SlowOnlineDistributedKeyGen128 should have been aborted before completing"
            )
        }
        None => anyhow::bail!(
            "SlowOnlineDistributedKeyGen128: channel already consumed by a previous call"
        ),
    }
}

#[tonic::async_trait]
impl<const EXTENSION_DEGREE: usize> OnlineDistributedKeyGen<Z128, EXTENSION_DEGREE>
    for SlowOnlineDistributedKeyGen128<EXTENSION_DEGREE>
{
    async fn keygen<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        _session: &mut S,
        _preprocessing: &mut P,
        _params: DKGParams,
        _tag: tfhe::Tag,
    ) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        slow_abort_bail().await
    }

    async fn compressed_keygen<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        _session: &mut S,
        _preprocessing: &mut P,
        _params: DKGParams,
        _tag: tfhe::Tag,
    ) -> anyhow::Result<(CompressedXofKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        slow_abort_bail().await
    }

    async fn compressed_keygen_from_existing_private_keyset<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        _session: &mut S,
        _preprocessing: &mut P,
        _params: DKGParams,
        _tag: tfhe::Tag,
        _existing_private_keyset: &PrivateKeySet<EXTENSION_DEGREE>,
    ) -> anyhow::Result<CompressedXofKeySet>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        slow_abort_bail().await
    }

    async fn keygen_from_existing_private_keyset<
        S: BaseSessionHandles,
        P: DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        _session: &mut S,
        _preprocessing: &mut P,
        _params: DKGParams,
        _tag: tfhe::Tag,
        _existing_private_keyset: &PrivateKeySet<EXTENSION_DEGREE>,
    ) -> anyhow::Result<FhePubKeySet>
    where
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        slow_abort_bail().await
    }
}
