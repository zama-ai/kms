use crate::{
    execution::{
        online::preprocessing::{
            dummy::DummyPreprocessing,
            orchestration::producers::randoms_producer::GenericRandomProducer,
        },
        runtime::sessions::{large_session::LargeSession, small_session::SmallSession},
    },
    malicious_execution::small_execution::malicious_offline::FailingPreprocessing,
};

pub type DummySmallSessionRandomProducer<Z> =
    GenericRandomProducer<Z, SmallSession<Z>, DummyPreprocessing<Z>>;

pub type DummyLargeSessionRandomProducer<Z> =
    GenericRandomProducer<Z, LargeSession, DummyPreprocessing<Z>>;

pub type FailingSmallSessionRandomProducer<Z> =
    GenericRandomProducer<Z, SmallSession<Z>, FailingPreprocessing<Z>>;
