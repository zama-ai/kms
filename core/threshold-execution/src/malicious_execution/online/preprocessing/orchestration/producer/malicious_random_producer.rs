use crate::{
    malicious_execution::small_execution::malicious_offline::FailingPreprocessing,
    online::preprocessing::{
        dummy::DummyPreprocessing,
        orchestration::producers::randoms_producer::GenericRandomProducer,
    },
    runtime::sessions::{large_session::LargeSession, small_session::SmallSession},
};

pub type DummySmallSessionRandomProducer<Z> =
    GenericRandomProducer<Z, SmallSession<Z>, DummyPreprocessing>;

pub type DummyLargeSessionRandomProducer<Z> =
    GenericRandomProducer<Z, LargeSession, DummyPreprocessing>;

pub type FailingSmallSessionRandomProducer<Z> =
    GenericRandomProducer<Z, SmallSession<Z>, FailingPreprocessing<Z>>;
