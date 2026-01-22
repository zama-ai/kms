use crate::{
    execution::{
        online::preprocessing::{
            dummy::DummyPreprocessing,
            orchestration::producers::triples_producer::GenericTripleProducer,
        },
        runtime::sessions::{large_session::LargeSession, small_session::SmallSession},
    },
    malicious_execution::small_execution::malicious_offline::FailingPreprocessing,
};

pub type DummySmallSessionTripleProducer<Z> =
    GenericTripleProducer<Z, SmallSession<Z>, DummyPreprocessing>;

pub type DummyLargeSessionTripleProducer<Z> =
    GenericTripleProducer<Z, LargeSession, DummyPreprocessing>;

pub type FailingSmallSessionTripleProducer<Z> =
    GenericTripleProducer<Z, SmallSession<Z>, FailingPreprocessing>;
