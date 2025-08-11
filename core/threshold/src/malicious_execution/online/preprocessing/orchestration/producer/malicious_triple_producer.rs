use crate::{
    execution::{
        online::preprocessing::{
            dummy::DummyPreprocessing,
            orchestration::producers::triples_producer::GenericTripleProducer,
        },
        runtime::session::{LargeSession, SmallSession},
    },
    malicious_execution::small_execution::malicious_offline::FailingPreprocessing,
};

pub type DummySmallSessionTripleProducer<Z> =
    GenericTripleProducer<Z, SmallSession<Z>, DummyPreprocessing<Z>>;

pub type DummyLargeSessionTripleProducer<Z> =
    GenericTripleProducer<Z, LargeSession, DummyPreprocessing<Z>>;

pub type FailingSmallSessionTripleProducer<Z> =
    GenericTripleProducer<Z, SmallSession<Z>, FailingPreprocessing<Z>>;
