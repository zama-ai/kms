use crate::execution::{
    online::preprocessing::{
        dummy::DummyPreprocessing,
        orchestration::producers::triples_producer::GenericTripleProducer,
    },
    runtime::session::{LargeSession, SmallSession},
};

pub type DummySmallSessionTripleProducer<Z> =
    GenericTripleProducer<Z, SmallSession<Z>, DummyPreprocessing<Z>>;

pub type DummyLargeSessionTripleProducer<Z> =
    GenericTripleProducer<Z, LargeSession, DummyPreprocessing<Z>>;
