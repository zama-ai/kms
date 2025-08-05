use crate::execution::{
    online::preprocessing::{
        dummy::DummyPreprocessing,
        orchestration::producers::randoms_producer::GenericRandomProducer,
    },
    runtime::session::{LargeSession, SmallSession},
};

pub type DummySmallSessionRandomProducer<Z> =
    GenericRandomProducer<Z, SmallSession<Z>, DummyPreprocessing<Z>>;

pub type DummyLargeSessionRandomProducer<Z> =
    GenericRandomProducer<Z, LargeSession, DummyPreprocessing<Z>>;
