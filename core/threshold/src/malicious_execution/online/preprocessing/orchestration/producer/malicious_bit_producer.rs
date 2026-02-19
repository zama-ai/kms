use crate::{
    execution::{
        online::preprocessing::{
            dummy::DummyPreprocessing, orchestration::producers::bits_producer::GenericBitProducer,
        },
        runtime::sessions::{large_session::LargeSession, small_session::SmallSession},
    },
    malicious_execution::{
        online::malicious_gen_bits::DummyBitGenEven,
        small_execution::malicious_offline::FailingPreprocessing,
    },
};

pub type DummySmallSessionBitProducer<Z> =
    GenericBitProducer<Z, SmallSession<Z>, DummyPreprocessing, DummyBitGenEven>;

pub type DummyLargeSessionBitProducer<Z> =
    GenericBitProducer<Z, LargeSession, DummyPreprocessing, DummyBitGenEven>;

pub type FailingSmallSessionBitProducer<Z> =
    GenericBitProducer<Z, SmallSession<Z>, FailingPreprocessing<Z>, DummyBitGenEven>;
