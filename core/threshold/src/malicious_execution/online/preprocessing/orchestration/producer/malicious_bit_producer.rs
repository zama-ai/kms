use crate::{
    execution::{
        online::preprocessing::{
            dummy::DummyPreprocessing, orchestration::producers::bits_producer::GenericBitProducer,
        },
        runtime::session::{LargeSession, SmallSession},
    },
    malicious_execution::online::malicious_gen_bits::DummyBitGenEven,
};

pub type DummySmallSessionBitProducer<Z> =
    GenericBitProducer<Z, SmallSession<Z>, DummyPreprocessing<Z>, DummyBitGenEven>;

pub type DummyLargeSessionBitProducer<Z> =
    GenericBitProducer<Z, LargeSession, DummyPreprocessing<Z>, DummyBitGenEven>;
