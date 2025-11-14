use crate::{
    algebra::galois_rings::degree_4::ResiduePolyF4Z128,
    execution::{
        online::preprocessing::orchestration::producer_traits::ProducerFactory,
        runtime::sessions::small_session::SmallSession,
    },
    malicious_execution::online::preprocessing::orchestration::producer::{
        malicious_bit_producer::{DummySmallSessionBitProducer, FailingSmallSessionBitProducer},
        malicious_random_producer::{
            DummySmallSessionRandomProducer, FailingSmallSessionRandomProducer,
        },
        malicious_triple_producer::{
            DummySmallSessionTripleProducer, FailingSmallSessionTripleProducer,
        },
    },
};

pub struct DummyProducerFactory;

pub struct FailingProducerFactory;

impl ProducerFactory<ResiduePolyF4Z128, SmallSession<ResiduePolyF4Z128>> for DummyProducerFactory {
    type TripleProducer = DummySmallSessionTripleProducer<ResiduePolyF4Z128>;
    type RandomProducer = DummySmallSessionRandomProducer<ResiduePolyF4Z128>;
    type BitProducer = DummySmallSessionBitProducer<ResiduePolyF4Z128>;
}

impl ProducerFactory<ResiduePolyF4Z128, SmallSession<ResiduePolyF4Z128>>
    for FailingProducerFactory
{
    type TripleProducer = FailingSmallSessionTripleProducer<ResiduePolyF4Z128>;
    type RandomProducer = FailingSmallSessionRandomProducer<ResiduePolyF4Z128>;
    type BitProducer = FailingSmallSessionBitProducer<ResiduePolyF4Z128>;
}
