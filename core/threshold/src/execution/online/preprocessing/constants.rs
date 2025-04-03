///Amount of triples generated in one batch by the orchestrator
pub(crate) const BATCH_SIZE_TRIPLES: usize = 10000;
///Amount of bits generated in one batch by the orchestrator
pub(crate) const BATCH_SIZE_BITS: usize = 10000;
///Number of batches of bits that can be queued per thread in the orchestrator
pub(crate) const CHANNEL_BUFFER_SIZE: usize = 5;
///Progress tracker will automatically report every TRACKER_LOG_PERCENTAGE percent
pub(crate) const TRACKER_LOG_PERCENTAGE: usize = 10;
