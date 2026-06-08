// TODO: Make those configurable ?
///Amount of triples generated in one batch by the orchestrator
pub(crate) const BATCH_SIZE_TRIPLES: usize = 10000;
///Amount of bits generated in one batch by the orchestrator
pub(crate) const BATCH_SIZE_BITS: usize = 10000;
///Number of batches of bits that can be queued per thread in the orchestrator.
///A value of 2 enables double-buffering: a producer can prepare the next batch
///while the consumer drains the current one, instead of stalling on a 1-slot
///channel. Kept small to bound memory (each queued batch is BATCH_SIZE_* shares
///per producer thread).
pub(crate) const CHANNEL_BUFFER_SIZE: usize = 2;
///Progress tracker will automatically report every TRACKER_LOG_PERCENTAGE percent
pub const TRACKER_LOG_PERCENTAGE: usize = 5;
