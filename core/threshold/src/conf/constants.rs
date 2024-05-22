use lazy_static::lazy_static;
use std::time::Duration;

pub const TRACER_MAX_QUEUE_SIZE: usize = 4096;
pub const TRACER_MAX_EXPORT_BATCH_SIZE: usize = 512;
pub const TRACER_MAX_CONCURRENT_EXPORTS: usize = 4;
lazy_static! {
    pub static ref TRACER_SCHEDULED_DELAY: Duration = Duration::from_millis(1000);
}
