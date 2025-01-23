use std::sync::OnceLock;

use lazy_static::lazy_static;
use peak_alloc::PeakAlloc;

lazy_static! {
    pub static ref MEM_ALLOCATOR: OnceLock<PeakAlloc> = OnceLock::new();
}
