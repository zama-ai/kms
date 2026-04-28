use peak_alloc::PeakAlloc;
use std::sync::OnceLock;

pub static MEM_ALLOCATOR: OnceLock<PeakAlloc> = OnceLock::new();
