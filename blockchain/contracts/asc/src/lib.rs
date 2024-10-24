// Configuring wee_alloc as the global allocator for WebAssembly builds
// This reduces the size of the Wasm binary by about 10KB compared to the default allocator
#[cfg(target_arch = "wasm32")]
use wee_alloc;

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

pub mod contract;
mod events;
mod state;
mod versioned_storage;
