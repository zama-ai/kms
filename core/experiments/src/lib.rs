#[cfg(feature = "measure_memory")]
pub mod allocator;
pub mod choreography;
pub mod conf;
pub mod utils;
pub mod zk_utils;

pub mod choreography_gen {
    tonic::include_proto!("ddec_choreography");
}
