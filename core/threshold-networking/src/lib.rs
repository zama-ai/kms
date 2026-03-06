//! Networking traits and implementations.

pub mod constants;
pub mod grpc;
pub mod health_check;
pub mod local;
pub mod sending_service;
pub mod tls;

mod ggen {
    tonic::include_proto!("ddec_networking");
}

pub mod choreography_gen {
    tonic::include_proto!("ddec_choreography");
}
