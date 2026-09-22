//! Networking traits and implementations.

pub(crate) mod clock;
pub mod constants;
pub mod grpc;
pub mod health_check;
pub mod local;
pub mod sending_service;
pub mod tls;
pub mod tls_certs;

mod ggen {
    tonic::include_proto!("ddec_networking");
}
