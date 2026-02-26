//! Networking traits and implementations.

pub mod constants;
pub mod grpc;
pub mod health_check;
pub mod local;
pub mod sending_service;
pub mod tls;

mod ggen {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("ddec_networking");
}
