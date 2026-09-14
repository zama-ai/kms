//! Checks the networking library's transport policy when the lib is compiled without `#[cfg(test)]`.

use std::sync::Arc;
use threshold_networking::grpc::{CoreToCoreNetworkConfig, GrpcNetworkingManager};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, crypto::aws_lc_rs::default_provider};

#[tokio::test]
async fn accepts_tls_configuration() {
    let tls_config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();

    assert!(
        GrpcNetworkingManager::new(Some(tls_config), CoreToCoreNetworkConfig::default()).is_ok()
    );
}

#[cfg(not(feature = "insecure"))]
#[tokio::test]
async fn rejects_plaintext_without_insecure_feature() {
    let error = GrpcNetworkingManager::new(None, CoreToCoreNetworkConfig::default()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("TLS configuration must be provided")
    );
}

#[cfg(feature = "insecure")]
#[tokio::test]
async fn accepts_plaintext_with_insecure_feature() {
    assert!(GrpcNetworkingManager::new(None, CoreToCoreNetworkConfig::default()).is_ok());
}
