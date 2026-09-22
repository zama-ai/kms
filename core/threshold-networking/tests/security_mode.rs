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

#[cfg(not(feature = "insecure"))]
mod secure_requests {
    use threshold_networking::grpc::{GrpcServer, NetworkingImpl};
    use threshold_types::{party::MpcIdentity, session_id::SessionId};
    use tonic::Code;

    #[expect(dead_code)]
    mod proto {
        tonic::include_proto!("ddec_networking");
    }

    fn client() -> proto::gnetworking_client::GnetworkingClient<GrpcServer> {
        let server = GrpcServer::new(NetworkingImpl::default());
        proto::gnetworking_client::GnetworkingClient::new(server)
    }

    #[tokio::test]
    async fn health_check_rejects_missing_tls_identity() {
        // HealthTag's fields are private; encode its field order.
        let tag = bc2wrap::serialize(&(MpcIdentity("party1".into()),)).unwrap();

        let error = client()
            .health_check(proto::HealthCheckRequest {
                tag,
                payload: vec![],
            })
            .await
            .unwrap_err();

        assert_eq!(error.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn send_value_rejects_missing_tls_identity() {
        // Tag's fields are private; encode its field order.
        let tag = bc2wrap::serialize(&(
            SessionId::new(&"tls-policy-test").unwrap(),
            MpcIdentity("party1".into()),
            0_u64,
        ))
        .unwrap();

        let error = client()
            .send_value(proto::SendValueRequest { tag, value: vec![] })
            .await
            .unwrap_err();

        assert_eq!(error.code(), Code::Unauthenticated);
    }
}
