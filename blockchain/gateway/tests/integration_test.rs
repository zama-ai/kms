#[cfg(test)]
mod tests {
    use ethers::providers::MockProvider;
    use gateway::{
        config::{init_conf_gateway, GatewayConfig, VerifyProvenCtResponseToClient},
        events::manager::{start_gateway, start_http_server},
        state::file_state::GatewayState,
    };
    use reqwest::Client;
    use serde::Deserialize;
    use serde_json::json;
    use std::collections::HashMap;
    use tokio::{sync::mpsc, time::Duration};

    fn id() -> usize {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static ID: AtomicUsize = AtomicUsize::new(0);
        ID.fetch_add(1, Ordering::SeqCst)
    }

    const GATEWAY_STATE_PATH: &str = ".GW_INTEGRATION_STATE";

    fn valid_config() -> GatewayConfig {
        let mut config: GatewayConfig = init_conf_gateway("config/gateway").unwrap();
        config.debug = true;
        let port = 7070 + id();
        let port = format!(":{port}");
        let old_port = ":7077";
        assert!(config.api_url.contains(old_port));
        config.api_url = config.api_url.replace(":7077", &port);
        config
    }

    async fn new_client() -> (
        Client,
        String,
        tokio::task::JoinHandle<()>,
        tokio::task::JoinHandle<Option<MockProvider>>,
    ) {
        let config: GatewayConfig = valid_config();
        let (sender, receiver) = mpsc::channel(100);
        let url_server = config.api_url.clone();
        let url_client = config.api_url.clone();
        let restored_state_result = GatewayState::restore_state(GATEWAY_STATE_PATH).await;
        if let Err(e) = &restored_state_result {
            eprintln!("Error restoring state: {}", e);
        }
        let (state, _, _) = restored_state_result.unwrap();

        let http_handle =
            tokio::spawn(async move { start_http_server(url_server, sender.clone()).await });
        let gateway_handle =
            tokio::spawn(
                async move { start_gateway(receiver, config, state, None).await.unwrap() },
            );
        tokio::time::sleep(Duration::from_millis(500)).await;
        (Client::new(), url_client, http_handle, gateway_handle)
    }

    #[tokio::test]
    #[serial_test::serial]

    async fn integration_test_keyurl() {
        let (client, url_client, http_handle, gateway_handle) = new_client().await;
        let test_count = 10;

        // key handle, we can try more than once in parallel
        let (tx, mut rx) = mpsc::channel(test_count);
        for _ in 0..test_count {
            let client = client.clone();
            let url_client = url_client.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                // Send a GET request to the Actix web service
                let response = client
                    .get(format!("http://{}/keyurl", url_client))
                    .send()
                    .await;
                assert!(response.is_ok());

                // Sanity check the response is sensible
                let body = response.unwrap().text().await.unwrap();
                // Sanity check the response is sensible
                assert!(body.len() > 200);
                assert!(body.contains("urls"));
                assert!(body.contains("fhe_parameter"));
                assert!(body.contains("PublicKey"));
                assert!(body.contains("ServerKey"));
                tx.send(true).await.unwrap();
            });
        }
        for _ in 0..test_count {
            // if something goes wrong we should not receive the final send
            // consider running the test *without* tokio spawn if something goes wrong
            let _ = tokio::time::timeout(Duration::from_millis(500), rx.recv())
                .await
                .unwrap();
        }

        // reencryption, we can try more than once
        let (tx, mut rx) = mpsc::channel(test_count);
        for _ in 0..test_count {
            let client = client.clone();
            let url_client = url_client.clone();
            let tx = tx.clone();

            let body_map: HashMap<&str, &str> = HashMap::from_iter([
                ("signature", "15a4f9a8eb61459cfba7d103d8f911fb04ce91ecf841b34c49c0d56a70b896d20cbc31986188f91efc3842b7df215cee8acb40178daedb8b63d0ba5d199bce121c"),
                ("client_address", "0x17853A630aAe15AED549B2B874de08B73C0F59c5"),
                ("enc_key", "2000000000000000df2fcacb774f03187f3802a27259f45c06d33cefa68d9c53426b15ad531aa822"),
                ("ciphertext_handle", "0748b542afe2353c86cb707e3d21044b0be1fd18efc7cbaa6a415af055bfb358"),
                ("eip712_verifying_contract", "0x66f9664f97F2b50F62D13eA064982f936dE76657")
            ]);

            tokio::spawn(async move {
                let response = client
                    .post(format!("http://{}/reencrypt", url_client))
                    .json(&body_map)
                    .send()
                    .await;
                assert!(response.is_ok());

                #[derive(Deserialize)]
                struct RespBody {
                    response: Vec<events::kms::ReencryptResponseValues>,
                    status: String,
                }

                let response_body: RespBody = response.unwrap().json().await.unwrap();
                assert_eq!(response_body.status, "success");
                assert!(response_body.response.len() == 1);
                assert_eq!(response_body.response[0].payload().0, b"payload".to_vec());
                assert_eq!(
                    response_body.response[0].signature().0,
                    b"signature".to_vec()
                );
                tx.send(true).await.unwrap();
            });
        }
        for _ in 0..test_count {
            // if something goes wrong we should not receive the final send
            // consider running the test *without* tokio spawn if something goes wrong
            let _ = tokio::time::timeout(Duration::from_millis(500), rx.recv())
                .await
                .unwrap();
        }

        http_handle.abort();
        gateway_handle.abort();
    }

    #[derive(Deserialize)]
    struct RespBodyVerifyProvenCt {
        response: VerifyProvenCtResponseToClient,
        status: String,
    }

    #[derive(Deserialize)]
    struct RespBodyVerifyProvenCtFailed {
        response: String,
        status: String,
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn integration_test_zkp_event_correct() {
        let body_map: serde_json::Value = serde_json::Value::Object(serde_json::Map::from_iter([
            ("ct_proof".into(), json!("00")),
            (
                "caller_address".into(),
                json!("0x0000000000000000000000000000000000000001"),
            ),
            (
                "contract_address".into(),
                json!("0x0000000000000000000000000000000000000002"),
            ),
            ("key_id".into(), json!("")),
            ("crs_id".into(), json!("")),
        ]));

        let (client, url_client, http_handle, gateway_handle) = new_client().await;
        let response = match client
            .post(format!("http://{url_client}/verify_proven_ct"))
            .json(&body_map)
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                eprintln!("{err}");
                unreachable!("")
            }
        };

        let status = response.status();
        assert_eq!(status, actix_web::http::StatusCode::OK.as_u16());
        let body = response.text().await.expect("Body");
        let body: RespBodyVerifyProvenCt =
            serde_json::de::from_str(&body).expect("Deserialized body");
        assert_eq!(body.status, "success");
        assert_eq!(
            body.response.kms_signatures,
            vec![vec![0_u8, 1, 2, 3]].into()
        );
        http_handle.abort();
        gateway_handle.abort();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn integration_test_zkp_event_bad_address() {
        let body_map: serde_json::Value = serde_json::Value::Object(serde_json::Map::from_iter([
            ("ct_proof".into(), json!("00")),
            (
                "caller_address".into(),
                json!("0x0000000000000000000000000000000000000001"),
            ),
            (
                "contract_address".into(),
                json!("0x0000000000000000000000000000000000000007"),
            ),
            ("key_id".into(), json!("")),
            ("crs_id".into(), json!("")),
        ]));

        let (client, url_client, http_handle, gateway_handle) = new_client().await;
        let response = match client
            .post(format!("http://{url_client}/verify_proven_ct"))
            .json(&body_map)
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                eprintln!("{err}");
                unreachable!("")
            }
        };

        let status = response.status();
        assert_eq!(status, actix_web::http::StatusCode::BAD_REQUEST.as_u16());
        let body = response.text().await.expect("Body");
        let body: RespBodyVerifyProvenCtFailed =
            serde_json::de::from_str(&body).expect("Deserialized body");
        assert_eq!(body.status, "failure");
        assert_eq!(body.response, "Unknown contact address.");
        http_handle.abort();
        gateway_handle.abort();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn integration_test_zkp_event_bad_proof_explicit() {
        let body_map: serde_json::Value = serde_json::Value::Object(serde_json::Map::from_iter([
            ("ct_proof".into(), json!("01")),
            (
                "caller_address".into(),
                json!("0x0000000000000000000000000000000000000001"),
            ),
            (
                "contract_address".into(),
                json!("0x0000000000000000000000000000000000000002"),
            ),
            ("key_id".into(), json!("")),
            ("crs_id".into(), json!("")),
        ]));

        let (client, url_client, http_handle, gateway_handle) = new_client().await;
        let response = match client
            .post(format!("http://{url_client}/verify_proven_ct"))
            .json(&body_map)
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                eprintln!("{err}");
                unreachable!("")
            }
        };

        let status = response.status();
        assert_eq!(status, actix_web::http::StatusCode::BAD_REQUEST.as_u16());
        let body = response.text().await.expect("Body");
        let body: RespBodyVerifyProvenCtFailed =
            serde_json::de::from_str(&body).expect("Deserialized body");
        assert_eq!(body.status, "failure");
        assert_eq!(
            body.response,
            "Error verifying proven ciphertext. Mock: only valid if element 0 is odd."
        );
        http_handle.abort();
        gateway_handle.abort();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn integration_test_zkp_event_bad_proof_implicit() {
        let body_map: serde_json::Value = serde_json::Value::Object(serde_json::Map::from_iter([
            ("ct_proof".into(), json!("03")),
            (
                "caller_address".into(),
                json!("0x0000000000000000000000000000000000000001"),
            ),
            (
                "contract_address".into(),
                json!("0x0000000000000000000000000000000000000002"),
            ),
            ("key_id".into(), json!("")),
            ("crs_id".into(), json!("")),
        ]));

        let (client, url_client, http_handle, gateway_handle) = new_client().await;
        let response = match client
            .post(format!("http://{url_client}/verify_proven_ct"))
            .json(&body_map)
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                eprintln!("{err}");
                unreachable!("")
            }
        };

        let status = response.status();
        assert_eq!(
            status,
            actix_web::http::StatusCode::INTERNAL_SERVER_ERROR.as_u16()
        );
        let body = response.text().await.expect("Body");
        let body: RespBodyVerifyProvenCtFailed =
            serde_json::de::from_str(&body).expect("Deserialized body");
        assert_eq!(body.status, "failure");
        assert_eq!(body.response, "channel closed");
        http_handle.abort();
        gateway_handle.abort();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn integration_test_zkp_event_bad_field() {
        let body_map: serde_json::Value = serde_json::Value::Object(serde_json::Map::from_iter([
            ("ct_proof".into(), json!("01")),
            ("caller_address".into(), json!("0x0000000000000000001")),
            (
                "contract_address".into(),
                json!("0x0000000000000000000000000000000000000002"),
            ),
            ("key_id".into(), json!("")),
            ("crs_id".into(), json!("")),
        ]));

        let (client, url_client, http_handle, gateway_handle) = new_client().await;
        let response = match client
            .post(format!("http://{url_client}/verify_proven_ct"))
            .json(&body_map)
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                eprintln!("{err}");
                unreachable!("")
            }
        };

        let status = response.status();
        assert_eq!(status, actix_web::http::StatusCode::BAD_REQUEST.as_u16());
        let body = response.text().await.expect("Body");
        let body: RespBodyVerifyProvenCtFailed =
            serde_json::de::from_str(&body).expect("Deserialized body");
        assert_eq!(body.status, "failure");
        assert_eq!(body.response, "Odd number of digits");
        http_handle.abort();
        gateway_handle.abort();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn integration_test_zkp_event_missing_field() {
        let body_map: serde_json::Value = serde_json::Value::Object(serde_json::Map::from_iter([
            ("ct_proof".into(), json!("01")),
            // missing ("caller_address".into(),   json!("0x000000000000000000000000000000000000001")),
            (
                "contract_address".into(),
                json!("0x0000000000000000000000000000000000000002"),
            ),
            ("key_id".into(), json!("")),
            ("crs_id".into(), json!("")),
        ]));

        let (client, url_client, http_handle, gateway_handle) = new_client().await;
        let response = match client
            .post(format!("http://{url_client}/verify_proven_ct"))
            .json(&body_map)
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                eprintln!("{err}");
                unreachable!("")
            }
        };

        let status = response.status();
        assert_eq!(status, actix_web::http::StatusCode::BAD_REQUEST.as_u16());
        let body = response.text().await.expect("Body");
        assert_eq!(
            body,
            "Json deserialize error: missing field `caller_address` at line 1 column 105"
        );
        http_handle.abort();
        gateway_handle.abort();
    }
}
