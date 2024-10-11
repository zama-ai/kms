#[cfg(test)]
mod tests {
    use gateway::{
        config::{init_conf_gateway, GatewayConfig},
        events::manager::{start_gateway, start_http_server},
    };
    use reqwest::Client;
    use serde::Deserialize;
    use std::{collections::HashMap, time::Duration};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn integration_test() {
        let mut config: GatewayConfig = init_conf_gateway("config/gateway").unwrap();
        config.debug = true;
        let (sender, receiver) = mpsc::channel(100);
        let url_server = config.api_url.clone();
        let url_client = config.api_url.clone();
        let http_handle =
            tokio::spawn(async move { start_http_server(url_server, sender.clone()).await });
        let gateway_handle = tokio::spawn(async move { start_gateway(receiver, config).await });
        tokio::time::sleep(Duration::from_millis(500)).await;
        let client = Client::new();
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
                assert!(body.contains("param_choice"));
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
}
