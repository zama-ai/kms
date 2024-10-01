#[cfg(test)]
mod tests {
    use gateway::{
        config::{init_conf_gateway, GatewayConfig},
        events::manager::{start_gateway, start_http_server},
    };
    use reqwest::Client;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn integration_test_keyurl() {
        let mut config: GatewayConfig = init_conf_gateway("config/gateway").unwrap();
        config.debug = true;
        let (sender, receiver) = mpsc::channel(100);
        let url_server = config.api_url.clone();
        let url_client = config.api_url.clone();
        let http_handle =
            tokio::spawn(async move { start_http_server(url_server, sender.clone()).await });
        let gateway_handle = tokio::spawn(async move { start_gateway(receiver, config).await });
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Create an HTTP client
        let client = Client::new();
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
        http_handle.abort();
        gateway_handle.abort();
    }
}
