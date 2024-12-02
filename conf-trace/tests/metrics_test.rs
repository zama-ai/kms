#[cfg(feature = "metrics_test")]
#[cfg(test)]
mod tests {
    use conf_trace::conf::Tracing;
    use conf_trace::metrics::{CoreMetrics, MetricError};
    use conf_trace::telemetry;
    use std::sync::Mutex;
    use std::sync::Once;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tokio::time::sleep;

    // Use a single port for all tests to avoid port conflicts
    static PORT: u16 = 9465;
    static INIT: Once = Once::new();

    // Store shutdown sender to keep server alive during tests
    static SHUTDOWN: Mutex<Option<oneshot::Sender<()>>> = Mutex::new(None);

    async fn init_test_metrics() -> (CoreMetrics, u16) {
        let tracing = Tracing::builder()
            .service_name("test_service")
            .metrics_port(PORT)
            .build();

        // Initialize metrics only once
        INIT.call_once(|| {
            let (provider, shutdown_tx) = telemetry::init_metrics(tracing.clone());
            *SHUTDOWN.lock().unwrap() = Some(shutdown_tx);
            let _ = provider; // Ignore the provider since we only need it for initialization
        });

        // Wait longer for the server to start and metrics to initialize
        sleep(Duration::from_millis(1000)).await;

        (CoreMetrics::new().expect("Failed to create metrics"), PORT)
    }

    async fn get_metrics(port: u16) -> String {
        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://localhost:{}/metrics", port))
            .send()
            .await
            .expect("Failed to get metrics");

        println!("Response status: {}", response.status());

        let text = response.text().await.expect("Failed to read metrics");
        println!("Response text length: {}", text.len());
        text
    }

    #[tokio::test]
    async fn test_request_counter() {
        let (metrics, port) = init_test_metrics().await;

        // Record some operations
        metrics.increment_request_counter("test_op").unwrap();
        metrics.increment_request_counter("test_op").unwrap();

        // Wait longer for metrics to be exported
        sleep(Duration::from_millis(500)).await;
        let metrics_output = get_metrics(port).await;
        println!("Metrics output:\n{}", metrics_output);
        assert!(metrics_output.contains("kms_operations_total"));
        assert!(metrics_output.contains("operation=\"test_op\""));
        assert!(metrics_output.contains("2")); // Count should be 2
    }

    #[tokio::test]
    async fn test_error_counter() {
        let (metrics, port) = init_test_metrics().await;

        // Record an error
        metrics
            .increment_error_counter("test_op", "test_error")
            .unwrap();

        // Wait longer for metrics to be exported
        sleep(Duration::from_millis(500)).await;
        let metrics_output = get_metrics(port).await;
        assert!(metrics_output.contains("kms_operation_errors_total"));
        assert!(metrics_output.contains("operation=\"test_op\""));
        assert!(metrics_output.contains("error=\"test_error\""));
        assert!(metrics_output.contains("1")); // Count should be 1
    }

    #[tokio::test]
    async fn test_duration_metrics() {
        let (metrics, port) = init_test_metrics().await;

        // Record duration using the timer guard
        {
            let _timer = metrics
                .time_operation("test_op")
                .unwrap()
                .tag("test_tag", "test_value")
                .unwrap()
                .start();

            // Simulate some work
            sleep(Duration::from_millis(100)).await;
        }

        // Wait longer for metrics to be exported
        sleep(Duration::from_millis(500)).await;
        let metrics_output = get_metrics(port).await;
        assert!(metrics_output.contains("kms_operation_duration_ms"));
        assert!(metrics_output.contains("operation=\"test_op\""));
        assert!(metrics_output.contains("test_tag=\"test_value\""));
    }

    #[tokio::test]
    async fn test_size_histogram() {
        let (metrics, port) = init_test_metrics().await;

        // Record some sizes
        metrics.observe_size("test_op", 100.0).unwrap();
        metrics.observe_size("test_op", 200.0).unwrap();

        // Wait longer for metrics to be exported
        sleep(Duration::from_millis(500)).await;
        let metrics_output = get_metrics(port).await;
        assert!(metrics_output.contains("kms_payload_size_bytes"));
        assert!(metrics_output.contains("operation=\"test_op\""));
    }

    #[tokio::test]
    async fn test_metric_tags() {
        let (metrics, port) = init_test_metrics().await;

        // Record duration using the timer guard
        {
            let _timer = metrics
                .time_operation("test_op")
                .unwrap()
                .tag("tag1", "value1")
                .unwrap()
                .tag("tag2", "value2")
                .unwrap()
                .start();

            // Simulate some work
            sleep(Duration::from_millis(100)).await;
        }

        // Wait longer for metrics to be exported
        sleep(Duration::from_millis(500)).await;
        let metrics_output = get_metrics(port).await;
        assert!(metrics_output.contains("tag1=\"value1\""));
        assert!(metrics_output.contains("tag2=\"value2\""));
    }

    #[tokio::test]
    async fn test_invalid_metric_names() {
        let (metrics, _) = init_test_metrics().await;

        // Test empty operation name
        assert!(metrics.increment_request_counter("").is_err());

        // Test empty tag key
        let result = metrics
            .time_operation("test_op")
            .unwrap()
            .tag("", "value")
            .unwrap_err();
        assert!(matches!(result, MetricError::InvalidTag(_)));
    }

    #[tokio::test]
    async fn test_gauge() {
        sleep(Duration::from_millis(1000)).await;
        let (metrics, port) = init_test_metrics().await;

        metrics.gauge("test_op", 32).unwrap();

        // Wait longer for metrics to be exported
        sleep(Duration::from_millis(500)).await;
        let metrics_output = get_metrics(port).await;
        assert!(metrics_output.contains("kms_gauge"));
        assert!(metrics_output.contains("operation=\"test_op\""));
        assert!(metrics_output.contains("32"));
    }
}
