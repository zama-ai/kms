use threshold_networking::tls_certs;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tls_certs::entry_point().await
}
