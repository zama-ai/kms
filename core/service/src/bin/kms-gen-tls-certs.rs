use threshold_fhe::tls_certs;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Majority of this file is in the threshold_fhe packge
    // because it needs to exist independently and cannot be a part of core/service.
    tls_certs::entry_point().await
}
