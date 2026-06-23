fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Map SendValueRequest's `bytes` fields to `bytes::Bytes` instead of the
    // default `Vec<u8>`, so the payload can be cloned/encoded on the send path
    // without copying. Scoped to SendValueRequest so other messages
    // (e.g. HealthCheckRequest) keep their existing `Vec<u8>` representation.
    tonic_prost_build::configure()
        .bytes(".ddec_networking.SendValueRequest.tag")
        .bytes(".ddec_networking.SendValueRequest.value")
        .compile_protos(&["protos/gnetworking.proto"], &["protos"])?;
    Ok(())
}
