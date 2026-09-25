fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        // Generate `bytes::Bytes` instead of `Vec<u8>` for the payload fields so the
        // sending service can hand the same buffer to every recipient and every
        // retry with a refcount bump instead of a deep copy.
        .bytes(".ddec_networking.SendValueRequest")
        .compile_protos(&["protos/gnetworking.proto"], &["protos"])?;
    Ok(())
}
