fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .bytes(".ddec_networking.SendValueRequest")
        .compile_protos(&["protos/gnetworking.proto"], &["protos"])?;
    Ok(())
}
