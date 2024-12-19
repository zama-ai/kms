fn main() -> Result<(), Box<dyn std::error::Error>> {
    let files = glob::glob("protos/**/*.proto")
        .unwrap()
        .collect::<Result<Vec<_>, _>>()?;
    let mut config = prost_build::Config::new();
    config.enable_type_names();
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .out_dir("src/messages")
        .include_file("mod.rs")
        .compile_protos_with_config(config, files.as_slice(), &["protos"])?;
    Ok(())
}
