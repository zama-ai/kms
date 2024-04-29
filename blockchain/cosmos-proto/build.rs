fn main() -> Result<(), Box<dyn std::error::Error>> {
    let files = glob::glob("protos/**/*.proto")
        .unwrap()
        .collect::<Result<Vec<_>, _>>()?;
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .out_dir("src/messages")
        .include_file("mod.rs")
        .compile(files.as_slice(), &["protos"])?;
    Ok(())
}
