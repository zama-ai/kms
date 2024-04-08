fn main() {
    // #[derive(Eq, Hash, PartialEq)]
    prost_build::Config::new()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(&["proto/transactions.proto"], &["proto"])
        .unwrap();
}
