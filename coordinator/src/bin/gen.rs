use kms_lib::{
    consts::{DEFAULT_CENTRAL_KEY_ID, DEFAULT_CRS_ID, OTHER_CENTRAL_DEFAULT_ID},
    util::key_setup::{
        ensure_central_crs_store_exists, ensure_central_keys_exist,
        ensure_central_server_signing_keys_exist, ensure_dir_exist,
    },
};

// Call write_default_keys from main taking the path from command line argument
#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <path>", args[0]);
        std::process::exit(1);
    }
    let path = &args[1];

    ensure_dir_exist().await;
    ensure_central_server_signing_keys_exist().await;
    ensure_central_keys_exist(path, &DEFAULT_CENTRAL_KEY_ID, &OTHER_CENTRAL_DEFAULT_ID).await;
    ensure_central_crs_store_exists(path, &DEFAULT_CRS_ID).await;

    println!(
        "Default keys written based on parameters stored in {}",
        path
    );
}
