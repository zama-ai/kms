use byteorder::{BigEndian, ByteOrder};
use reqwest::Client;
use sha2::{Digest, Sha256};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "client")]
struct Opt {
    /// Action to perform: "post" or "get"
    #[structopt(short, long)]
    action: String,

    /// Data to post (hex-encoded) or identifier to get
    #[structopt(short, long)]
    data: Option<String>,

    /// url
    #[structopt(short, long, default_value = "http://localhost:8088")]
    url: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();

    // Create an HTTP client
    let client = Client::new();

    match opt.action.as_str() {
        // cargo run --bin kv_store_client -- --action post --data "$(echo -n 'my test data' | xxd -p)"
        "post" => {
            if let Some(data) = opt.data {
                // Decode the hex string to Vec<u8>
                let data_bytes = hex::decode(data).expect("Invalid hex data");

                // Convert the Vec<u8> to a hex string
                let hex_data = hex::encode(&data_bytes);

                // Send the hex-encoded data to the Actix web service
                let response = client
                    .post(format!("{}/store", opt.url))
                    .body(hex_data)
                    .send()
                    .await?;

                // Print the response
                let response_text = response.text().await?;
                println!("Response: {}", response_text);
            } else {
                eprintln!("Data must be provided for POST action.");
            }
        }
        // cargo run --bin kv_store_client -- --action get --data 0000000c8352f5962a8bb52aca2c0eaec8cf56623f7b1dbfd899270a6747b6873a8d429f
        "get" => {
            if let Some(identifier) = opt.data {
                let size_hex = &identifier[..8];
                let hash = &identifier[8..];

                // Decode the size
                let size_bytes = hex::decode(size_hex).unwrap();
                let data_size = BigEndian::read_u32(&size_bytes);
                println!("Data size: {}", data_size);
                // Send a GET request to the Actix web service
                let response = client
                    .get(&format!("{}/store/{}", opt.url, identifier))
                    .send()
                    .await?;

                // Print the response
                let response_text = response.text().await?;
                println!("Response: {}", response_text);
                // Decode the hex response to bytes
                let response_bytes = hex::decode(response_text).expect("Invalid hex data");

                // Convert the bytes to a string
                let response_string =
                    String::from_utf8(response_bytes.clone()).expect("Invalid UTF-8 data");
                println!("Response: {}", response_string);

                println!("Verifying...");
                // verify the size of the data
                assert_eq!(response_bytes.len() as u32, data_size);

                // verify the hash of the data
                let mut hasher = Sha256::new();
                hasher.update(&response_bytes);
                let result = hasher.finalize();
                let hex_hash = hex::encode(result);
                assert_eq!(hash, hex_hash);
                print!("Data size and hash verified successfully.");
            } else {
                eprintln!("Identifier must be provided for GET action.");
            }
        }
        _ => {
            eprintln!("Invalid action. Use 'post' or 'get'.");
        }
    }

    Ok(())
}
