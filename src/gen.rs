// Call write_default_keys from main taking the path from command line argument
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <path>", args[0]);
        std::process::exit(1);
    }
    let path = &args[1];
    kms_lib::write_default_keys(path);
    println!("Keys written to {}", path);
}
