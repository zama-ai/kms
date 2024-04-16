//! CLI tool for interacting with a group of flamins
use clap::Parser;
use distributed_decryption::execution::constants::REAL_PARAM_PATH;
use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
use distributed_decryption::file_handling::read_as_json;
use distributed_decryption::session_id::SessionId;
use distributed_decryption::{
    choreography::{choreographer::ChoreoRuntime, parse_session_config_file_with_computation},
    execution::runtime::session::DecryptionMode,
};
use ndarray::Array1;
use ndarray_stats::QuantileExt;
use std::path::PathBuf;
use tfhe::{prelude::FheEncrypt, FheUint64};

#[derive(Parser, Debug)]
#[clap(name = "flamingo")]
#[clap(about = "A simple CLI tool for interacting with a Flamin cluster")]
pub struct Cli {
    /// Session config file to use
    session_config: PathBuf,

    #[clap(long, default_value_t = 1)]
    /// Session range to use
    session_range: u32,

    #[clap(long, default_value_t = 1)]
    /// Key epoch id
    epoch: u128,

    #[clap(long, default_value_t = 10)]
    /// L (big LWE key dimension)
    ell: u32,

    #[clap(long, default_value_t = 5)]
    /// message to encrypt
    msg: u64,

    #[clap(long, default_value_t = 4)]
    /// message to encrypt
    plaintext_bits: u8,

    #[clap(long)]
    /// Directory to read certificates from
    certs: Option<String>,

    #[clap(long)]
    /// Own identity; `certs` must be specified
    identity: Option<String>,

    #[clap(long)]
    results: bool,

    #[clap(long)]
    no_keygen: bool,
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    tracing_subscriber::fmt::init();

    let tls_config = None;

    let (role_assignments, threshold) =
        parse_session_config_file_with_computation(&args.session_config)?;
    let runtime = ChoreoRuntime::new(role_assignments, tls_config)?;

    let pk = if args.no_keygen {
        // retrieve previously generated pubkey
        runtime
            .initiate_retrieve_pubkey(&SessionId::from(args.epoch))
            .await?
    } else {
        // set keys. this can be done once per epoch
        // TODO allow for non-default parameters
        let default_params: NoiseFloodParameters = read_as_json(REAL_PARAM_PATH.to_string())?;
        runtime
            .initiate_keygen(&SessionId::from(args.epoch), threshold, default_params)
            .await?
    };
    let (ct, _id) = FheUint64::encrypt(args.msg, &pk).into_raw_parts();
    let session_id = SessionId::new(&ct)?;
    for _i in 0..args.session_range {
        runtime
            .initiate_threshold_decryption(&DecryptionMode::PRSSDecrypt, threshold, &ct)
            .await?;
    }

    if args.results {
        let res = runtime
            .initiate_retrieve_results(&session_id, args.session_range)
            .await?;

        // collect results as microseconds for precision and convert to milliseconds for readability
        if let Some(elapsed_times) = res.elapsed_times {
            for (role, p_online_times) in elapsed_times {
                let micros = Array1::from_vec(
                    p_online_times
                        .iter()
                        .map(|x| x.as_micros() as f64 / 1000.0)
                        .collect(),
                );

                // print results als milliseconds
                tracing::info!(
                    "Party {role}: Online times of {} iterations in milliseconds: Mean: {:.2} - Median: {:.2} - Min: {:.2} - Max: {:.2} - StdDev: {:.2};",
                    args.session_range,
                    micros.mean().unwrap(),
                    *micros.mapv(|x| (x * 1000.0) as u128).quantile_axis_mut(
                        ndarray::Axis(0),
                        noisy_float::types::n64(0.5),
                        &ndarray_stats::interpolate::Midpoint,
                    )?.first().unwrap() as f64 / 1000.0,
                    micros.min()?,
                    micros.max()?,
                    micros.std(0.0),
                );
            }
        }

        tracing::info!("Decryption Results: {:?}", res.outputs);
    }

    Ok(())
}
