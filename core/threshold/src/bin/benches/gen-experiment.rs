use clap::{Args, Parser, Subcommand, ValueEnum};
use minijinja::{context, path_loader, Environment};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::fs::File;
use std::io::Write;

#[derive(Subcommand, Debug)]
pub enum Command {
    #[clap(name = "parties")]
    Parties(ProtocolArg),
    #[clap(name = "choreographer")]
    Choreographer,
    #[clap(name = "all")]
    All(ProtocolArg),
}

#[derive(Clone, Debug, Serialize, Deserialize, ValueEnum)]
pub enum Protocol {
    BGV,
    TFHE,
}

impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::BGV => write!(f, "bgv"),
            Protocol::TFHE => write!(f, "tfhe"),
        }
    }
}

#[derive(Clone, Args, Debug)]
pub struct ProtocolArg {
    #[clap(long, value_enum)]
    protocol: Protocol,
}

#[derive(Parser, Debug)]
#[clap(name = "exp-conf")]
pub struct Cli {
    #[clap(short, default_value = "4")]
    n_parties: usize,

    #[clap(short, default_value = "1")]
    threshold: u8,

    #[clap(short = 'w', long, default_value = "10")]
    witness_dim: u32,

    #[clap(short = 'o', long, default_value = "experiment")]
    experiment_name: String,

    #[clap(short = 'f', long, default_value = "temp")]
    output_folder: String,

    #[clap(short = 'd', long, default_value = "experiments/templates")]
    template_dir: String,

    #[clap(short = 's', long, default_value = "secure")]
    moby_strategy: String,

    #[clap(subcommand)]
    command: Option<Command>,
}

fn create_env(template_dir: &str) -> Environment<'static> {
    let mut env = Environment::new();
    env.set_loader(path_loader(template_dir));
    env
}

fn main() {
    let args = Cli::parse();

    let env = create_env(&args.template_dir);
    let conf_template = env.get_template("conf.toml.j2").unwrap();
    let docker_template = env.get_template("docker-compose.yml.j2").unwrap();
    let mut templates = vec![];
    let command = args.command.unwrap_or(Command::All(ProtocolArg {
        protocol: Protocol::TFHE,
    }));
    let protocol = match command {
        Command::Parties(protocol) => {
            templates.push(("yml", docker_template));
            protocol.protocol.to_string()
        }
        Command::Choreographer => {
            templates.push(("toml", conf_template));
            "".to_string()
        }
        Command::All(protocol) => {
            templates.push(("toml", conf_template));
            templates.push(("yml", docker_template));
            protocol.protocol.to_string()
        }
    };

    let image_degree = (args.n_parties as f64).log2().floor() as u32 + 1;
    let image_name = match protocol.as_str() {
        "bgv" => "bgv-core".to_string(),
        "tfhe" => format!("tfhe-core-degree-{image_degree}"),
        _ => panic!("Unsupported protocol: {protocol}"),
    };

    let context = context!(
        n_parties => args.n_parties,
        threshold => args.threshold,
        experiment_name => args.experiment_name,
        witness_dim => args.witness_dim,
        image_name => image_name,
        moby_strategy => args.moby_strategy,
    );

    // Create the directory (if not exists) that will be used for experiment files
    std::fs::create_dir_all(&args.output_folder).unwrap();

    templates.iter().for_each(|(ty, template)| {
        let output = template.render(context.clone()).unwrap();
        println!(
            "Generating {:?} for {:?} parties with threshold {:?}",
            ty, args.n_parties, args.threshold
        );
        let file_name = format!("{}/{}.{}", args.output_folder, args.experiment_name, ty);
        let mut file = File::create(&file_name).unwrap();
        file.write_all(output.as_bytes()).unwrap();
        println!("Template has been generated. Check ======> {file_name:?}");
    });
}
