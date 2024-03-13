use clap::{Parser, Subcommand};
use minijinja::{context, path_loader, Environment};
use std::fs::File;
use std::io::Write;

#[derive(Subcommand, Debug)]
pub enum Command {
    #[clap(name = "cluster")]
    Cluster,
    #[clap(name = "experiment")]
    Experiment,
    #[clap(name = "all")]
    All,
}

#[derive(Parser, Debug)]
#[clap(name = "exp-conf")]
pub struct Cli {
    #[clap(short, default_value = "4")]
    n_parties: usize,

    #[clap(short, default_value = "1")]
    threshold: u8,

    #[clap(short = 'm', long, default_value = "5")]
    number_messages: usize,

    #[clap(short = 'w', long, default_value = "10")]
    witness_dim: u32,

    #[clap(short = 'e', long, default_value = "1")]
    epoch_id: u32,

    #[clap(short = 's', long, default_value = "1")]
    decrypt_setup_mode: u8,

    #[clap(short = 'o', long, default_value = "experiment")]
    experiment_name: String,

    #[clap(short = 'f', long, default_value = "temp")]
    output_folder: String,

    #[clap(short = 'd', long, default_value = "experiments/templates")]
    template_dir: String,

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
    let command = args.command.unwrap_or(Command::All);
    match command {
        Command::Cluster => {
            templates.push(("yml", docker_template));
        }
        Command::Experiment => {
            templates.push(("toml", conf_template));
        }
        Command::All => {
            templates.push(("toml", conf_template));
            templates.push(("yml", docker_template));
        }
    }
    let decrypt_mode = match args.decrypt_setup_mode {
        1 => "PRSSDecrypt",
        2 => "LargeDecrypt",
        _ => panic!("Invalid decrypt setup mode"),
    };

    let context = context!(
        n_parties => args.n_parties,
        threshold => args.threshold,
        number_messages => args.number_messages,
        experiment_name => args.experiment_name,
        witness_dim => args.witness_dim,
        epoch_id => args.epoch_id,
        decrypt_mode => decrypt_mode,
    );
    templates.iter().for_each(|(ty, template)| {
        let output = template.render(context.clone()).unwrap();
        println!(
            "Generating {:?} for {:?} parties with threshold {:?}",
            ty, args.n_parties, args.threshold
        );
        let file_name = format!("{}/{}.{}", args.output_folder, args.experiment_name, ty);
        let mut file = File::create(&file_name).unwrap();
        file.write_all(output.as_bytes()).unwrap();
        println!("Template has been generated. Check ======> {:?}", file_name);
    });
}
