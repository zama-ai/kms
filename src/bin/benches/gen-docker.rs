use clap::Parser;
use minijinja::{context, path_loader, Environment};
use std::fs::File;
use std::io::Write;

#[derive(Parser, Debug)]
#[clap(name = "docker-benches")]
pub struct Cli {
    #[clap(short, default_value = "4")]
    n_parties: usize,

    #[clap(short, default_value = "1")]
    threshold: u8,

    #[clap(short = 'f', long, default_value = "temp/experiment.yml")]
    docker_file: String,

    #[clap(
        short = 'd',
        long,
        default_value = "operations/docker/benches/templates"
    )]
    template_dir: String,
}

fn create_env(template_dir: &str) -> Environment<'static> {
    let mut env = Environment::new();
    env.set_loader(path_loader(template_dir));
    env
}

fn main() {
    let args = Cli::parse();

    let env = create_env(&args.template_dir);
    let template = env.get_template("experiment.yml.j2").unwrap();
    let output = template
        .render(context!(n_parties => args.n_parties, threshold => args.threshold))
        .unwrap();
    println!(
        "Generating docker compose for {:?} parties with threshold {:?}",
        args.n_parties, args.threshold
    );
    let mut file = File::create(&args.docker_file).unwrap();
    file.write_all(output.as_bytes()).unwrap();
    println!(
        "docker compose has been generated. Check ======> {:?}",
        args.docker_file
    );
}
