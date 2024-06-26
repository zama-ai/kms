use std::env;
use std::io::Write;
use std::process::Command;

#[derive(Clone)]
pub struct DockerComposeCmd {
    file: String,
}

impl DockerComposeCmd {
    pub fn new(file: &str) -> DockerComposeCmd {
        DockerComposeCmd {
            file: file.to_string(),
        }
    }

    pub fn up(&self) {
        let skip_build_docker = env::var("DOCKER_SKIP_BUILD").unwrap_or("".to_string());
        let mut build = Command::new("docker");
        build
            .arg("compose")
            .arg("-f")
            .arg(self.file.clone())
            .arg("up")
            .arg("-d");
        if skip_build_docker.is_empty() {
            build.arg("--build");
        }
        let output = build
            .arg("--wait")
            .output()
            .expect("Failed to execute command");
        std::io::stdout().write_all(&output.stdout).unwrap();
    }

    pub fn down(&self) {
        let output = Command::new("docker")
            .arg("compose")
            .arg("-f")
            .arg(self.file.clone())
            .arg("down")
            .arg("--volumes")
            .arg("--remove-orphans")
            .output()
            .expect("Failed to execute command");
        std::io::stdout().write_all(&output.stdout).unwrap();
    }
}

pub struct DockerCompose {
    cmd: DockerComposeCmd,
}

impl DockerCompose {
    pub fn new(file: &str) -> DockerCompose {
        let cmd = DockerComposeCmd::new(file);
        cmd.up();
        DockerCompose { cmd }
    }
}

impl Drop for DockerCompose {
    fn drop(&mut self) {
        self.cmd.down();
    }
}
