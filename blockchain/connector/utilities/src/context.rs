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
        let output = Command::new("docker")
            .arg("compose")
            .arg("-f")
            .arg(self.file.clone())
            .arg("up")
            .arg("-d")
            .arg("--build")
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
