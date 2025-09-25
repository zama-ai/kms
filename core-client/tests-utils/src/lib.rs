use std::env;
use std::fmt;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output};

pub struct DockerComposeCmd {
    pub root_path: PathBuf,
    pub mode: KMSMode,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum KMSMode {
    ThresholdDefaultParameter,
    ThresholdTestParameter,
    ThresholdCustodianTestParameter,
    Centralized,
    CentralizedCustodian,
}

// Wrapper struct for Output
pub struct OutputWrapper<'a>(&'a Output);

impl fmt::Display for OutputWrapper<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stdout = String::from_utf8_lossy(&self.0.stdout);
        let stderr = String::from_utf8_lossy(&self.0.stderr);
        write!(
            f,
            "Status: {}\nStdout: {}\nStderr: {}",
            self.0.status, stdout, stderr
        )
    }
}

// Helper function to create the wrapper
pub fn format_output(output: &Output) -> OutputWrapper<'_> {
    OutputWrapper(output)
}

impl DockerComposeCmd {
    pub fn new(mode: KMSMode) -> Self {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
        let err_parent_msg = "Failed to get parent directory";
        let root_path = PathBuf::from(manifest_dir)
            .parent()
            .expect(err_parent_msg)
            .to_path_buf();
        DockerComposeCmd { root_path, mode }
    }

    pub fn up(&self) {
        self.down(); // Make sure that no container is running
        let build_docker = env::var("DOCKER_BUILD_TEST_CORE_CLIENT").unwrap_or("".to_string());
        if let KMSMode::ThresholdTestParameter = self.mode {
            env::set_var("CORE_CLIENT__FHE_PARAMS", "Test");
        } else {
            env::set_var("CORE_CLIENT__FHE_PARAMS", "Default");
        }

        let mut build = Command::new("docker");
        build
            .current_dir(self.root_path.clone())
            .arg("compose")
            .arg("-f")
            .arg("docker-compose-core-base.yml")
            .arg("-f");

        match self.mode {
            KMSMode::ThresholdDefaultParameter | KMSMode::ThresholdTestParameter => {
                build.arg("docker-compose-core-threshold.yml");
            }
            KMSMode::ThresholdCustodianTestParameter => {
                build.arg("docker-compose-core-threshold-custodian.yml");
            }
            KMSMode::CentralizedCustodian => {
                build.arg("docker-compose-core-centralized-custodian.yml");
            }
            KMSMode::Centralized => {
                build.arg("docker-compose-core-centralized.yml");
            }
        }

        build.arg("up").arg("-d");

        if build_docker == "1" {
            build.arg("--build");
        }

        build.arg("--wait");
        println!("{build:?}");

        match build.spawn() {
            Err(error) => {
                self.down();
                panic!("Failed to execute docker compose up command: {error}");
            }
            Ok(mut p) => match p.wait() {
                Err(error) => {
                    self.down();
                    panic!("Failed to execute docker compose up command: {error}");
                }
                Ok(status) => {
                    if !status.success() {
                        self.down();
                        panic!(
                            "Docker compose failed to start. Command: {build:?}\nStatus: {status:?}\nSee output above.\n"
                        );
                    } else {
                        println!("Successfully launched command: {build:?}");
                    }
                }
            },
        };
    }

    pub fn down(&self) {
        {
            let mut docker_logs = Command::new("docker");
            docker_logs
                .current_dir(self.root_path.clone())
                .arg("compose")
                .arg("-f")
                .arg("docker-compose-core-base.yml")
                .arg("-f");
            match self.mode {
                KMSMode::ThresholdDefaultParameter | KMSMode::ThresholdTestParameter => {
                    docker_logs.arg("docker-compose-core-threshold.yml");
                }
                KMSMode::ThresholdCustodianTestParameter => {
                    docker_logs.arg("docker-compose-core-threshold-custodian.yml");
                }
                KMSMode::CentralizedCustodian => {
                    docker_logs.arg("docker-compose-core-centralized-custodian.yml");
                }
                KMSMode::Centralized => {
                    docker_logs.arg("docker-compose-core-centralized.yml");
                }
            }

            docker_logs.arg("logs");
            let docker_logs_output = docker_logs
                .output()
                .expect("Failed to fetch docker compose logs");
            std::io::stdout()
                .write_all(&docker_logs_output.stdout)
                .unwrap();
        }

        {
            let mut docker_down = Command::new("docker");
            docker_down
                .current_dir(self.root_path.clone())
                .arg("compose")
                .arg("-f")
                .arg("docker-compose-core-base.yml")
                .arg("-f");
            match self.mode {
                KMSMode::ThresholdDefaultParameter | KMSMode::ThresholdTestParameter => {
                    docker_down.arg("docker-compose-core-threshold.yml");
                }
                KMSMode::ThresholdCustodianTestParameter => {
                    docker_down.arg("docker-compose-core-threshold-custodian.yml");
                }
                KMSMode::CentralizedCustodian => {
                    docker_down.arg("docker-compose-core-centralized-custodian.yml");
                }
                KMSMode::Centralized => {
                    docker_down.arg("docker-compose-core-centralized.yml");
                }
            }
            docker_down
                .arg("down")
                .arg("--volumes")
                .arg("--remove-orphans");

            let docker_down_output = docker_down
                .output()
                .expect("Failed to execute docker compose down command");

            std::io::stdout()
                .write_all(&docker_down_output.stdout)
                .unwrap();
            // We don't really care if this finalize correctly
        }
    }
}

pub struct DockerCompose {
    pub cmd: DockerComposeCmd,
    pub mode: KMSMode,
}

impl DockerCompose {
    pub fn new(mode: KMSMode) -> DockerCompose {
        let cmd = DockerComposeCmd::new(mode.clone());
        cmd.up();
        DockerCompose { cmd, mode }
    }
}

impl Drop for DockerCompose {
    fn drop(&mut self) {
        self.cmd.down();
    }
}
