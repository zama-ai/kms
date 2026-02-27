use std::env;
use std::fmt;
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

pub struct DockerComposeCmd {
    pub root_path: PathBuf,
    pub mode: KMSMode,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum KMSMode {
    ThresholdDefaultParameter,
    ThresholdTestParameter,
    ThresholdTestParameterNoInit,
    ThresholdTestParameterNoInitSixParty,
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

fn port_is_bindable(port: u16) -> bool {
    TcpListener::bind(("0.0.0.0", port)).is_ok()
}

/// Wait until all given TCP ports on localhost are no longer bound.
/// This prevents "address already in use" errors when Docker Compose retries
/// start before the OS has released ports from the previous run.
///
/// All ports are checked in every iteration so that a single slow-to-free port
/// cannot consume the entire deadline before the others are even checked.
/// Each iteration probes all ports in parallel via threads.
fn wait_for_ports_free(ports: &[u16], timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let all_free = std::thread::scope(|s| {
            let handles: Vec<_> = ports
                .iter()
                .map(|&port| s.spawn(move || port_is_bindable(port)))
                .collect();
            handles.into_iter().all(|h| h.join().unwrap_or(false))
        });
        if all_free {
            return;
        }
        if Instant::now() >= deadline {
            let still_bound: Vec<u16> = ports
                .iter()
                .copied()
                .filter(|&p| !port_is_bindable(p))
                .collect();
            panic!(
                "Timed out waiting for ports to be released after {:?}. Still bound: {:?}",
                timeout, still_bound
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
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

    const fn ports_for_mode(mode: KMSMode) -> &'static [u16] {
        match mode {
            KMSMode::ThresholdTestParameterNoInitSixParty => &[
                50100, 50200, 50300, 50400, 50500, 50600, 50001, 50002, 50003, 50004, 50005, 50006,
            ],
            KMSMode::ThresholdDefaultParameter
            | KMSMode::ThresholdTestParameter
            | KMSMode::ThresholdTestParameterNoInit
            | KMSMode::ThresholdCustodianTestParameter => {
                &[50100, 50200, 50300, 50400, 50001, 50002, 50003, 50004]
            }
            KMSMode::Centralized | KMSMode::CentralizedCustodian => &[50100],
        }
    }

    pub fn up(&self) {
        self.down(); // Make sure that no container is running
                     // Wait for the OS to release ports before starting new containers.
                     // Without this, Docker Compose retries fail with "address already in use".
        wait_for_ports_free(Self::ports_for_mode(self.mode), Duration::from_secs(30));
        let build_docker = env::var("DOCKER_BUILD_TEST_CORE_CLIENT").unwrap_or("".to_string());

        // set the FHE params based on mode
        match self.mode {
            KMSMode::ThresholdDefaultParameter
            | KMSMode::Centralized
            | KMSMode::CentralizedCustodian => {
                env::set_var("CORE_CLIENT__FHE_PARAMS", "Default");
            }
            KMSMode::ThresholdTestParameter
            | KMSMode::ThresholdTestParameterNoInit
            | KMSMode::ThresholdTestParameterNoInitSixParty
            | KMSMode::ThresholdCustodianTestParameter => {
                env::set_var("CORE_CLIENT__FHE_PARAMS", "Test");
            }
        }

        // build the docker compose command
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
            KMSMode::ThresholdTestParameterNoInit => {
                build.arg("docker-compose-core-threshold.yml");
                build.env("KMS_DOCKER_EMPTY_PEERLIST", "true");
            }
            // six party variant used for testing context switching and resharing
            // basically it will support two sets of 4 party threshold networks
            // where there is an overlap of two partyes (parties 3 and 4) that are in both networks
            KMSMode::ThresholdTestParameterNoInitSixParty => {
                build.arg("docker-compose-core-threshold-6.yml");
                build.env("KMS_DOCKER_EMPTY_PEERLIST", "true");
            }
            KMSMode::ThresholdCustodianTestParameter => {
                build.arg("docker-compose-core-threshold.yml");
                build.env("KMS_DOCKER_BACKUP_SECRET_SHARING", "true");
            }
            KMSMode::CentralizedCustodian => {
                build.arg("docker-compose-core-centralized.yml");
                build.env("KMS_DOCKER_BACKUP_SECRET_SHARING", "true");
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
                KMSMode::ThresholdDefaultParameter
                | KMSMode::ThresholdTestParameter
                | KMSMode::ThresholdTestParameterNoInit
                | KMSMode::ThresholdCustodianTestParameter => {
                    docker_logs.arg("docker-compose-core-threshold.yml");
                }
                KMSMode::ThresholdTestParameterNoInitSixParty => {
                    docker_logs.arg("docker-compose-core-threshold-6.yml");
                }
                KMSMode::CentralizedCustodian | KMSMode::Centralized => {
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
                KMSMode::ThresholdDefaultParameter
                | KMSMode::ThresholdTestParameter
                | KMSMode::ThresholdTestParameterNoInit
                | KMSMode::ThresholdCustodianTestParameter => {
                    docker_down.arg("docker-compose-core-threshold.yml");
                }
                KMSMode::ThresholdTestParameterNoInitSixParty => {
                    docker_down.arg("docker-compose-core-threshold-6.yml");
                }
                KMSMode::Centralized | KMSMode::CentralizedCustodian => {
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
        let cmd = DockerComposeCmd::new(mode);
        cmd.up();
        DockerCompose { cmd, mode }
    }
}

impl Drop for DockerCompose {
    fn drop(&mut self) {
        self.cmd.down();
    }
}
