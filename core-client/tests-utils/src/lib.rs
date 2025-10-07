use std::env;
use std::fmt;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

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

/// A struct that represents a Kubernetes test context.
///
/// This struct contains the necessary fields to interact with a Kubernetes cluster.
/// It provides methods to check if pods are ready and to get pod logs.
pub struct KubernetesCmd {
    pub mode: KMSMode,
    pub root_path: PathBuf,
}

impl KubernetesCmd {
    pub fn new(mode: KMSMode) -> Self {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
        let err_parent_msg = "Failed to get parent directory";
        let root_path = PathBuf::from(manifest_dir)
            .parent()
            .expect(err_parent_msg)
            .to_path_buf();
        KubernetesCmd { mode, root_path }
    }

    pub fn up(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Create a Kubernetes client
        eprintln!(
            "Setup kube context {}",
            std::env::var("KUBE_CONTEXT").unwrap()
        );
        let kubeconfig = std::env::var("KUBECONFIG").unwrap();

        // Check if kubeconfig file exists
        if !std::path::Path::new(&kubeconfig).exists() {
            eprintln!("Error: KUBECONFIG file does not exist at: {}", kubeconfig);
            return Err("KUBECONFIG file does not exist".into());
        }

        eprintln!("Using kubeconfig from: {}", kubeconfig);

        // List all contexts to debug
        let kubectl_context = Command::new("kubectl")
            .args(["config", "view", "-o", "jsonpath='{.contexts[*].name}'"])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .output()?;

        eprintln!(
            "Available contexts: {:?}",
            String::from_utf8_lossy(&kubectl_context.stdout)
        );

        if !kubectl_context.status.success() {
            eprintln!(
                "Error getting contexts: {}",
                String::from_utf8_lossy(&kubectl_context.stderr)
            );
            return Err("Failed to list kubectl contexts".into());
        }

        let _kubectl_context = Command::new("kubectl")
            .args([
                "config",
                "use-context",
                &std::env::var("KUBE_CONTEXT").unwrap(),
                "--kubeconfig",
                &std::env::var("KUBECONFIG").unwrap(),
            ])
            .stdout(Stdio::inherit()) // Show stdout in real-time
            .stderr(Stdio::inherit()) // Show stderr in real-time
            .output()?;

        if !_kubectl_context.status.success() {
            return Err("Failed to set kubectl context".into());
        }

        eprintln!("Setup namespace {}", std::env::var("NAMESPACE").unwrap());
        let _namespaces = Command::new("kubectl")
            .args(["get", "namespace", &std::env::var("NAMESPACE").unwrap()])
            .stdout(Stdio::inherit()) // Show stdout in real-time
            .stderr(Stdio::inherit()) // Show stderr in real-time
            .output()?;

        // if _namespaces.status.success() {
        //     Command::new("kubectl")
        //         .args(["delete", "namespace", &std::env::var("NAMESPACE").unwrap()])
        //         .stdout(Stdio::inherit()) // Show stdout in real-time
        //         .stderr(Stdio::inherit()) // Show stderr in real-time
        //         .output()?;
        // } else {
        //     Command::new("kubectl")
        //         .args(["create", "namespace", &std::env::var("NAMESPACE").unwrap()])
        //         .stdout(Stdio::inherit()) // Show stdout in real-time
        //         .stderr(Stdio::inherit()) // Show stderr in real-time
        //         .output()?;
        // }
        // 2. Add Helm repo if needed
        eprintln!("Adding MinIO Helm repo");
        let repo_add_minio = Command::new("helm")
            .args(["repo", "add", "minio", "https://charts.min.io/"])
            .stdout(Stdio::inherit()) // Show stdout in real-time
            .stderr(Stdio::inherit()) // Show stderr in real-time
            .output()?;

        if !repo_add_minio.status.success() {
            let stderr = String::from_utf8_lossy(&repo_add_minio.stderr);
            println!("Error: Failed to add MinIO Helm repo: {}", stderr);
        }

        // 3. Update Helm repos
        let repo_update = Command::new("helm").args(["repo", "update"]).output()?;

        if !repo_update.status.success() {
            let stderr = String::from_utf8_lossy(&repo_update.stderr);
            println!("Error: Failed to update Helm repos: {}", stderr);
        }

        // 4. Install/upgrade the Helm chart
        eprintln!("Installing MinIO");
        let minio_install = Command::new("helm")
            .args([
                "upgrade",
                "--install",
                "minio",
                "minio/minio",
                "--namespace",
                &std::env::var("NAMESPACE").unwrap(),
                "--create-namespace",
                "--wait",
                "-f",
                self.root_path
                    .join(std::env::var("MINIO_VALUES_FILE").unwrap())
                    .to_str()
                    .unwrap(),
            ])
            .stdout(Stdio::inherit()) // Show stdout in real-time
            .stderr(Stdio::inherit()) // Show stderr in real-time
            .output();

        let output = match minio_install {
            Ok(output) => output,
            Err(e) => {
                println!("Error executing command: {}", e);
                return Err(Box::new(e));
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!("Command failed with error: {}", stderr);
            return Err(format!("Command failed: {}", stderr).into());
        }

        let kubectl_get_pods = Command::new("kubectl")
            .args([
                "get",
                "pods",
                "--namespace",
                &std::env::var("NAMESPACE").unwrap(),
            ])
            .stdout(Stdio::inherit()) // Show stdout in real-time
            .stderr(Stdio::inherit()) // Show stderr in real-time
            .output();

        eprintln!(
            "Available pods: {:?}",
            String::from_utf8_lossy(&kubectl_get_pods.unwrap().stdout)
        );

        eprintln!("Installing KMS");
        let (_values_file, kms_nb_pod) = match self.mode {
            KMSMode::ThresholdDefaultParameter | KMSMode::ThresholdTestParameter => {
                (&std::env::var("KMS_THRESHOLD_VALUES_FILE").unwrap(), 4)
            }
            KMSMode::ThresholdCustodianTestParameter => (
                &std::env::var("KMS_THRESHOLD_CUSTODIAN_VALUES_FILE").unwrap(),
                4,
            ),
            KMSMode::CentralizedCustodian => (
                &std::env::var("KMS_CENTRALIZED_CUSTODIAN_VALUES_FILE").unwrap(),
                1,
            ),
            KMSMode::Centralized => (&std::env::var("KMS_CENTRALIZED_VALUES_FILE").unwrap(), 1),
        };

        for i in 1..kms_nb_pod {
            let helm_upgrade_kms = Command::new("helm")
                .args([
                    "upgrade",
                    "--install",
                    &std::env::var("KMS_RELEASE_NAME").unwrap(),
                    // "--version",
                    // &std::env::var("KMS_CHART_VERSION").unwrap(),
                    // &std::env::var("KMS_CHART_REGISTRY_URL").unwrap(),
                    self.root_path.join("charts/kms-core").to_str().unwrap(),
                    "--namespace",
                    &std::env::var("NAMESPACE").unwrap(),
                    "--create-namespace",
                    "-f",
                    self.root_path
                        .join("./ci/kube-testing/kms/values-kms-test.yaml")
                        .to_str()
                        .unwrap(),
                    "-f",
                    self.root_path
                        .join(format!(
                            "./ci/kube-testing/kms/values-kms-service-threshold-{}-kms-test.yaml",
                            i
                        ))
                        .to_str()
                        .unwrap(),
                    "--set",
                    "kmsCore.image.tag=v0.12.0",
                    "--set",
                    "kmsCoreClient.image.tag=v0.12.0",
                    "--wait",
                    "--timeout=1200s",
                ])
                .stdout(Stdio::inherit()) // Show stdout in real-time
                .stderr(Stdio::inherit()) // Show stderr in real-time
                .output()?;

            let kubectl_describe_pods = Command::new("kubectl")
                .args([
                    "describe",
                    "pod",
                    &format!("kms-core-{}", i),
                    "--namespace",
                    &std::env::var("NAMESPACE").unwrap(),
                ])
                .stdout(Stdio::inherit()) // Show stdout in real-time
                .stderr(Stdio::inherit()) // Show stderr in real-time
                .output()?;

            eprintln!(
                "Describe pod: {:?}",
                String::from_utf8_lossy(&kubectl_describe_pods.stdout)
            );

            if !helm_upgrade_kms.status.success() {
                let stderr = String::from_utf8_lossy(&helm_upgrade_kms.stderr);
                println!("Error: Failed to install/upgrade Helm chart: {}", stderr);
                self.down();
            }
        }

        eprintln!("Waiting for KMS Core to be ready...");
        for i in 1..kms_nb_pod {
            let _kms_core_wait = Command::new("kubectl")
                .args([
                    "wait",
                    "--for=condition=ready",
                    "pod",
                    &format!("kms-core-{}", i),
                    "-n",
                    &std::env::var("NAMESPACE").unwrap(),
                    "--timeout=600s",
                ])
                .stdout(Stdio::inherit()) // Show stdout in real-time
                .stderr(Stdio::inherit()) // Show stderr in real-time
                .output()?;
        }

        eprintln!("Waiting for KMS Core initialization to complete...");
        let _helm_upgrade_kms_init = Command::new("helm")
            .args([
                "upgrade",
                "--install",
                "kms-core-init",
                // "--version",
                // &std::env::var("KMS_CHART_VERSION").unwrap(),
                // &std::env::var("KMS_CHART_REGISTRY_URL").unwrap(),
                self.root_path.join("charts/kms-core").to_str().unwrap(),
                "--namespace",
                &std::env::var("NAMESPACE").unwrap(),
                "--create-namespace",
                "-f",
                self.root_path
                    .join("./ci/kube-testing/kms/values-kms-service-init-kms-test.yaml")
                    .to_str()
                    .unwrap(),
                "--set",
                "kmsCore.image.tag=v0.12.0",
                "--set",
                "kmsCoreClient.image.tag=v0.12.0",
                "--wait-for-jobs",
                "--timeout=1200s",
            ])
            .stdout(Stdio::inherit()) // Show stdout in real-time
            .stderr(Stdio::inherit()) // Show stderr in real-time
            .output()?;

        eprintln!("Waiting for KMS Core initialization to complete...");
        let _kms_init_wait = Command::new("kubectl")
            .args([
                "wait",
                "--for=condition=complete",
                "job",
                "-l app=kms-threshold-init-job",
                "-n",
                &std::env::var("NAMESPACE").unwrap(),
                "--timeout=600s",
            ])
            .stdout(Stdio::inherit()) // Show stdout in real-time
            .stderr(Stdio::inherit()) // Show stderr in real-time
            .output()?;

        let _helm_upgrade_kms_gen_keys = Command::new("helm")
            .args([
                "upgrade",
                "--install",
                "kms-core-gen-keys",
                // "--version",
                // &std::env::var("KMS_CHART_VERSION").unwrap(),
                // &std::env::var("KMS_CHART_REGISTRY_URL").unwrap(),
                self.root_path.join("charts/kms-core").to_str().unwrap(),
                "--namespace",
                &std::env::var("NAMESPACE").unwrap(),
                "--create-namespace",
                "-f",
                self.root_path
                    .join("./ci/kube-testing/kms/values-kms-service-gen-keys-kms-test.yaml")
                    .to_str()
                    .unwrap(),
                "--set",
                "kmsCore.image.tag=v0.12.0",
                "--set",
                "kmsCoreClient.image.tag=v0.12.0",
                "--wait",
                "--wait-for-jobs",
                "--timeout=2400s",
            ])
            .stdout(Stdio::inherit()) // Show stdout in real-time
            .stderr(Stdio::inherit()) // Show stderr in real-time
            .output()?;

        eprintln!("Waiting for KMS Core gen keys to complete...");
        let _kms_gen_keys_wait = Command::new("kubectl")
            .args([
                "wait",
                "--for=condition=complete",
                "job",
                "-l app=kms-core-client-gen-keys",
                "-n",
                &std::env::var("NAMESPACE").unwrap(),
                "--timeout=600s",
            ])
            .stdout(Stdio::inherit()) // Show stdout in real-time
            .stderr(Stdio::inherit()) // Show stderr in real-time
            .output()?;

        eprintln!("Waiting for job to be complete...");
        let _ = Command::new("kubectl")
            .args([
                "wait",
                "--for=condition=complete",
                "job",
                "-l app=kms-core-client-gen-keys",
                "-n",
                &std::env::var("NAMESPACE").unwrap(),
                "--timeout=600s",
            ])
            .stdout(Stdio::inherit()) // Show stdout in real-time
            .stderr(Stdio::inherit()) // Show stderr in real-time
            .output()?;

        println!("Waiting for pods to be ready...");
        let _ = Command::new("kubectl")
            .args([
                "wait",
                "--for=condition=complete",
                "pod",
                "-l app=kms-core",
                "--namespace",
                &std::env::var("NAMESPACE").unwrap(),
            ])
            .stdout(Stdio::inherit()) // Show stdout in real-time
            .stderr(Stdio::inherit()) // Show stderr in real-time
            .output()?;

        //Kubectl port-forward to access the service
        let _ = Command::new("kubectl")
            .args([
                "port-forward",
                "svc",
                "minio",
                "9000:9000",
                "-n",
                &std::env::var("NAMESPACE").unwrap(),
            ])
            .stdout(Stdio::inherit()) // Show stdout in real-time
            .stderr(Stdio::inherit()) // Show stderr in real-time
            .output()
            .expect("Failed to port-forward Minio");

        for i in 1..kms_nb_pod {
            let _ = Command::new("kubectl")
                .args([
                    "port-forward",
                    "svc",
                    &format!("kms-core-{}", i),
                    &format!("50{}00:50100", i),
                    "-n",
                    &std::env::var("NAMESPACE").unwrap(),
                ])
                .stdout(Stdio::inherit()) // Show stdout in real-time
                .stderr(Stdio::inherit()) // Show stderr in real-time
                .output()
                .expect("Failed to port-forward Minio");
        }

        Ok(())
    }

    pub fn down(&self) {
        // Uninstall the Helm release
        // ======================================================================
        // LOG COLLECTION
        // ======================================================================
        let kms_nb_pod = match self.mode {
            KMSMode::ThresholdDefaultParameter
            | KMSMode::ThresholdTestParameter
            | KMSMode::ThresholdCustodianTestParameter => 4,
            KMSMode::CentralizedCustodian | KMSMode::Centralized => 1,
        };

        println!("Collecting logs from KMS Core pods before uninstalling...");
        for i in 1..kms_nb_pod {
            println!("Collecting logs from KMS Core pod {}", i);
            let pod_name = format!(
                "kms-service-threshold-{}-{}-core-{}",
                i,
                &std::env::var("PATH_SUFFIX").unwrap(),
                i
            );
            let log_file = format!("kms-core-{}-logs.txt", i);
            // Get pod logs and save to file
            if Command::new("kubectl")
                .args([
                    "get",
                    "pod",
                    &pod_name,
                    "-n",
                    &std::env::var("NAMESPACE").unwrap(),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .expect("Failed to check pod existence")
                .status
                .success()
            {
                let kubernetes_logs_output = Command::new("kubectl")
                    .args([
                        "logs",
                        &pod_name,
                        "-c",
                        "kms-core",
                        "-n",
                        &std::env::var("NAMESPACE").unwrap(),
                    ])
                    .output()
                    .expect("Failed to get pod logs");

                // Write logs to file
                let mut file = std::fs::File::create(&log_file).expect("Failed to create log file");
                file.write_all(&kubernetes_logs_output.stdout)
                    .expect("Failed to write logs to file");

                // Also write to stdout
                std::io::stdout()
                    .write_all(&kubernetes_logs_output.stdout)
                    .expect("Failed to write logs to stdout");

                println!("  ✅ Logs saved to {}", log_file);
            } else {
                println!("  ⚠️ Pod {} not found, skipping log collection", pod_name);
                std::fs::File::create(&log_file).expect("Failed to create log file");
            }
        }

        let helm_uninstall = Command::new("helm")
            .args([
                "uninstall",
                &std::env::var("KMS_RELEASE_NAME").unwrap(),
                "--namespace",
                &std::env::var("NAMESPACE").unwrap(),
            ])
            .stdout(Stdio::inherit()) // Show stdout in real-time
            .stderr(Stdio::inherit()) // Show stderr in real-time
            .output()
            .expect("Failed to uninstall Helm release");

        if !helm_uninstall.status.success() {
            println!(
                "Warning: Failed to uninstall {} Helm release: {}",
                &std::env::var("KMS_RELEASE_NAME").unwrap(),
                String::from_utf8_lossy(&helm_uninstall.stderr)
            );
        }

        let helm_uninstall_minio = Command::new("helm")
            .args([
                "uninstall",
                "minio",
                "--namespace",
                &std::env::var("NAMESPACE").unwrap(),
            ])
            .stdout(Stdio::inherit()) // Show stdout in real-time
            .stderr(Stdio::inherit()) // Show stderr in real-time
            .output()
            .expect("Failed to uninstall MinIO Helm release");

        if !helm_uninstall_minio.status.success() {
            println!(
                "Warning: Failed to uninstall MinIO Helm release: {}",
                String::from_utf8_lossy(&helm_uninstall_minio.stderr)
            );
        }

        // Optionally, delete the namespace
        // Be careful with this in shared environments
        let delete_ns = Command::new("kubectl")
            .args(["delete", "namespace", &std::env::var("NAMESPACE").unwrap()])
            .stdout(Stdio::inherit()) // Show stdout in real-time
            .stderr(Stdio::inherit()) // Show stderr in real-time
            .output()
            .expect("Failed to delete namespace");

        if !delete_ns.status.success() {
            println!(
                "Warning: Failed to delete namespace: {}",
                String::from_utf8_lossy(&delete_ns.stderr)
            );
        }
    }
}

pub struct Kubernetes {
    pub cmd: KubernetesCmd,
    pub mode: KMSMode,
}

impl Kubernetes {
    pub fn new(mode: KMSMode) -> Result<Self, Box<dyn std::error::Error>> {
        let cmd = KubernetesCmd::new(mode.clone());
        cmd.up()?; // This will return early if up() fails
        Ok(Kubernetes { cmd, mode })
    }
}

impl Drop for Kubernetes {
    fn drop(&mut self) {
        self.cmd.down();
    }
}
