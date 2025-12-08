#!/bin/bash


# A script, which can be executed with a single command in the
# Baseline Platform (Ubuntu Desktop 24.04.1 LTS),
# to automatically download the needed External Dependencies
# (if applicable), and perform the code compilation required to later execute/test the
# proposed crypto-systems. Teams are encouraged to strive for a script that can obtain
# the External Dependencies with a specific version, in order to favor reproducible
# results (see Inst1). The team may include an additional script designed to use the
# most-up-to-date version of the External Dependencies (which may later lead to non-
# working implementations, absent further adjustments of the Packaged Codebase).

# NOTE: We probably want to set specific versions for everything below ?

set -e

# Update package lists
sudo apt-get update

# Install essential packages
sudo apt-get install -y git protobuf-compiler ca-certificates curl pkg-config openssl libssl-dev gcc


# Add Docker's official GPG key:
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

# Install Docker
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

sudo usermod -aG docker $USER

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Source cargo environment
. "$HOME/.cargo/env"

# Install Cargo make for Benchmark script
cargo install --force cargo-make
# Install cargo-criterion for non-threshold benchmarks
cargo install --force cargo-criterion

# Clone the repository (replace with submission's repo URL)
REPO_URL="https://github.com/zama-ai/kms.git"
TARGET_DIR="$HOME/kms/core/threshold"

if [ ! -d "$TARGET_DIR" ]; then
    cd $HOME
    git clone "$REPO_URL"
else
    echo "Directory $TARGET_DIR already exists. Skipping clone."
fi

cd "$TARGET_DIR"

# NOTE: This makes the script stop
bash NIST_scripts/build.sh
sudo su $USER
