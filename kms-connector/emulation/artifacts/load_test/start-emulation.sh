#!/bin/bash

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "This script is designed for macOS only"
    exit 1
fi

# Check for required commands
if ! command_exists anvil; then
    echo "Error: anvil command not found. Please install Foundry."
    exit 1
fi

# Change to the project root directory
cd "$(dirname "$0")/../.." || exit 1

# Check if config file exists
if [ ! -f "artifacts/load_test/emul-config.toml" ]; then
    echo "Error: emul-config.toml not found in emulation directory"
    exit 1
fi

# Kill any existing anvil processes
pkill anvil 2>/dev/null || true

# Function to create a new terminal window and run a command
create_terminal() {
    local title=$1
    local command=$2
    osascript - <<EOF
tell application "Terminal"
    do script "clear; printf '\\\033]0;$title\\\007'; cd '$(pwd)'; $command"
    activate
end tell
EOF
}

echo "Starting Anvil node..."
create_terminal "Anvil Node" "anvil --block-time 0.25"

# Wait for anvil to start
echo "Waiting for Anvil to start..."
sleep 5

echo "Starting Mock Events..."
create_terminal "Mock Events" "RUST_LOG=info cargo run --bin mock-load"

# Wait for contract deployment
echo "Waiting for contract deployment..."
sleep 5

echo "Starting Mock KMS Core..."
create_terminal "Mock KMS Core" "RUST_LOG=info cargo run --bin mock-core"

# Wait for mock-core to start
echo "Waiting for Mock Core to initialize..."
sleep 3

echo "Starting KMS Connector..."
create_terminal "KMS Connector" 'RUST_LOG=info cargo run --bin kms-connector start -c artifacts/load_test/emul-config.toml'

echo "All components started. Check the terminal windows for output."
