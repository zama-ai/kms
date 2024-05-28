# Rust Contract Execution Tool

This Rust tool allows you to execute and query smart contracts. It provides a command-line interface (CLI) for interacting with a blockchain network.

## Prerequisites

- Rust (ensure you have Rust installed on your system)
- A running blockchain node (e.g., Cosmos, Ethereum, etc.)
- Configuration file (optional, specify with `-f` flag)

## Usage

1. Clone this repository and navigate to the project directory.
2. Build the project using `cargo build`.
3. Run the tool with the desired command:

### Execute Contract

```bash
$ cargo run -- execute-contract -m <path_to_json_file>
```

- `-m` or `--file-stdin`: Specify the input file (use - for `stdin`).

### Query Contract

```bash
$ cargo run -- query-contract -t <txn_id> -p <proof> -o <operation>
```

- `-t` or `--txn-id`: Transaction ID for querying. This is output by previous command `execute-contract` if the command was successfully executed.
- `-p` or `--proof`: Proof of transaction validity. Same as Transaction ID
- `-o` or `--operation`: Specify the operation (e.g., `decrypt_response`, `keygen_response`, etc. See [KmsOperation](../events/kms.rs)).

### Configuration

You can provide additional configuration options via a configuration file (if needed). Use the `-f` flag to specify the path to the configuration file. In that file you will configure the addresses of validators, contract address to interact with and mnemonic wallet.

An example of configuration file can be found ![here](./config/default.toml)

### Examples

#### Execute a contract:

```bash
$ cargo run -- execute-contract -m decrypt.json
```

where `decrypt.json` should contain the message to the send to the ASC.

> See [example_input.json](./example_input.json)


#### Query a contract:

```bash
$ cargo run -- query-contract -t TXN_ID -p PROOF -o OPERATION
```


