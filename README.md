# distributed-decryption
[![Rust](https://github.com/zama-ai/distributed-decryption/actions/workflows/rust.yml/badge.svg)](https://github.com/zama-ai/distributed-decryption/actions/workflows/rust.yml)


## Profiling

To profile various protocols, see the `benches/` folder.

Following instructions are for Linux based systems. For individual benches one can run the following:

```sh
cargo bench --bench prep -- --profile-time 60 triple_generation/n=5_t=1_batch=1000
```

To see the flamegraph produced, fire up a terminal and open it with your favorite browser:
```sh
firefox target/criterion/triple_generation/n=5_t=1_batch=1000/profile/flamegraph.svg
```

For MacOS based users run the following:

```sh
cargo flamegraph --root --bench prep -- triple_generation/n=5_t=1_batch=1000
```


## Building Docker image

Building **distributed-decryption** Docker image requires some additional setup, because in latest version of the project there is a dependency to a private Github project. This will require to have the correct **SSH** credentials configured either locally or remotely in the case we are running this on CI/CD phase.

### Local Building

In order to build docker image locally you should have `ssh-agent` running and with your ssh private key added to the authentication agent.

1. Run `ssh-agent`

```bash
> eval $(ssh-agent -c)
```

2. Add your key to the authentication agent. Lets supposed that your private key is under `~/.ssh/my_key`

```bash
> ssh-add ~/.ssh/my_key
> ssh-add -l
```

> NOTE: You can add this lines of codes to your shell interpreter like zsh, bash, fish, etc. in order to not need to run these steps on each new session.

3. Now you are ready to build docker image with the following command:

```bash
> docker build --ssh default -t ddec .
```

### CI/CD Building

TO BE DEFINED

## Text below is outdated...

To run a 10 party benchmark for distributed decryption on a local network run the following:

```sh
docker build -t ddec .
cd experiments/10
docker compose up
```

By default the docker images run a distributed decryption with session id equal
to 1. To collect statistics about timings on different parties run the
following:

```sh
docker exec -it 10-choreo-1 bash
RUST_LOG=info mobygo -n 4 results --session-id 1
```

## Simulating Docker Network Setting

To simulate a certain network connection on all containers run the following (replace `wan.sh` with the desired network below):
```sh
# configure network on all running containers
./operations/docker/scripts/runinallcontainers.sh ./operations/docker/scripts/wan.sh
# verify that ping latency has changed as desired
docker exec distributed-decryption-p1-1 ping distributed-decryption-p2-1
```

The following networks are simulated using `tc`:

| Network Config  | Script | Latency | Bandwidth |
| --- | --- | --- | --- |
| None  | `off.sh`  | none  | no limit  |
| WAN  | `wan.sh`  | 50 ms  | 100 Mbit/s  |
| 1 Gbps LAN  | `lan1.sh`  | 0.5 ms  | 1 Gbit/s  |
| 10 Gbps LAN  | `lan10.sh`  | 0.5 ms  | 10 Gbit/s  |

Note that ping RTT will be 2x the latency from the table, when the network config is set on all nodes.

## Networking (gRPC) Benchmarks
gRPC Benchmarking requires to setup a whole network inside a docker compose orchestator. This disable the possibility to integrate this kind of benchmarks with `Criterion` inside `cargo bench` running command.

In order to bypass this limitation we have automate this `gRPC` benchmarks using `cargo-make` utility. This implies the following new components to easily spawn different benchmarks configurations:

- `src/bin/benches/gen-experiment.rs`: This new binary allows us to dynamically create a new experiment setup on the fly. A new experiment will contain `docker-compose.yml` file based on some command line parameters with the setup of the network topology (parties) plus the configuration file `conf.toml` for `mobygo` command in order to know how to execute that experiment. See `cargo run --bin gen-experiment --features="templating" -- --help`.
- `cargo-make`: With cargo make we are orchestating all the command line chain in order to
  1. Run `cargo run --bin gen-experiment ...` to generate the desired experiment with the desired amount of parties
  2. Start docker compose generated in step 1.
  3. Run `cargo run --bin mobygo ... ` choreographer in order to **init, decrypt and gather results** based on the desired configuration.
  4. Finally stop docker compose started in step 2.

### Prerequisites for running benchmarks

- Install [cargo-make](https://github.com/sagiegurari/cargo-make?tab=readme-ov-file#installation).

### Configuration files
Depending on the experiment, command line parameters injected to choreographer can be set using configuration file. Inside `Makefile.toml` file, it can be seen how those experiments are generated.

```toml
[tasks.grpc-bench-4-1-10-prss]
env = { "NUM_PARTIES" = "4", "THRESHOLD" = "1", "NUM_MESSAGES" = "10", "PROTOCOL" = "1", EXPERIMENT_NAME = "bench-p4_t1_msg10_prss" }
run_task = { name = ["grpc-bench"] }
description = "4 parties, 1 threshold, 10 messages, PRSS"
```

Therefore if you want to create a new experiment just copy and paste this task, rename it and change the environment variables values to the desired experiment setup.


### Run all benchmarks

```bash
> cargo make run-grpc-benchmarks
```

### New configuration
If you want to write a new configuration to test specific parameter set, just do the following:

1. Create a new task inside `Makefile.toml`. You can be based on any of the existing experiment

```toml
[tasks.my-task-name]
env = { "NUM_PARTIES" = "4", "THRESHOLD" = "1", "NUM_MESSAGES" = "10", "PROTOCOL" = "1", EXPERIMENT_NAME = "my-experiment-name" }
run_task = { name = ["grpc-bench"] }
description = "my experiment description"
```

2. Now just run the experiment.

```bash
> cargo make my-task-name
```

> NOTE: Perhaps you need to rebuild the docker image used by the experiment. You can do it just running `cargo make docker-image`

## AWS Benchmarks

Here is how to reproduce the benchmarks for the distributed decryption paper.

Benchmarks in the paper were run on an AWS `m6i.metal` instance.

1. Clone the repository and check out the right branch to be benchmarked.
2. Build the docker image: `sudo docker build -t ddec .`
3. Choose which setting (number of workers) to run from `experiments/`. It is possible to spin up more workers than actually benchmarked, e.g., you can benchmark on only 4 parties while 40 workers are available.
Change directory to the desired setting, e.g.: `cd distributed-decryption/experiments/40`.
4. Start the workers: `sudo docker-compose up -d`
5. Set up the network connection between the containers as described above.
6. Find the id of the `choreo` container: `sudo docker container ls`
7. Start a bash on the `choreo` container, e.g., `sudo docker exec -it f2667e5f5665 bash` (replace `f2667e5f5665` with the actual id of `choreo` from above). (In some versions of docker it might be possible to just call `docker exec -it 40-choreo-1 bash`, without figuring out the id).
8. From the choreo bash start running a benchmark on the workers, using the desired parameters. Note that session 1 is automatically run when the container is started, so pick a higher number:

    ```sh
    mobygo -n 10 launch --session-id 100 -t 3 --circuit-path ./circuits/ddec-1-plaintext-1/ddec.flamin --session-range 50
    ```
    Multiple runs with different parameters can be put in a shell script that calls `mobygo` several times in a row.

9. Collect the results with the corresponding session ids. By default party 1 does the reconstruction, so we provided the average numbers for party 1 in the paper. You can collect and print more parties' runtimes by providing a higher `-n` parameter.
    ```sh
    mobygo -n 1 results --session-id 100 --session-range 50
    ```
10. Assume you have collected benchmark results in a file called `results.txt`, you can copy it from docker to the AWS machine using:
`sudo docker cp f2667e5f5665:usr/src/ddec/results.txt .`
Otherwise the results will be gone when you stop the containers.
