# Core threshold protocols 
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


## CI/CD Building

Check documentation [here](./doc/ci.md)


## Benchmarks with real network
Benchmarking with a real network requires to set up said network inside a docker compose orchestrator. This prevents integrating this kind of benchmarks with `Criterion` inside `cargo bench` running command.

In order to bypass this limitation we have automated this `gRPC` benchmarks using `cargo-make` utility. 

### Prerequisites for running benchmarks

- Install [cargo-make](https://github.com/sagiegurari/cargo-make?tab=readme-ov-file#installation).

### Generate experiment
To create configuration files, we use a binary located in `src/bin/benches/gen-experiment.rs`.
This binary dynamically creates a new experiment setup on the fly. An experiment is composed of a `.yml` file that describes the parties (and telemetry) configuration, and a `.toml` configuration file for the choreographer (`mobygo` or `stairwayctl`) with the network topology of the parties. See `cargo run --bin gen-experiment --features="templating" -- --help`.

### Parties
The MPC parties are run by executing the mobygo binary from `src/bin/moby/mobygo.rs`.
We use the same mobygo source file for both `BGV` and `TFHE`, the difference is set via feature flags:
- For TFHE, compile mobygo with either no feature or **--features testing** (to allow for centralised key generation)
- For BGV, compile mobygo with **--features experimental,testing**.

We thus have two possible docker images which we can be build, one for `TFHE` and one for `BGV`.

TFHE image can be built via
```sh
cargo make tfhe-docker-image 
```

BGV image can be built via
```sh
cargo make bgv-docker-image 
```

### Choreographer
To interact with the MPC parties, we use a choreographer called `moby` from `src/bin/moby/moby.rs` for `TFHE`, and `stairwayctl` from `src/experimental/bin/stairwayctl.rs` for `BGV`.

In both cases, the choreographer allows to :
- Initiate the PRSSs
- Create preprocessing (for Distributed Key Generation in both cases and Distributed Decryption for `TFHE`)
- Initiate Distributed Key Generation 
- Initiate Distributed Decryption
- Initiate CRS Ceremony (for `TFHE` only)
- Retrieve results for the above
- Check status of a task

For a list of the available commands, run: 
```sh
./moby --help 
```

And for information on a specific command, run:
```sh
./moby command --help 
```

(Works also with `stairwayctl`)

### Pre-defined commands 
With `cargo make` we have pre-defined commands to run experiments for both `TFHE` and `BGV`. 

NOTE: Commands prefixed with `tfhe-` can be replaced by `bgv-`to execute experiment for `BGV` instead of `TFHE`

First generate the certificates, say for 5 MPC parties:
```sh
cargo make --env NUM_PARTIES=5 gen-test-certs 
```

Then create the `.yml` and `.toml` files for the experiment:
```sh
cargo make --env NUM_PARTIES=5 --env THRESHOLD=1 --env EXPERIMENT_NAME=my_experiment tfhe-gen-experiment 
```

Finally, run the parties:
```sh
cargo make --env EXPERIMENT_NAME=my_experiment start-parties 
```

It is now possible to interact with the cluster of parties with the `mobygo` choreographer by using the generated `.toml` file:
```sh
./mobygo -c temp/my_experiment.toml my-command 
```

Once done, we can shut down the parties with:
```sh
cargo make --env EXPERIMENT_NAME=my_experiment stop-parties 
```


We also provide one-liner benches, which can be run directly after the certificate generations.

Either with a *fake* centralised key generation
```sh
cargo make tfhe-bench-fake-dkg 
```
Or with a real key generation (which takes much longer)
```sh
cargo make tfhe-bench-real-dkg 
```

These benchmarks run the scripts located in the `test_scripts` folder.

**NOTE**: The docker container also runs telemetry tools, therefore when running experiments, all telemetry data are exported to [jaeger](http://localhost:16686) as well as locally exported in an opentelemetry json file in `temp/telemetry`.


### Simulating Docker Network Setting

To simulate a certain network connection on all containers run the following (replace `wan.sh` with the desired network below):
```sh
# configure network on all running containers
./operations/docker/scripts/runinallcontainers.sh ./operations/docker/scripts/wan.sh
# verify that ping latency has changed as desired
docker exec tfhe-core-p1-1 ping tfhe-core--p2-1
```

The following networks are simulated using `tc`:

| Network Config  | Script | Latency | Bandwidth |
| --- | --- | --- | --- |
| None  | `off.sh`  | none  | no limit  |
| WAN  | `wan.sh`  | 50 ms  | 100 Mbit/s  |
| 1 Gbps LAN  | `lan1.sh`  | 0.5 ms  | 1 Gbit/s  |
| 10 Gbps LAN  | `lan10.sh`  | 0.5 ms  | 10 Gbit/s  |

Note that ping RTT will be 2x the latency from the table, when the network config is set on all nodes.

## Testing
Integration tests are located in the `tests` folder and require a `Redis` server to be running locally. Make sure to install `Redis`and run `redis-server` in a separate terminal before running these tests.