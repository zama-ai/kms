#!/bin/bash
sudo docker run -v ./config-mobygo.toml:/app/ddec/config.toml -v ./small_test_params.json:/app/ddec/parameters/small_test_params.json -v ./temp:/app/ddec/temp -e RUST_LOG=info -ti ghcr.io/zama-ai/ddec mobygo -c ./config.toml init
