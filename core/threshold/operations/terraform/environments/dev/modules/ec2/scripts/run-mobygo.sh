#!/bin/bash
mkdir -p /home/ec2-user/temp

docker run -v `pwd`/config.toml:/app/ddec/config.toml -v `pwd`/small_test_params.json:/app/ddec/parameters/small_test_params.json -v `pwd`/temp:/app/ddec/temp -e RUST_LOG=info -ti ghcr.io/zama-ai/ddec mobygo -c /app/ddec/config.toml $1

