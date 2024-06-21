# Development Environment

The KMS development environment consists of 2 docker compose files which are:

- [**Zama KMS**](./docker-compose-kms.yml): Contains all the components to run a development version of **Zama KMS**.
- [**Zama Gateway**](./docker-compose-gateway.yml): Contains the components to run the **Zama Gateway** which integrates **FHEVM** with **Zama KMS**.

## Dependencies

- **Zama Gateway**: Depends on **FHEVM** and **Gateway KV Store**, which is initialized with the **Zama KMS** docker compose command. Therefore, this is the _last_ docker compose command that should be run.

## Prerequisites

- **Docker 26+** installed on your system.
- **FHEVM** validator running and configured.

## Configure Docker Compose Environment Variables

### Zama Gateway Docker Compose

```yaml
name: zama-gateway

services:

  gateway:
    image: ghcr.io/zama-ai/kms-blockchain-gateway-dev:latest
    command:
      - "gateway"
    environment:
      - GATEWAY__ETHEREUM__LISTENER_TYPE=FHEVM_V1_1
      - GATEWAY__ETHEREUM__WSS_URL=ws://FHEVM_VALIDATOR_HOST:FHEVM_VALIDATOR_PORT
      - GATEWAY__ETHEREUM__FHE_LIB_ADDRESS=000000000000000000000000000000000000005d
      - GATEWAY__ETHEREUM__ORACLE_PREDEPLOY_ADDRESS=c8c9303Cd7F337fab769686B593B87DC3403E0cd
      - GATEWAY__KMS__CONTRACT_ADDRESS=wasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s0phg4d
      - GATEWAY__KMS__ADDRESS=http://localhost:9090
      - GATEWAY__KMS__KEY_ID=04a1aa8ba5e95fb4dc42e06add00b0c2ce3ea424
      - GATEWAY__STORAGE__URL=http://localhost:8088
      - ASC_CONN__BLOCKCHAIN__ADDRESSES=http://localhost:9090
```

**Zama Gateway** requires several specific configurations as shown in the provided `docker-compose-gateway.yml` file.

| Variable | Description | Default Value |
| --- | --- | --- |
| GATEWAY__ETHEREUM__LISTENER_TYPE | Listener type for Ethereum gateway | FHEVM_V1_1 |
| GATEWAY__ETHEREUM__WSS_URL | WebSocket URL for FHEVM Ethereum. You need to run FHEVM first and set this data | ws://FHEVM_VALIDATOR_HOST:FHEVM_VALIDATOR_PORT |
| GATEWAY__ETHEREUM__FHE_LIB_ADDRESS | FHE library address for Ethereum gateway. This should be taken from FHEVM once it is running and configured | 000000000000000000000000000000000000005d |
| GATEWAY__ETHEREUM__ORACLE_PREDEPLOY_ADDRESS | Oracle predeploy contract address for FHEVM gateway | c8c9303Cd7F337fab769686B593B87DC3403E0cd |
| GATEWAY__KMS__ADDRESS | Address for KMS gateway. If you are running the **Zama KMS** docker container on the same machine, it should be `localhost:9090` | http://localhost:9090 |
| GATEWAY__KMS__KEY_ID | Key ID for KMS gateway. Refer to the [How to obtain KMS Key Id](#kms-key-id) section | 04a1aa8ba5e95fb4dc42e06add00b0c2ce3ea424 |
| GATEWAY__STORAGE__URL | URL for storage gateway. If you are running the **Zama KMS** docker container on the same machine, it should be `localhost:8088` | http://KMS-KV-STORE-HOST:KMS-KV-STORE-PORT |
| ASC_CONN__BLOCKCHAIN__ADDRESSES | Blockchain addresses for ASC connection. Same as `GATEWAY__KMS__ADDRESS` | http://localhost:9090 |

## Steps for running

1. Run the **Zama KMS** docker compose

```bash
docker compose -f docker-compose-kms.yml up -d
```

2. Change the configuration of `docker-compose-gateway.yml` according to the [previous section](#zama-gateway-docker-compose).

3. Run the **Zama Gateway** docker compose

```bash
docker compose -f docker-compose-gateway.yml up -d
```

## KMS Key Id

To obtain the `Key Id` to set up in the `GATEWAY__KMS__KEY_ID` environment variable, run the following command:

```bash
> docker run -ti ghcr.io/zama-ai/kms-service-dev:latest ls keys/PUB/PublicKey
04a1aa8ba5e95fb4dc42e06add00b0c2ce3ea424  8e917efb2fe00ebbe8f73b2ba2ed80e7e28970de
```

If there are no fundamental changes, you should see 2 outputs of hex numbers. The first number `04a1aa8ba5e95fb4dc42e06add00b0c2ce3ea424`, which is the default value, is the key id.
