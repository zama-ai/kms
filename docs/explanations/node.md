# KMS node

Each KMS Node is a logical MPC party running the [threshold protocols](../getting-started/concepts.md).
It consists of the following components:
1. KMS Core Service: gRPC service that accepts calls from the [Connector](./connector.md) for operations like decryption, key generation and CRS generation.
2. The Threshold Service: This is the server running the actual MPC protocols, which is communicating directly with the other MPC parties' threshold service. That is, it is a separate service that should not be manually called or triggered.

Using the KMS node the Core service will receive and validate a call and then call directly into the Threshold Service software component and ask it to execute the raw MPC protocols needed. This will make it run a specific MPC protocol with the other nodes' Threshold Services. The result will then be returned to the Core Service which will take care of encrypting/signing and any other kind of packaging before return the result to the external gRPC caller.

For more details on the Connector, consult the KMS Core Service [README](../../core/service/README.md) and the Threshold Service [README](../../core/threshold/README.md). For information on how to interact with a running KMS Core (whether local or a remote deployment) consult the Core Client [README](../../core-client/README.md).