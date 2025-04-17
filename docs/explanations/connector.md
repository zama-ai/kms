# KMS connector

The role of the connector is to make the link between the fhevm Gateway and the MPC nodes.
Basically it is a service that will on the same machine as each of the MPC nodes and it will listen for KMS events coming from the fhevm Gateway.
It will pick up these events and forward them to the KMS Core via a gRPC call (see [here for more details](../guides/entry_points.md)).
The connector will then poll the KMS Core via gRPC until the result from the request is ready, at which point it will make transaction with the result and post this to the fhevm Gateway.

Thus the Connector basically is the link between the smart contracts on the fhevm Gateway and the gRPC endpoints on the KMS Cores. Furthermore since it is run on the same machine as each of the KMS Cores it means the gRPC endpoints on the cores will be closed to requests from a network and thus that only the Connector facilitates calls. But the Connector only facilitates calls that have been validated by the fhevm Gateway, and hence the underlying security comes from the policies and the deployment of the fhevm Gateway. At least when using the Zama KMS in the solution deployed by ZWS.

For more details on the Connector, consult it's [README](https://github.com/zama-ai/kms-connector).
