# KMS main entry points

The Zama KMS can basically be used for:
- FHE key generation
- Generation of key switching keys
- Decryption (both publicly and privately to a specific user)
- CRS (powers-of-tau) generation

Soon, it will also be possible to do:
- Key Resharing


In the [access](#different-ways-to-access-the-zama-kms) section we go through the different abstraction levels that can be utilized to use the Zama KMS.
[Afterwards]() we go through the detailed commands that can be executed using the Zama KMS.

## Different ways to access the Zama KMS

There are multiple ways to use the Zama KMS, each requiring different amounts of external infrastructure running:
- Interacting with an EVM L1 host chain (with contracts that emit events that gets ported to the fhevm Gateway).
- By using the Connector with the Arbitrum Gateway L2 blockchain. Consult the [fhevm Gateway](https://github.com/zama-ai/gateway-l2) repository for details.
- Through the CLI Core Client. See the [CLI Core Client README](../../core-client/README.md) for further details.
- Directly through the gRPC endpoints on each server instance. See the [API section](../../core/grpc/README.md) for detail.

We now go through each of these in more detail.

### L1 host chain interaction
To use the Zama KMS through an L1 host chain, it requires both the L1 contracts, the fhevm Gateway, an Oracle, Relayer and Coprocessor running. Furthermore, interaction using the host chain only allows _implicit_ usage of the Zama KMS, as actual queries for setup and key generation has to be done through the fhevm Gateway. Hence, the host chain only facilitates computation (using the coprocessor) and decryption using the Zama KMS.
In practice we don't expect people to launch this setup directly, but instead use the setup facilitating host chain interaction provided by ZWS. Even so, using the Zama KMS through the ZWS setup requires the launching of application contracts on Ethereum, along with setup calls done to the fhevm Gateway. Thus this solution is only possible for registered partners of Zama that has been approved through by the fhevm Gateway governance. End-users of FHE may instead use solutions provided by Zama's partners directly. Some relevant resources for further information on this include [Inco](https://www.inco.org/), [Fhenix](https://www.fhenix.io/) or [Shiba Inu's treat token](https://shib.io/tokens/treat).
For further technical details, see [this repo](https://github.com/zama-ai/fhevm).

### fhevm Gateway blockchain
To use the Zama KMS through the fhevm Gateway requires both the Zama KMS system, the fhevm Gateway running and Coprocessor running. While interaction using the fhevm Gateway allows close to direct usage of the Zama KMS, it should be observed that the ZWS hosted solution for this is meant to integrate with Ethereum and a Coprocessor, hence its usefulness may become rather limited unless contracts are customized.
In practice we don't expect developers to launch this setup directly, or if they do, make a fork of the fhevm Gateway contracts and host their own customized setup. Instead, we expect the main usage to come through an application on the host chain as mentioned above, or through a forked and self-hosted setup of the fhevm Gateway contracts.
End-users could interact directly with the fhevm Gateway for certain operations (e.g. user decryption), the same is true for administrators of apps who could directly interact with the fhevm Gateway to do CRS and key management, including key generation.

### gRPC interaction
The main entry point into the Zama KMS is through the gRPC endpoints on the KMS Core. These endpoints allow indiscriminate usage of the Zama KMS. That is, there is no validations in checks to validate that the caller are allowed to issue these calls. That is, anyone who is able to make calls to the decryption endpoint on all the cores can get a decryption executed. That is, any kind of access restriction and key management logic have to have already been carried out _before_  the possibility to call the gRPC endpoint.
In the ZWS deployment, this logic is carried out in the fhevm Gateway, which emits events if requests are validated. These are picked up by a Connector on _each_ KMS Core, which then forwards the request to gRPC endpoint on a local KMS Core. That is, each Connector and Core run on the same physical machine and hence the gRPC endpoints on the Core are only _locally_ accessible. Thus calls _have_ to be validated by the fhevm Gateway before they can be executed (unless one controls more thant t of the Core servers).

As a developer this is probably the entry point you would want to use into the Zama KMS. Both because it only requires deployment of the $$n$$ KMS Cores but also because it is very easy to issue commands to, yet, from an operations perspective, it is easy to limit the access. Using the gRPC endpoints on the Zama KMS also makes testing and debugging easy since it only requires the KMS Core running and allow to make custom calls in a simple manner.

Still, if deploying the KMS Core purely as a gRPC service it is _essential_ to ensure that gRPC calls can _only_ be made _after_ any access control and request validation has been carried out, e.g. as discussed above.

While ZWS offers a setup of the Zama KMS, it is also possible to host this yourself. In fact, it is possible to use the host chain and fhevm Gateway setup _with_ your own hosted instance of the Zama KMS. In fact the contracts on the fhevm Gateway are constructed to make this extremely easy, and hence ensure that the key manage never leaves your control.
Still, observe that even hosting your own setup of the Zama KMS requires not only running $$n$$ instances of the KMS Core, but also the $$n$$ instances of the KMS Connector, Redis database, along with $$n$$ S3 buckets (although a local filesystem can be used instead of S3).

## Zama KMS abstract commands
Below we go through the commands that can be executed at the Zama KMS gRPC endpoint. To access these using the gRPC endpoints we refer to the [API](../references/api/core_grpc.md) specification and for information on how try to run the server see [here on-perm installation](./on_prem_installation.md) and [here for SaaS usage](./saas_usage.md) and consult the [CLI Core Client README](../../core-client/README.md) for information on how to try to issue these commands locally.

### Preprocessing
Preprocessing is needed to generate correlated randomness which is used later, when you generate a FHE key set, or a Key Switching Key (KSK). Preprocessed material can only be used _once_ and hence needs to be generated every time you wish to generate an FHE key set.
Calls to preprocessing requires key parameters, the specification of a unique `RequestId`, which is a 32-byte hex string. In case of the generation of a KSK the `RequestId` of the existing keys which the switching key needs to be from and to.

Observe the preprocessed material is stored in Redis database in a deployed situation (although running a test setup the data can be stored in RAM).

Observe that preprocessing is at a low abstraction level, hence it can only be found at the gRPC interface. I.e. if using the fhevm Gateway, there will be no such endpoint. Instead the key generation on the fhevm Gateway will ensure sufficient calls to the KMS Cores are made to preprocess the needed material.

For non-test parameters this process is very slow. Even on strong machines it will take several hours, maybe even up to a day.

### Key generation
Key generation allows the generation of an FHE key set, or public KSK. To do key generation, preprocessing must have been done beforehand and not used before.
The key generation requires a unique `RequestId`, which is a 32-byte hex string
request, the key parameters, EIP712 domain information (used by the servers for signing the response), the `RequestId` of the preprocessing to used, which _must_ be unused and already generated. Furthermore, it _must_ have been generated for the same parameters as used in the key generation call. Finally, the request _may_ also include the `RequestId`s of keys to generate a KSK from and to (again it is required the preprocessing has been carried out for this as well).

The KMS Cores will post the result of the key generation to a public storage system, which may be the local file system or an S3 bucket. While a signed digests of the public key material is returned to the caller.

The key generation process is slow and may take a couple of hours, even when running on strong machines.

#### Insecure mode
To support a fast setup in test situations, the Zama KMS supports an "insecure" mode for key generation, where preprocessing is not required and where the key generation itself only takes a few seconds. However, as the name suggests, this mode is _not_ threshold secure. I.e. it should only be used for testing purposes.

### CRS generation
CRS generation allows the generation of a Common Reference String (CRS) in a distributed secure manner. The CRS is what is known as "powers-of-tau". Amongst other things, it can be used to do zero-knowledge proofs of plaintext knowledge for FHE encrypted messages. See [this paper](https://eprint.iacr.org/2023/800.pdf) for more information.
While a CRS is not directly linked to a public key, it must be generated based on parameters of the public keys used to encrypt the messages for which is will be used for proof of knowledge.

The CRS generation requires  a unique `RequestId`, which is a 32-byte hex string
request, the key parameters for the public keys which it will be used with, the max amount of plaintext bits of the messages encrypted that it will be used with and finally EIP712 domain information (used by the servers for signing the response).

The KMS Cores will post the result of the CRS generation to a public storage system, which may be the local file system or an S3 bucket. While a signed digest of the CRS is returned to the caller.

The CRS generation process is moderately slow. It may take several minutes to complete.

## Public Decryption
Public decryption allows decryption of a vector of ciphertexts in such a manner that all KMS Core servers along with the caller of the request learns the decrypted value in plain, along with EIP712 signatures on the result from each of the $$n$$ KMS Cores servers.

The decryption request requires a unique `RequestId`, which is a 32-byte hex string
request, an ID of the key needed to decrypt (this will be the `RequestId` used to generate the key), the address of the smart contract used that may be used to validate the request, EIP712 domain information (used by the servers for signing the response) along with the vector of ciphertexts to be decrypted and meta information about each of these. The meta information incudes what kind of plain value they are encrypting (e.g. uint8 or uint32), along with an optional handle used to identify each ciphertext externally.

The public decryption process is very fast and should be expected to be done within a few seconds at the most.

## User Decryption
User decryption allows decryption of a vector of ciphertexts in such a manner that _only_ a designated receiver can learn the decrypted value in plain. This means that neither the caller, nor the KMS Cores learn the decrypted value. This is achieved by each KMS Core only "partially" decrypted the ciphertext and then signcrypting it under the public encryption key of a designated receiver. This allows the receiving user to decrypt and validate all the $$n$$ partial decryptions and then combine the partial decryptions to the true plaintext.

The user decryption request requires a unique `RequestId`, which is a 32-byte hex string
request, an ID of the key needed to decrypt (this will be the `RequestId` used to generate the key), EIP712 domain information (used by the servers for signing the response) along with the vector of ciphertexts to be decrypted and meta information about each of these. The meta information incudes what kind of plain value they are encrypting (e.g. uint8 or uint32).

The user decryption process is very fast and should be expected to be done within a few seconds at the most.

## Key reshare

Key resharing allow each of MPC parties holding a share of a private FHE key to "refresh" these shares. More specifically it means that the pseudorandom values that each party hold, which when combined constitute the secret FHE key, change, but with the public key remaining the same. This also means, that if the parties were to reconstruct the private key it would also be the same. Hence this should _not_ be mistaken for key rolling or key rotation.
However, performing this procedure has the advantage of making the old secret key shares obsolete. So if at most $$t$$ of the MPC parties have been compromised and an adversary has learned their private key shares, it means that the adversary only needs one more key share to be able to reconstruct the real secret key.
However if the parties at this point complete a resharing, and delete their old shares, then the stolen secret shares the adversary holds will become worthless. That is, the adversary would have to corrupt $$t$$ parties to get back to the situation he was in before.

Besides handling localized compromises, the resharing can also be used for failure recovery. Say at most $$t$$ of the MPC servers have lost their secret key shares, then they could participate with the rest of the MPC servers in the key refreshing protocol in order for them to get new private key shares.

This features is coming soon....