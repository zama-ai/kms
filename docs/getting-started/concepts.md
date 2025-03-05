# Threshold cryptography concepts

Threshold cryptography is a specific part of secure Multi Party Computation (MPC), where public or private key cryptography systems are developed s.t. the secret key can be cryptographically shared between multiple parties, s.t. a threshold of these parties need to collaborate to use the key, or gain any information about the true value of the secret key.
Concretely, in a group of $n$ parties collaborate to create a public and private key pair $pk, sk$ where each party has a share of $sk$ denoted $sk_i$ s.t. $sk$ never exists in plain at any party. Furthermore, the system is specified by a parameter $t<n$ denoted the _threshold_, s.t. more than $t$ parties are required to use their shares in order to decrypt.

While there exists multiple flavours of threshold cryptography and MPC in general, the flavour we employ in the Zama KMS offers very high security and _robustness_ guarantees. More specifically, key generation and decryption will succeed even if at most $t$ of the parties are offline or chose to act _malicious_, by running malicious code and hence not follow the prescribed protocol.

Still, to achieve such strong security the Zama KMS requires $t<n/3$, hence the smallest amount of servers requires to achieve $t>0$ is 4, that is the protocols requires a _strong honest majority_.

More information about MPC is given in our [Whitepaper](https://github.com/zama-ai/kms-whitepaper/), whereas the theoretical and academic details on our protocols can be found in the paper [Noah's Ark: Efficient Threshold-FHE Using Noise Flooding](https://eprint.iacr.org/2023/815) published at WAHC 2023.