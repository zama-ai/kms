# Threshold cryptography concepts

Threshold cryptography is a part of Multi Party Computation (MPC). The idea is to set up a group of $$n$$ parties, and within this group of parties, to generate a secret key $$sk$$. None of the parties knows $$sk$$, they just individually know a piece of the key $$sk_i$$. With some advanced protocols, $$k$$ parties can collaborate to decrypt a ciphertext (which was previously encrypted with the public key $$pk$$ corresponding to $$sk$$) using their key splits.

Here, $$k$$ is a chosen security parameter, called the threshold: having $$k = n$$ is the most secure choice: all the parties must collaborate to decrypt. However, if one of the parties is offline and do not want to collaborate, the protocol is blocked. So, one often chose a small $$k$$. Obviously, chosing $$k=1$$ is also a very bad choice, since any party can decrypt alone.

More information about MPC are given in [this section](../explanations/threshold_cryptography.md) or in our [Whitepaper](https://github.com/zama-ai/kms-whitepaper/releases/download/2024-09-11_06-45-46/main.pdf).