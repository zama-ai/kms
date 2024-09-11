# Roadmap

- [ ] Add the following features to the client:
  - Decrypt(ciphertext)
  - Re-encrypt(ciphertext, pub_key)
    - Document how the keys for re-encryption should be generated
- [ ] Properly parametrize the faucet/genesis to have an almost infinite gas source. At the moment the base wallet only has enough for one decryption in the centralized case
- [x] Support threshold in docker compose
- [x] Support centralized in docker compose
- [x] Support Encrypt-decrypt
- [ ] Support Encrypt-re-encrypt
- [ ] Support keygen
- [ ] Get the address of the contract based on key-id
- [ ] Get key-id based on contract address
- [ ] Get services configuration automatically from BC
- [ ] Check that everything crashes properly if improperly setup
