use crate::engine::threshold::threshold_kms::ThresholdKms;
use crate::engine::threshold::traits::{
    BackupOperator, ContextManager, CrsGenerator, Initiator, KeyGenPreprocessor, KeyGenerator,
    PublicDecryptor, UserDecryptor,
};
#[cfg(feature = "insecure")]
use crate::engine::threshold::traits::{InsecureCrsGenerator, InsecureKeyGenerator};
use kms_grpc::kms::v1::*;
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpoint;
use tonic::{Request, Response, Status};

macro_rules! impl_endpoint {
    { impl CoreServiceEndpoint $implementations:tt } => {
        #[cfg(not(feature="insecure"))]
        #[tonic::async_trait]
        impl<
                IN: Initiator + Sync + Send + 'static,
                UD: UserDecryptor + Sync + Send + 'static,
                PD: PublicDecryptor + Sync + Send + 'static,
                KG: KeyGenerator + Sync + Send + 'static,
                PP: KeyGenPreprocessor + Sync + Send + 'static,
                CG: CrsGenerator + Sync + Send + 'static,
                CM: ContextManager + Sync + Send + 'static,
                BO: BackupOperator + Sync + Send + 'static,
            > CoreServiceEndpoint for ThresholdKms<IN, UD, PD, KG, PP, CG, CM, BO> $implementations

        #[cfg(feature="insecure")]
        #[tonic::async_trait]
        impl<
                IN: Initiator + Sync + Send + 'static,
                UD: UserDecryptor + Sync + Send + 'static,
                PD: PublicDecryptor + Sync + Send + 'static,
                KG: KeyGenerator + Sync + Send + 'static,
                IKG: InsecureKeyGenerator + Sync + Send + 'static,
                PP: KeyGenPreprocessor + Sync + Send + 'static,
                CG: CrsGenerator + Sync + Send + 'static,
                ICG: InsecureCrsGenerator + Sync + Send + 'static,
                CM: ContextManager + Sync + Send + 'static,
                BO: BackupOperator + Sync + Send + 'static,
            > CoreServiceEndpoint for ThresholdKms<IN, UD, PD, KG, IKG, PP, CG, ICG, CM, BO> $implementations
    }
}

impl_endpoint! {
    impl CoreServiceEndpoint {
        /// Initializes the threshold KMS service.
        /// This involves executing the PRSS protocol to generate secret shared correlated randomness.
        ///
        /// * `request` - Struct containing the request ID, which must be 32 bytes lower-case hex encoding without `0x` prefix.
        ///
        /// # Returns
        /// * Errors:
        ///    - `InvalidArgument` - If the request ID does not match the expected format or missing.
        ///    - `Internal` - An error occured during PRSS generation.
        ///    - `AlreadyExists` - If PRSS already exists. (TODO should we give an option to overwrite?)
        ///
        /// # Conditions
        /// * Pre-condition:
        ///     * `request_id` in `request` must be present, valid, fresh and unique [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
        /// * Post-condition:
        ///     * The `request_id` in `request` has been consumed and the PRSS has been executed successfully.
        async fn init(&self, request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
            self.initiator.init(request).await
        }

        /// Computes the preprocessed material needed for a single key generation.
        /// The method is async in the sense that it returns immediately, but the actual preprocessing is done in the background.
        ///
        /// * `_request` - Struct containing all the data of the request.
        ///
        /// # Returns
        /// * Errors:
        ///    - `InvalidArgument` - If the request is not valid or does not match the expected format.
        ///    - `ResourceExhausted` - If the KMS is currently busy with too many requests.
        ///    - `Aborted` - Other issues unrelated to the preprocessing protocol, e.g., missing PRSS, storage, serialization, etc.
        ///    - `AlreadyExists` - If the request contains a request ID that was previously used.
        ///
        /// # Conditions
        /// * Pre-condition:
        ///     * `request_id` in `request` must be present, valid, fresh and unique [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
        ///     * `params` in `request` must be castable to a [`FheParameter`], currently this means 0 or 1.
        ///     * `keyset_config` in `request` may be set or not. If not set, the default keyset configuration is used.
        ///        If set, it must follow the enum constraints of [`KeySetConfig`].
        ///        I.e. be either `Standard` (0) or `DecompressionOnly` (1).
        ///        Furthermore, if `Standard` is used then `standard_keyset_config` must also be set.
        /// * Post-condition:
        ///     * The `request_id` in `request` has been consumed and the PRSS has been executed successfully.
        #[tracing::instrument(skip(self, request))]
        async fn key_gen_preproc(
            &self,
            request: Request<KeyGenPreprocRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.keygen_preprocessor.key_gen_preproc(request).await
        }

        /// Retrieves the result from a preprocessing request.
        ///
        /// * `request` - The request ID under which the preprocessing was started
        ///               which must be 32 bytes lower-case hex encoding without `0x` prefix.
        ///
        /// # Returns
        /// * `Ok(Response<KeyGenPreprocResult>)` - This is an empty structure.
        ///
        /// * Errors:
        ///   - `InvalidArgument` - If the request ID is not valid or does not match the expected format.
        ///   - `NotFound` - If the preprocessing does not exist for `request`.
        ///   - `Internal` - If the preprocessing failed with an error.
        ///   - `Unavailable` - If the preprocessing is not complete for `request`.
        ///
        /// # Conditions
        /// * Pre-condition:
        ///     * `request` must be a valid [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
        ///                 Furthermore, the request ID must be the same as the one used to start the preprocessing with method `key_gen_preproc`.
        ///                 Finally the parameters used to start preprocessing must have been valid.
        /// * Post-condition:
        ///     * The `request_id` in `request` can be used to retrieve the result of the user decryption again in the future. However there is no guarantee on how long the result will be stored.
        #[tracing::instrument(skip(self, request))]
        async fn get_key_gen_preproc_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<KeyGenPreprocResult>, Status> {
            self.keygen_preprocessor.get_result(request).await
        }

        /// Computes key generation.
        /// The method is async in the sense that it returns immediately, but the actual key generation is done in the background.
        ///
        /// * `request` - Struct containing all the data of the request.
        ///
        /// # Returns
        /// * Errors:
        ///    - `InvalidArgument` - If the request is not valid or does not match the expected format.
        ///    - `ResourceExhausted` - If the KMS is currently busy with too many requests.
        ///    - `Aborted` - Other issues unrelated to the preprocessing protocol, e.g., missing PRSS, storage, serialization, etc.
        ///    - `AlreadyExists` - If the request contains a request ID that was previously used.
        ///    - `NotFound` - If the preprocessing under `preproc_id` does not exist.
        ///
        /// # Conditions
        /// * Pre-condition:
        ///     * `request_id` in `request` must be present, valid, fresh and unique [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
        ///     * `params` in `request` must be castable to a [`FheParameter`], currently this means 0 or 1.
        ///     * `preproc_id` in `request` must be present, and a valid [`RequestId`] which has already been used to start a preprocessing request with method `key_gen_preproc` that has completed successfully
        ///         and has not already been consumed by another key generation request.
        ///     * `domain` in `request` must be set.
        ///     * `keyset_config` in `request` may be set or not. If not set, the default keyset configuration is used. If set, it must follow the enum constraints of [`KeySetConfig`].
        ///         I.e. be either `Standard` (0) or `DecompressionOnly` (1). Furthermore, if `Standard` is used then `standard_keyset_config` must also be set.
        ///         Furthermore, `keyset_config` must be set or not set in exactly the same was as it was in the argument for the preprocessing request started with `preproc_id`.
        ///     * `keyset_added_info` in `request` _must_ be set if `keyset_config` is set to `DecompressionOnly`, otherwise it is ignored.
        /// * Post-condition:
        ///     * `request_id` in `request` has been consumed and the key generation has been started in the background using `request_id` as identifier.
        ///     * `preproc_id` in `request` has been consumed and the preprocessing under this ID cannot be used anymore.
        #[tracing::instrument(skip(self, request))]
        async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
            self.key_generator.key_gen(request).await
        }

        /// Retrieves the result from a key generation.
        ///
        /// * `request` - The request ID under which the key generation was started.
        ///
        /// # Returns
        /// * `Ok(Response<KeyGenResult>)` - If the key generation completed successfully for `request`, then this ID will be relayed in `request_id`.
        ///                                - Furthermore, the `key_results` in the response will contain the result information of each relevant public key; e.g. public encryption key, server key, and SnS key.
        ///                                - The [`SignedPubDataHandle`] will be populated s.t. `key_handle` will contain the SHAKE-256 hash of the serialization of the given result.
        ///                                - Similarely the `signature` will contain the regular ECDSA signature of the public decryption result, signed by the KMS' secret signing key.
        ///                                - Finally the `external_signature` will contain the EIP-712 signature of the public decryption result using the `domain` provided in the request.
        /// * Errors:
        ///   - `InvalidArgument` - If the request ID is not valid or does not match the expected format.
        ///   - `NotFound` - If the key generation does not exist for `request`.
        ///   - `Internal` - If the key generation failed with an error.
        ///   - `Unavailable` - If the key generation is not complete for `request`.
        ///
        /// # Conditions
        /// * Pre-condition:
        ///     * `request` must be a valid [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
        ///                 Furthermore, the request ID must be the same as the one used to start the key generation with method `key_gen`.
        ///                 Finally the parameters used to start key generation must have been valid.
        /// * Post-condition:
        ///     * The `request_id` in `request` can be used to retrieve the result of the key generation again in the future. However there is no guarantee on how long the result will be stored.
        #[tracing::instrument(skip(self, request))]
        async fn get_key_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<KeyGenResult>, Status> {
            self.key_generator.get_result(request).await
        }

        /// Computes a user decryption. That is, it decrypts a ciphertext and encrypts the result under a user's public key.
        /// The method is async in the sense that it returns immediately, but the actual decryption is done in the background.
        ///
        /// * `request` - Struct containing all the data of the request.
        ///
        /// # Errors
        ///    - `InvalidArgument` - If the request is not valid or does not match the expected format.
        ///    - `ResourceExhausted` - If the KMS is currently busy with too many requests.
        ///    - `AlreadyExists` - If the request contains a request ID that was previously used.
        ///    - `Aborted` - If an internal error occured in starting the user decryption.
        ///
        /// # Conditions
        /// * Pre-condition:
        ///     * `request_id` in `request` must be present, valid, fresh and unique [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
        ///     * `typed_ciphertexts` in `request` must be a non-empty vector of [`TypedCiphertext`]s, where each ciphertext is a valid ciphertext for the keyset present in the KMS (see below).
        ///                  Observe that the KMS does _not_ check the validity of the ciphertexts!
        ///                  TODO: consider checking these before starting the user decryption protocol.
        ///     * `key_id` in `request` must be present, valid [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
        ///                  Furthermore, it must have been successfully generated by the KMS previous using the `key_gen` or `insecure_key_gen` methods.
        ///                  The `key_id` must also match the one used to encrypt the the ciphertexts in `typed_ciphertexts`.
        ///     * `client_address` in `request` must be the the EIP-55 encoded (blockchain wallet) address of the user requesting the decryption. I.e. including `0x` prefix.
        ///     * `enc_key` in `request` must be the public key of the user requesting the decryption. This must be a bincode (v.1) encoded ML-KEM 512 key.
        ///     * `domain` in `request` _must_ be set. Furthermore, within `domain`, the `verifying_contract` _must_ be set and be distinct from the `client_address`.
        /// * Post-condition:
        ///     * `request_id` in `request` has been consumed and the user decryption has been started in the background using `request_id` as identifier.
        #[tracing::instrument(skip(self, request))]
        async fn user_decrypt(
            &self,
            request: Request<UserDecryptionRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.user_decryptor.user_decrypt(request).await
        }

        /// Retrieves the result from a user decryption.
        ///
        /// * `request` - The request ID under which the user decryption was started.
        ///
        /// # Returns
        /// * `Ok(Response<UserDecryptionResponse>)` - If decryption completed successfully then `signature` will contain the ECDSA signature of the user decryption result, signed by the KMS' secret signing key.
        ///                                          - The `external_signature` will contain the EIP-712 signature of the public decryption result using the `domain` provided in the request.
        ///                                          - The `payload` will always be set and contain the given KMS' contribution to the user dercryption.
        ///
        /// * Errors:
        ///   - `InvalidArgument` - If the request ID is not valid or does not match the expected format.
        ///   - `NotFound` - If the user decryption does not exist for `request`.
        ///   - `Internal` - If the user decryption failed with an error.
        ///   - `Unavailable` - If the user decryption is not complete for `request`.
        ///   - `Aborted` - If an internal error occured in retrieving the user decryption result.
        ///
        /// # Conditions
        /// * Pre-condition:
        ///     * `request` must be a valid [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
        ///                 Furthermore, the request ID must be the same as the one used to start the user decryption with method `user_decrypt`.
        ///                 Finally the parameters used to start user decryption must have been valid, i.e. `user_decrypt` must not have returned an error.
        /// * Post-condition:
        ///     * The `request_id` in `request` can be used to retrieve the result of the user decryption again in the future. However there is no guarantee on how long the result will be stored.
        #[tracing::instrument(skip(self, request))]
        async fn get_user_decryption_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<UserDecryptionResponse>, Status> {
            self.user_decryptor.get_result(request).await
        }

        /// Computes a public decryption. That is, it decrypts a ciphertext and returns the plaintext.
        /// The method is async in the sense that it returns immediately, but the actual decryption is done in the background.
        ///
        /// * `request` - Struct containing all the data of the request.
        ///
        /// # Errors
        ///    - `InvalidArgument` - If the request is not valid or does not match the expected format.
        ///    - `ResourceExhausted` - If the KMS is currently busy with too many requests.
        ///    - `AlreadyExists` - If the request contains a request ID that was previously used.
        ///    - `Aborted` - If an internal error occured in starting the user decryption.
        ///
        /// # Conditions
        /// * Pre-condition:
        ///     * `request_id` in `request` must be present, valid, fresh and unique [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
        ///     * `ciphertexts` in `request` must be a non-empty vector of [`TypedCiphertext`]s, where each ciphertext is a valid ciphertext for the keyset present in the KMS (see below).
        ///                  Observe that the KMS does _not_ check the validity of the ciphertexts!
        ///     * `domain` in `request` _should_ be set. If not present, there there will be no external signature on the result of the public decryption.
        /// * Post-condition:
        ///     * `request_id` in `request` has been consumed and the public decryption has been started in the background using `request_id` as identifier.
        #[tracing::instrument(skip(self, request))]
        async fn public_decrypt(
            &self,
            request: Request<PublicDecryptionRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.decryptor.public_decrypt(request).await
        }

        /// Retrieves the result from a public decryption.
        ///
        /// * `request` - The request ID under which the public decryption was started.
        ///
        /// # Returns
        /// * `Ok(Response<PublicDecryptionResponse>)` - If the public decryption completed successfully then the `signature` will contain the regular ECDSA signature of the public decryption result, signed by the KMS' secret signing key.
        ///                                            - Finally the `payload` will be set and contain result of the public decryption.
        /// * Errors:
        ///   - `InvalidArgument` - If the request ID is not valid or does not match the expected format.
        ///   - `NotFound` - If the public decryption does not exist for `request`.
        ///   - `Internal` - If the public decryption failed with an error.
        ///   - `Unavailable` - If the public decryption is not complete for `request`.
        ///   - `Aborted` - If an internal error occured in retrieving the public decryption result.
        ///
        /// # Conditions
        /// * Pre-condition:
        ///     * `request` must be a valid [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
        ///                 Furthermore, the request ID must be the same as the one used to start the public decryption with method `public_decrypt`.
        ///                 Finally the parameters used to start public decryption must have been valid, i.e. `public_decrypt` must not have returned an error.
        /// * Post-condition:
        ///     * The `request_id` in `request` can be used to retrieve the result of the public decryption again in the future. However there is no guarantee on how long the result will be stored.
        #[tracing::instrument(skip(self, request))]
        async fn get_public_decryption_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<PublicDecryptionResponse>, Status> {
            self.decryptor.get_result(request).await
        }


        /// Computes a CRS generation. That is, it generates a common reference string (CRS) for the KMS.
        /// The method is async in the sense that it returns immediately, but the actual CRS generation is done in the background.
        ///
        /// * `request` - Struct containing all the data of the request.
        ///
        /// # Returns
        /// * Errors:
        ///    - `InvalidArgument` - If the request ID is not present, valid or does not match the expected format.
        ///    - `NotFound` - If the parameters in the request are not valid.
        ///    - `ResourceExhausted` - If the KMS is currently busy with too many requests.
        ///    - `Aborted` - If an internal error occured in starting the crs generation _or_ if an invalid argument was given.
        ///
        /// # Conditions
        /// * Pre-condition:
        ///     * `request_id` in `request` must be present, valid, fresh and unique [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
        ///     * `params` in `request` must be castable to a [`FheParameter`], currently this means 0 or 1.
        ///     * `max_number_bits` is the amount of bits that can be proven for ciphertext vector using the generated CRS. If this is not provided, then it defaults to the maximum supported by the fhevm.
        ///     * `domain` in `request` _should_ be set, if not, then there will be no external signature on the result of the CRS generation.
        /// * Post-condition:
        ///     * `request_id` in `request` has been consumed and the CRS generation has been started in the background using `request_id` as identifier.
        #[tracing::instrument(skip(self, request))]
        async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
            self.crs_generator.crs_gen(request).await
        }

        /// Retrieves the result from a CRS generation.
        ///
        /// * `request` - The request ID under which the CRS generation was started.
        ///
        /// # Returns
        /// * `Ok(Response<CrsGenResult>)` - If the CRS generation completed successfully for `request`, then this ID will be relayed in `request_id`.
        ///                                - Furthermore the `crs_results` [`SignedPubDataHandle`] will be set and `key_handle` will contain the SHAKE-256 hash of the serialization of the CRS result.
        ///                                - Similarely the `signature` will contain the regular ECDSA signature of the CRS result, signed by the KMS' secret signing key,
        ///                                - Finally the `external_signature` will contain the EIP-712 signature of the CRS result using the `domain` provided in the request.
        /// * Errors:
        ///     - `InvalidArgument` - If the request ID is not valid or does not match the expected format.
        ///     - `NotFound` - If the CRS generation does not exist for `request`.
        ///     - `Internal` - If the CRS generation failed with an error.
        ///     - `Unavailable` - If the CRS generation is not complete for `request`, i.e. it is still running in the background.
        ///
        /// # Conditions
        /// * Pre-condition:
        ///     * `request` must be a valid [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
        ///                 Furthermore, the request ID must be the same as the one used to start the CRS generation with method `crs_gen`.
        ///                 Finally the parameters used to start CRS generation must have been valid, i.e. `crs_gen` must not have returned an error.
        /// * Post-condition:
        ///     * The `request_id` in `request` can be used to retrieve the result of the CRS generation again in the future. However there is no guarantee on how long the result will be stored.
        #[tracing::instrument(skip(self, request))]
        async fn get_crs_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<CrsGenResult>, Status> {
            self.crs_generator.get_result(request).await
        }

        /// WARNING: This method is by definition expected to be insecure and should not be used in production.
        ///
        /// Computes an insecure key generation.
        /// The method is async in the sense that it returns immediately, but the actual key generation is done in the background.
        ///
        /// * `request` - Struct containing all the data of the request.
        ///
        /// # Returns
        /// * Errors:
        ///    - `InvalidArgument` - If the request ID is not valid or does not match the expected format.
        ///    - `ResourceExhausted` - If the KMS is currently busy with too many requests.
        ///    - `Aborted` - If an internal error occured in starting the key generation _or_ if an invalid argument was given.
        ///
        /// # Conditions
        /// * Pre-condition:
        ///     * `request_id` in `request` must be present, valid, fresh and unique [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
        ///     * `params` in `request` must be castable to a [`FheParameter`], currently this means 0 or 1.
        ///     * `preproc_id` in `request` must be present, and a valid [`RequestId`] which has already been used to start a preprocessing request with method `key_gen_preproc` that has completed successfully
        ///         and has not already been consumed by another key generation request.
        ///     * `domain` in `request` _should_ be set, if not, then there will be no external signature on the result of the key generation.
        ///     * `keyset_config` in `request` may be set or not. If not set, the default keyset configuration is used. If set, it must follow the enum constraints of [`KeySetConfig`].
        ///         I.e. be either `Standard` (0) or `DecompressionOnly` (1). Furthermore, if `Standard` is used then `standard_keyset_config` must also be set.
        ///         Furthermore, `keyset_config` must be set or not set in exactly the same was as it was in the argument for the preprocessing request started with `preproc_id`.
        ///     * `keyset_added_info` in `request` _must_ be set if `keyset_config` is set to `DecompressionOnly`, otherwise it is ignored.
        /// * Post-condition:
        ///     * `request_id` in `request` has been consumed and the key generation has been started in the background using `request_id` as identifier.
        ///     * `preproc_id` in `request` has been consumed and the preprocessing under this ID cannot be used anymore.
        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn insecure_key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
            self.insecure_key_generator.insecure_key_gen(request).await
        }

        /// WARNING: This method is insecure and should not be used in production.
        ///
        /// Retrieves the result from an insecure key generation.
        ///
        /// * `request` - The request ID under which the key generation was started.
        ///
        /// # Returns
        /// * `Ok(Response<KeyGenResult>)` - If the key generation completed successfully for `request`, then this ID will be relayed in `request_id`.
        ///                                - Furthermore, the `key_results` in the response will contain the result information of each relevant public key; e.g. public encryption key, server key, and SnS key.
        ///                                - The [`SignedPubDataHandle`] will be populated s.t. `key_handle` will contain the SHAKE-256 hash of the serialization of the given result.
        ///                                - Similarely the `signature` will contain the regular ECDSA signature of the public decryption result, signed by the KMS' secret signing key.
        ///                                - Finally the `external_signature` will contain the EIP-712 signature of the public decryption result using the `domain` provided in the request.
        /// * Errors:
        ///   - `InvalidArgument` - If the request ID is not valid or does not match the expected format.
        ///   - `NotFound` - If the key generation does not exist for `request`.
        ///   - `Internal` - If the key generation failed with an error.
        ///   - `Unavailable` - If the key generation is not complete for `request`.
        ///
        /// # Conditions
        /// * Pre-condition:
        ///     * `request` must be a valid [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
        ///                 Furthermore, the request ID must be the same as the one used to start the key generation with method `insecure_key_gen`.
        ///                 Finally the parameters used to start key generation must have been valid.
        /// * Post-condition:
        ///     * The `request_id` in `request` can be used to retrieve the result of the key generation again in the future. However there is no guarantee on how long the result will be stored.
        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn get_insecure_key_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<KeyGenResult>, Status> {
            self.insecure_key_generator.get_result(request).await
        }

        /// WARNING: This method is by definition expected to be insecure and should not be used in production.
        ///
        /// Computes an insecure CRS generation. That is, it generates a common reference string (CRS) for the KMS.
        /// The method is async in the sense that it returns immediately, but the actual CRS generation is done in the background.
        ///
        /// * `request` - Struct containing all the data of the request.
        ///
        /// # Returns
        /// * Errors:
        ///    - `InvalidArgument` - If the request ID is not present, valid or does not match the expected format.
        ///    - `NotFound` - If the parameters in the request are not valid.
        ///    - `ResourceExhausted` - If the KMS is currently busy with too many requests.
        ///    - `Aborted` - If an internal error occured in starting the crs generation _or_ if an invalid argument was given.
        ///
        /// # Conditions
        /// * Pre-condition:
        ///     * `request_id` in `request` must be present, valid, fresh and unique [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
        ///     * `params` in `request` must be castable to a [`FheParameter`], currently this means 0 or 1.
        ///     * `max_number_bits` is the amount of bits that can be proven for ciphertext vector using the generated CRS. If this is not provided, then it defaults to the maximum supported by the fhevm.
        ///     * `domain` in `request` _should_ be set, if not, then there will be no external signature on the result of the CRS generation.
        /// * Post-condition:
        ///     * `request_id` in `request` has been consumed and the CRS generation has been started in the background using `request_id` as identifier.
        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn insecure_crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
            self.insecure_crs_generator.insecure_crs_gen(request).await
        }

        /// WARNING: This method is by definition expected to be insecure and should not be used in production.
        ///
        /// Retrieves the result from an insecure CRS generation.
        ///
        /// * `request` - The request ID under which the CRS generation was started.
        ///
        /// # Returns
        /// * `Ok(Response<CrsGenResult>)` - If the CRS generation completed successfully for `request`, then this ID will be relayed in `request_id`.
        ///                                - Furthermore the `crs_results` [`SignedPubDataHandle`] will be set and `key_handle` will contain the SHAKE-256 hash of the serialization of the CRS result.
        ///                                - Similarely the `signature` will contain the regular ECDSA signature of the CRS result, signed by the KMS' secret signing key,
        ///                                - Finally the `external_signature` will contain the EIP-712 signature of the CRS result using the `domain` provided in the request.
        /// * Errors:
        ///     - `InvalidArgument` - If the request ID is not valid or does not match the expected format.
        ///     - `NotFound` - If the CRS generation does not exist for `request`.
        ///     - `Internal` - If the CRS generation failed with an error.
        ///     - `Unavailable` - If the CRS generation is not complete for `request`, i.e. it is still running in the background.
        ///
        /// # Conditions
        /// * Pre-condition:
        ///     * `request` must be a valid [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
        ///                 Furthermore, the request ID must be the same as the one used to start the CRS generation with method `insecure_crs_gen`.
        ///                 Finally the parameters used to start CRS generation must have been valid, i.e. `insecure_crs_gen` must not have returned an error.
        /// * Post-condition:
        ///     * The `request_id` in `request` can be used to retrieve the result of the CRS generation again in the future. However there is no guarantee on how long the result will be stored.
        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn get_insecure_crs_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<CrsGenResult>, Status> {
            self.insecure_crs_generator.get_result(request).await
        }

        /// WARNING: This method is not implemented yet and will always return an error.
        ///
        /// Contructs a new KMS context. That is, updates the internal state and configuration files to support a new KMS context.
        ///
        /// Currently this method _always_ returns an error (`Unimplemented`), as the feature is not yet implemented.
        ///
        /// * `_request` - Struct containing all the data of the request.
        ///
        /// # Conditions
        /// * Pre-condition:  -
        /// * Post-condition: -
        #[tracing::instrument(skip(self, request))]
        async fn new_kms_context(
            &self,
            request: Request<NewKmsContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.context_manager.new_kms_context(request).await
        }

        /// WARNING: This method is not implemented yet and will always return an error.
        ///
        /// Destroyes a new KMS context. That is, switches from one context to another, or removes the old one.
        ///
        /// Currently this method _always_ returns an error (`Unimplemented`), as the feature is not yet implemented.
        ///
        /// * `_request` - Struct containing all the data of the request.
        ///
        /// # Conditions
        /// * Pre-condition:  -
        /// * Post-condition: -
        #[tracing::instrument(skip(self, request))]
        async fn destroy_kms_context(
            &self,
            request: Request<DestroyKmsContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.context_manager.destroy_kms_context(request).await
        }

        /// WARNING: This method is not implemented yet and will always return an error.
        ///
        /// Contructs a new custodian context. That is, updates the internal state of custodians used for backup.
        ///
        /// Currently this method _always_ returns an error (`Unimplemented`), as the feature is not yet implemented.
        ///
        /// * `_request` - Struct containing all the data of the request.
        ///
        /// # Conditions
        /// * Pre-condition:  -
        /// * Post-condition: -
        #[tracing::instrument(skip(self, request))]
        async fn new_custodian_context(
            &self,
            request: Request<kms_grpc::kms::v1::NewCustodianContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.context_manager.new_custodian_context(request).await
        }

        /// WARNING: This method is not implemented yet and will always return an error.
        ///
        /// Destroyes a custodian context. That is, updates the internal state and configuration files to start used a new custodian context and removes the old one.
        ///
        /// Currently this method _always_ returns an error (`Unimplemented`), as the feature is not yet implemented.
        ///
        /// * `_request` - Struct containing all the data of the request.
        ///
        /// # Conditions
        /// * Pre-condition:  -
        /// * Post-condition: -
        #[tracing::instrument(skip(self, request))]
        async fn destroy_custodian_context(
            &self,
            request: Request<kms_grpc::kms::v1::DestroyCustodianContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            self.context_manager.destroy_custodian_context(request).await
        }

        /// WARNING: This method is not fully implemented yet.
        ///
        /// Retrieves the encryption public key of this KMS.
        /// This can be used by a custorian to encrypt data for the KMS during recovery.
        ///
        /// * `_request` - Struct containing all the data of the request.
        ///
        /// # Returns
        /// * `Ok(Response<OperatorPublicKey>)`
        ///
        /// # Conditions
        /// * Pre-condition:  -
        /// * Post-condition: -
        #[tracing::instrument(skip(self, request))]
        async fn get_operator_public_key(
            &self,
            request: Request<kms_grpc::kms::v1::Empty>,
        ) -> Result<Response<kms_grpc::kms::v1::OperatorPublicKey>, Status> {
            self.backup_operator.get_operator_public_key(request).await
        }

        /// WARNING: This method is not fully implemented yet.
        ///
        /// Restore keys from a backup.
        ///
        /// * `_request` - Struct containing all the data of the request.
        ///
        /// # Conditions
        /// * Pre-condition:  -
        /// * Post-condition: -
        #[tracing::instrument(skip(self, request))]
        async fn custodian_backup_restore(
            &self,
            request: Request<kms_grpc::kms::v1::Empty>,
        ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
            self.backup_operator.custodian_backup_restore(request).await
        }
    }
}
