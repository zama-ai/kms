use crate::engine::centralized::central_kms::CentralizedKms;
use crate::engine::traits::{BackupOperator, ContextManager};
use crate::tonic_some_or_err;
use crate::vault::storage::Storage;
use kms_grpc::kms::v1::{
    self, Empty, InitRequest, KeyGenPreprocRequest, KeyGenPreprocResult, OperatorPublicKey,
};
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpoint;
use tonic::{Request, Response, Status};

use crate::engine::centralized::service::{crs_gen_impl, get_crs_gen_result_impl};
use crate::engine::centralized::service::{get_key_gen_result_impl, key_gen_impl};
use crate::engine::centralized::service::{
    get_public_decryption_result_impl, get_user_decryption_result_impl, public_decrypt_impl,
    user_decrypt_impl,
};

#[tonic::async_trait]
impl<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
        CM: ContextManager + Sync + Send + 'static,
        BO: BackupOperator + Sync + Send + 'static,
    > CoreServiceEndpoint for CentralizedKms<PubS, PrivS, CM, BO>
{
    /// Initializes the centralized KMS service.
    ///
    /// Currently this method _always_ returns an error (Abort, error code 10), as the centralized KMS does not support this operation.
    /// More specifically, the operation initializes the PRSS state betweeen MPC parties, but since there is only one party in the centralized KMS, this operation is not needed.
    ///
    /// * `_request` - Struct containing all the data of the request.
    ///
    /// # Conditions
    /// * Pre-condition:  -
    /// * Post-condition: -
    async fn init(&self, _request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
        tonic_some_or_err(
            None,
            "Requesting init on centralized kms is not suported".to_string(),
        )
        .map_err(Status::from)
    }

    /// Computes the preprocessed material needed for a single key generation.
    ///
    /// Currently this method _always_ returns an error (Abort, error code 10), as the centralized KMS does not support this operation.
    ///
    /// * `_request` - Struct containing all the data of the request.
    ///
    /// # Conditions
    /// * Pre-condition:  -
    /// * Post-condition: -
    #[tracing::instrument(skip(self, _request))]
    async fn key_gen_preproc(
        &self,
        _request: Request<KeyGenPreprocRequest>,
    ) -> Result<Response<Empty>, Status> {
        tonic_some_or_err(
            None,
            "Requesting preproc on centralized kms is not suported".to_string(),
        )
        .map_err(Status::from)
    }

    /// Returns the status of the generation of preprocessing material.
    /// Currently this method _always_ returns an error (Abort, error code 10), as the centralized KMS does not support this operation.
    ///
    /// * `_request` - Struct containing all the data of the request.
    ///
    /// # Conditions
    /// * Pre-condition:  -
    /// * Post-condition: -
    #[tracing::instrument(skip(self, _request))]
    async fn get_key_gen_preproc_result(
        &self,
        _request: Request<v1::RequestId>,
    ) -> Result<Response<KeyGenPreprocResult>, Status> {
        tonic_some_or_err(
            None,
            "Requesting preproc status on centralized kms is not suported".to_string(),
        )
        .map_err(Status::from)
    }

    /// WARNING: This method is by definition expected to be insecure and should not be used in production.
    ///
    /// Computes an insecure key generation. For the centralized KMS this is exactly the same as the regular `key_gen` method.
    /// The method is async in the sense that it returns immediately, but the actual key generation is done in the background.
    ///
    /// * `request` - Struct containing all the data of the request.
    ///
    /// # Returns
    /// * Errors:
    ///    - `InvalidArgument` - If the request ID is not valid or does not match the expected format.
    ///    - `Internal` - If the key generation failed with an internal error (may be related to metrics).
    ///    - `ResourceExhausted` - If the KMS is currently busy with too many requests.
    ///    - `Aborted` - If an internal error occured in starting the key generation _or_ if an invalid argument was given. // TODO we likely want to ensure invalid argument are returned when that is the cause of error
    ///
    /// # Conditions
    /// * Pre-condition:
    ///     * `request_id` in `request` must be present, valid, fresh and unique [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
    ///     * `params` in `request` must be castable to a [`FheParameter`], currently this means 0 or 1.
    ///     * `preproc_id` in `request` is ignored and _should_ hence be set to `None` to avoid confusion.
    ///     * `domain` in `request` _should_ be set, if not, then there will be no external signature on the result of the key generation.
    ///     * `keyset_config` in `request` may be set or not. If not set, the default keyset configuration is used. If set, it must follow the enum constraints of [`KeySetConfig`].
    ///         I.e. be either `Standard` (0) or `DecompressionOnly` (1). Furthermore, if `Standard` is used then `standard_keyset_config` must also be set.
    ///     * `keyset_added_info` in `request` _must_ be set if `keyset_config` is set to `DecompressionOnly`, otherwise it is ignored.
    /// * Post-condition:
    ///     * `request_id` in `request` is has been consumed and the key generation has been started in the background using `request_id` as identifier.
    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn insecure_key_gen(
        &self,
        request: Request<kms_grpc::kms::v1::KeyGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        self.key_gen(request).await
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
    ///   - `Aborted` - If an internal error occured in retrieving the key generation result.
    ///
    /// # Conditions
    /// * Pre-condition:
    ///     * `request` must be a valid [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
    ///                 Furthermore, the request ID must be the same as the one used to start the key generation with method `insecure_key_gen` or `key_gen`.
    ///                 Finally the parameters used to start key generation must have been valid.
    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn get_insecure_key_gen_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::KeyGenResult>, Status> {
        self.get_key_gen_result(request).await
    }

    /// Computes key generation.
    /// The method is async in the sense that it returns immediately, but the actual key generation is done in the background.
    ///
    /// * `request` - Struct containing all the data of the request.
    ///
    /// # Returns
    /// * Errors:
    ///    - `InvalidArgument` - If the request ID is not valid or does not match the expected format.
    ///    - `Internal` - If the key generation failed with an internal error (may be related to metrics).
    ///    - `ResourceExhausted` - If the KMS is currently busy with too many requests.
    ///    - `Aborted` - If an internal error occured in starting the key generation _or_ if an invalid argument was given. // TODO we likely want to ensure invalid argument are returned when that is the cause of error
    ///
    /// # Conditions
    /// * Pre-condition:
    ///     * `request_id` in `request` must be present, valid, fresh and unique [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
    ///     * `params` in `request` must be castable to a [`FheParameter`], currently this means 0 or 1.
    ///     * `preproc_id` in `request` is ignored and _should_ hence be set to `None` to avoid confusion.
    ///     * `domain` in `request` _should_ be set, if not, then there will be no external signature on the result of the key generation.
    ///     * `keyset_config` in `request` may be set or not. If not set, the default keyset configuration is used. If set, it must follow the enum constraints of [`KeySetConfig`].
    ///         I.e. be either `Standard` (0) or `DecompressionOnly` (1). Furthermore, if `Standard` is used then `standard_keyset_config` must also be set.
    ///     * `keyset_added_info` in `request` _must_ be set if `keyset_config` is set to `DecompressionOnly`, otherwise it is ignored.
    /// * Post-condition:
    ///     * `request_id` in `request` is has been consumed and the key generation has been started in the background using `request_id` as identifier.
    #[tracing::instrument(skip(self, request))]
    async fn key_gen(
        &self,
        request: Request<kms_grpc::kms::v1::KeyGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        key_gen_impl(self, request).await
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
    ///   - `Aborted` - If an internal error occured in retrieving the key generation result.
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
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::KeyGenResult>, Status> {
        get_key_gen_result_impl(self, request).await
    }

    /// Computes a user decryption. That is, it decrypts a ciphertext and encrypts the result under a user's public key.
    /// The method is async in the sense that it returns immediately, but the actual decryption is done in the background.
    ///
    /// * `request` - Struct containing all the data of the request.
    ///
    /// # Errors
    ///    - `ResourceExhausted` - If the KMS is currently busy with too many requests.
    ///    - `Internal` - If the request failed with an internal error (may be related to metrics).
    ///    - `Aborted` - If an internal error occured in starting the user decryption _or_ if an invalid argument was given. // TODO we likely want to ensure invalid argument are returned when that is the cause of error
    ///
    /// # Conditions
    /// * Pre-condition:
    ///     * `request_id` in `request` must be present, valid, fresh and unique [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
    ///     * `typed_ciphertexts` in `request` must be a non-empty vector of [`TypedCiphertext`]s, where each ciphertext is a valid ciphertext for the keyset present in the KMS (see below).
    ///                  Observe that the KMS does _not_ check the validity of the ciphertexts _before_ accepting the request! Any errors will be returned in _get_user_decryption_result_.
    ///     * `key_id` in `request` must be present, valid [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
    ///                  Furthermore, it must have been successfully generated by the KMS previous using the `key_gen` or `insecure_key_gen` methods.
    ///                  The `key_id` must also match the used to encrypt the the ciphertexts in `typed_ciphertexts`.
    ///     * `client_address` in `request` must be the the EIP-55 encoded (blockchain wallet) address of the user requesting the decryption. I.e. including `0x` prefix.
    ///     * `enc_key` in `request` must be the public key of the user requesting the decryption. This must be a bincode (v.1) encoded ML-KEM 512 key.
    ///     * `domain` in `request` _must_ be set. Furthermore, within `domain`, the `verifying_contract` _must_ be set and be distinct from the `client_address`.
    /// * Post-condition:
    ///     * `request_id` in `request` is has been consumed and the user decryption has been started in the background using `request_id` as identifier.
    #[tracing::instrument(skip(self, request))]
    async fn user_decrypt(
        &self,
        request: Request<kms_grpc::kms::v1::UserDecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        user_decrypt_impl(self, request).await
    }

    /// Retrieves the result from a user decryption.
    ///
    /// * `request` - The request ID under which the user decryption was started.
    ///
    /// # Returns
    /// * `Ok(Response<UserDecryptionResponse>)` - If decryption completed successfully then `signature` will contain the ECDSA signature of the user decryption result, signed by the KMS' secret signing key.
    ///                                          - The `external_signature` will contain the EIP-712 signature of the public decryption result using the `domain` provided in the request.
    ///                                          - The `payload` will always be set and contain decrypted payload.
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
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::UserDecryptionResponse>, Status> {
        get_user_decryption_result_impl(self, request).await
    }

    /// Computes a public decryption. That is, it decrypts a ciphertext and returns the plaintext.
    /// The method is async in the sense that it returns immediately, but the actual decryption is done in the background.
    ///
    /// * `request` - Struct containing all the data of the request.
    ///
    /// # Errors
    ///    - `ResourceExhausted` - If the KMS is currently busy with too many requests.
    ///    - `Internal` - If the request failed with an internal error (may be related to metrics).
    ///    - `Aborted` - If an internal error occured in starting the public decryption _or_ if an invalid argument was given. // TODO we likely want to ensure invalid argument are returned when that is the cause of error
    ///
    /// # Conditions
    /// * Pre-condition:
    ///     * `request_id` in `request` must be present, valid, fresh and unique [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
    ///     * `ciphertexts` in `request` must be a non-empty vector of [`TypedCiphertext`]s, where each ciphertext is a valid ciphertext for the keyset present in the KMS (see below).
    ///                  Observe that the KMS does _not_ check the validity of the ciphertexts _before_ accepting the request! Any errors will be returned in _get_public_decryption_result_.
    ///     * `domain` in `request` _should_ be set. If not present, there there will be no external signature on the result of the public decryption. // TODO is this actually the desired logic?
    /// * Post-condition:
    ///     * `request_id` in `request` is has been consumed and the public decryption has been started in the background using `request_id` as identifier.
    #[tracing::instrument(skip(self, request))]
    async fn public_decrypt(
        &self,
        request: Request<kms_grpc::kms::v1::PublicDecryptionRequest>,
    ) -> Result<Response<Empty>, Status> {
        public_decrypt_impl(self, request).await
    }

    /// Retrieves the result from a public decryption.
    ///
    /// * `request` - The request ID under which the public decryption was started.
    ///
    /// # Returns
    /// * `Ok(Response<PublicDecryptionResponse>)` - If the public decryption completed successfully then the `signature` will contain the regular ECDSA signature of the public decryption result, signed by the KMS' secret signing key.
    ///                                            - Finally the `payload` will contain result of the public decryption
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
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::PublicDecryptionResponse>, Status> {
        get_public_decryption_result_impl(self, request).await
    }

    /// Computes a CRS generation. That is, it generates a common reference string (CRS) for the KMS.
    /// The method is async in the sense that it returns immediately, but the actual CRS generation is done in the background.
    ///
    /// * `request` - Struct containing all the data of the request.
    ///
    /// # Returns
    /// * Errors:
    ///    - `InvalidArgument` - If the request ID is not valid or does not match the expected format.
    ///    - `Internal` - If the request failed with an internal error (may be related to metrics).
    ///    - `ResourceExhausted` - If the KMS is currently busy with too many requests.
    ///    - `Aborted` - If an internal error occured in starting the crs generation _or_ if an invalid argument was given. // TODO we likely want to ensure invalid argument are returned when that is the cause of error
    ///
    /// # Conditions
    /// * Pre-condition:
    ///     * `request_id` in `request` must be present, valid, fresh and unique [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
    ///     * `params` in `request` must be castable to a [`FheParameter`], currently this means 0 or 1.
    ///     * `max_number_bits` is the amount of bits that can be proven for ciphertext vector using the generated CRS. If this is not provided, then it defaults to the maximum supported by the fhevm.
    ///     * `domain` in `request` _should_ be set, if not, then there will be no external signature on the result of the CRS generation.
    /// * Post-condition:
    ///     * `request_id` in `request` is has been consumed and the CRS generation has been started in the background using `request_id` as identifier.
    #[tracing::instrument(skip(self, request))]
    async fn crs_gen(
        &self,
        request: Request<kms_grpc::kms::v1::CrsGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        crs_gen_impl(self, request).await
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
    ///     - `Aborted` - If an internal error occured in retrieving the crs generation result.
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
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::CrsGenResult>, Status> {
        get_crs_gen_result_impl(self, request).await
    }

    /// WARNING: This method is by definition expected to be insecure and should not be used in production.
    ///
    /// Computes an insecure CRS generation. In the centralized KMS this is exactly the same as the regular `crs_gen` method.
    /// That is, it generates a common reference string (CRS) for the KMS.
    /// The method is async in the sense that it returns immediately, but the actual CRS generation is done in the background.
    ///
    /// * `request` - Struct containing all the data of the request.
    ///
    /// # Returns
    /// * Errors:
    ///    - `InvalidArgument` - If the request ID is not valid or does not match the expected format.
    ///    - `Internal` - If the request failed with an internal error (may be related to metrics).
    ///    - `ResourceExhausted` - If the KMS is currently busy with too many requests.
    ///    - `Aborted` - If an internal error occured in starting the crs generation _or_ if an invalid argument was given. // TODO we likely want to ensure invalid argument are returned when that is the cause of error
    ///
    /// # Conditions
    /// * Pre-condition:
    ///     * `request_id` in `request` must be present, valid, fresh and unique [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
    ///     * `params` in `request` must be castable to a [`FheParameter`], currently this means 0 or 1.
    ///     * `max_number_bits` is the amount of bits that can be proven for ciphertext vector using the generated CRS. If this is not provided, then it defaults to the maximum supported by the fhevm.
    ///     * `domain` in `request` _should_ be set, if not, then there will be no external signature on the result of the CRS generation.
    /// * Post-condition:
    ///     * `request_id` in `request` is has been consumed and the CRS generation has been started in the background using `request_id` as identifier.
    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn insecure_crs_gen(
        &self,
        request: Request<kms_grpc::kms::v1::CrsGenRequest>,
    ) -> Result<Response<Empty>, Status> {
        self.crs_gen(request).await
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
    ///     - `Aborted` - If an internal error occured in retrieving the crs generation result.
    ///
    /// # Conditions
    /// * Pre-condition:
    ///     * `request` must be a valid [`RequestId`]. I.e. 32 byte lower-case hex encoding without `0x` prefix.
    ///                 Furthermore, the request ID must be the same as the one used to start the CRS generation with method `insecure_crs_gen` or `crs_gen`.
    ///                 Finally the parameters used to start CRS generation must have been valid, i.e. `insecure_crs_gen` must not have returned an error.
    /// * Post-condition:
    ///     * The `request_id` in `request` can be used to retrieve the result of the CRS generation again in the future. However there is no guarantee on how long the result will be stored.
    #[cfg(feature = "insecure")]
    #[tracing::instrument(skip(self, request))]
    async fn get_insecure_crs_gen_result(
        &self,
        request: Request<v1::RequestId>,
    ) -> Result<Response<kms_grpc::kms::v1::CrsGenResult>, Status> {
        self.get_crs_gen_result(request).await
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
        request: Request<kms_grpc::kms::v1::NewKmsContextRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
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
        request: Request<kms_grpc::kms::v1::DestroyKmsContextRequest>,
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
        self.context_manager
            .destroy_custodian_context(request)
            .await
    }

    /// WARNING: This method is not implemented yet.
    ///
    /// Currently this method _always_ returns an error (`Unimplemented`), as the feature is not yet implemented.
    ///
    /// However it is supposed to retrieve the encryption public key of this KMS.
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
        request: Request<Empty>,
    ) -> Result<Response<OperatorPublicKey>, Status> {
        self.backup_operator.get_operator_public_key(request).await
    }

    /// WARNING: This method is not fully implemented yet.
    ///
    /// Currently this method _always_ returns an error (`Unimplemented`), as the feature is not yet implemented.
    ///
    /// However, it is supposed to restore keys from a backup.
    ///
    /// * `_request` - Struct containing all the data of the request.
    ///
    /// # Conditions
    /// * Pre-condition:  -
    /// * Post-condition: -
    #[tracing::instrument(skip(self, request))]
    async fn custodian_backup_restore(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<Empty>, Status> {
        self.backup_operator.custodian_backup_restore(request).await
    }
}
