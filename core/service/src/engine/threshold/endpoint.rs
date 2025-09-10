use crate::engine::threshold::threshold_kms::ThresholdKms;
use crate::engine::threshold::traits::{
    BackupOperator, ContextManager, CrsGenerator, Initiator, KeyGenPreprocessor, KeyGenerator,
    PublicDecryptor, UserDecryptor,
};
#[cfg(feature = "insecure")]
use crate::engine::threshold::traits::{InsecureCrsGenerator, InsecureKeyGenerator};
use kms_grpc::kms::v1::{health_status_response::PeerHealth, HealthStatusResponse};
use kms_grpc::kms::v1::{
    CrsGenRequest, CrsGenResult, DestroyKmsContextRequest, Empty, InitRequest,
    KeyGenPreprocRequest, KeyGenPreprocResult, KeyGenRequest, KeyGenResult,
    KeyMaterialAvailabilityResponse, NewKmsContextRequest, PublicDecryptionRequest,
    PublicDecryptionResponse, RequestId, UserDecryptionRequest, UserDecryptionResponse,
};
use kms_grpc::kms_service::v1::{
    core_service_endpoint_client::CoreServiceEndpointClient,
    core_service_endpoint_server::CoreServiceEndpoint,
};
use observability::{
    metrics::METRICS,
    metrics_names::{
        map_tonic_code_to_metric_tag, OP_BACKUP_RESTORE, OP_CRS_GEN_REQUEST, OP_CRS_GEN_RESULT,
        OP_CUSTODIAN_BACKUP_RECOVERY, OP_DESTROY_CUSTODIAN_CONTEXT, OP_DESTROY_KMS_CONTEXT,
        OP_FETCH_PK, OP_INIT, OP_KEYGEN_PREPROC_REQUEST, OP_KEYGEN_PREPROC_RESULT,
        OP_KEYGEN_REQUEST, OP_KEYGEN_RESULT, OP_NEW_CUSTODIAN_CONTEXT, OP_NEW_KMS_CONTEXT,
        OP_PUBLIC_DECRYPT_REQUEST, OP_PUBLIC_DECRYPT_RESULT, OP_USER_DECRYPT_REQUEST,
        OP_USER_DECRYPT_RESULT,
    },
};
use std::time::Instant;
use tonic::{transport::Channel, Request, Response, Status};

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
    // See the proto file for the documentation of each method.
    impl CoreServiceEndpoint {
        async fn init(&self, request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_INIT);
            self.initiator.init(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_INIT, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn key_gen_preproc(
            &self,
            request: Request<KeyGenPreprocRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_KEYGEN_PREPROC_REQUEST);
            self.keygen_preprocessor.key_gen_preproc(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_KEYGEN_PREPROC_REQUEST, tag);
            })
        }

        #[tracing::instrument(skip(self, request))]
        async fn get_key_gen_preproc_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<KeyGenPreprocResult>, Status> {
            METRICS.increment_request_counter(OP_KEYGEN_PREPROC_RESULT);
            self.keygen_preprocessor.get_result(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_KEYGEN_PREPROC_RESULT, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_KEYGEN_REQUEST);
            self.key_generator.key_gen(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_KEYGEN_REQUEST, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn get_key_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<KeyGenResult>, Status> {
            METRICS.increment_request_counter(OP_KEYGEN_RESULT);
            self.key_generator.get_result(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_KEYGEN_RESULT, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn user_decrypt(
            &self,
            request: Request<UserDecryptionRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_USER_DECRYPT_REQUEST);
            self.user_decryptor.user_decrypt(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_USER_DECRYPT_REQUEST, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn get_user_decryption_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<UserDecryptionResponse>, Status> {
            METRICS.increment_request_counter(OP_USER_DECRYPT_RESULT);
            self.user_decryptor.get_result(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_USER_DECRYPT_RESULT, tag);
            })


        }

        #[tracing::instrument(skip(self, request))]
        async fn public_decrypt(
            &self,
            request: Request<PublicDecryptionRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_PUBLIC_DECRYPT_REQUEST);
            self.decryptor.public_decrypt(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_PUBLIC_DECRYPT_REQUEST, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn get_public_decryption_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<PublicDecryptionResponse>, Status> {
            METRICS.increment_request_counter(OP_PUBLIC_DECRYPT_RESULT);
            self.decryptor.get_result(request).await .inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_PUBLIC_DECRYPT_RESULT, tag);
            })
       }


        #[tracing::instrument(skip(self, request))]
        async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_CRS_GEN_REQUEST);
            self.crs_generator.crs_gen(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_CRS_GEN_REQUEST, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn get_crs_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<CrsGenResult>, Status> {
            METRICS.increment_request_counter(OP_CRS_GEN_RESULT);
            self.crs_generator.get_result(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_CRS_GEN_RESULT, tag);
            })


        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn insecure_key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(observability::metrics_names::OP_INSECURE_KEYGEN_REQUEST);
            self.insecure_key_generator.insecure_key_gen(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(observability::metrics_names::OP_INSECURE_KEYGEN_REQUEST, tag);
            })

        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn get_insecure_key_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<KeyGenResult>, Status> {
            METRICS.increment_request_counter(observability::metrics_names::OP_INSECURE_KEYGEN_RESULT);
            self.insecure_key_generator.get_result(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(observability::metrics_names::OP_INSECURE_KEYGEN_RESULT, tag);
            })


        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn insecure_crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(observability::metrics_names::OP_INSECURE_CRS_GEN_REQUEST);
            self.insecure_crs_generator.insecure_crs_gen(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(observability::metrics_names::OP_INSECURE_CRS_GEN_REQUEST, tag);
            })

        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn get_insecure_crs_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<CrsGenResult>, Status> {
            METRICS.increment_request_counter(observability::metrics_names::OP_INSECURE_CRS_GEN_RESULT);
            self.insecure_crs_generator.get_result(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(observability::metrics_names::OP_INSECURE_CRS_GEN_RESULT, tag);
            })


        }

        #[tracing::instrument(skip(self, request))]
        async fn new_kms_context(
            &self,
            request: Request<NewKmsContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_NEW_KMS_CONTEXT);
            self.context_manager.new_kms_context(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_NEW_KMS_CONTEXT, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn destroy_kms_context(
            &self,
            request: Request<DestroyKmsContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_DESTROY_KMS_CONTEXT);
            self.context_manager.destroy_kms_context(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_DESTROY_KMS_CONTEXT, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn new_custodian_context(
            &self,
            request: Request<kms_grpc::kms::v1::NewCustodianContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_NEW_CUSTODIAN_CONTEXT);
            self.context_manager.new_custodian_context(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_NEW_CUSTODIAN_CONTEXT, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn destroy_custodian_context(
            &self,
            request: Request<kms_grpc::kms::v1::DestroyCustodianContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_DESTROY_CUSTODIAN_CONTEXT);
            self.context_manager.destroy_custodian_context(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_DESTROY_CUSTODIAN_CONTEXT, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn get_operator_public_key(
            &self,
            request: Request<kms_grpc::kms::v1::Empty>,
        ) -> Result<Response<kms_grpc::kms::v1::OperatorPublicKey>, Status> {
            METRICS.increment_request_counter(OP_FETCH_PK);
            self.backup_operator.get_operator_public_key(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_FETCH_PK, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn custodian_backup_recovery(
            &self,
            request: Request<kms_grpc::kms::v1::BackupRecoveryRequest>,
        ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
            METRICS.increment_request_counter(OP_CUSTODIAN_BACKUP_RECOVERY);
            self.backup_operator.custodian_backup_recovery(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_CUSTODIAN_BACKUP_RECOVERY, tag);
            })
        }

        #[tracing::instrument(skip(self, request))]
        async fn backup_restore(
            &self,
            request: Request<kms_grpc::kms::v1::Empty>,
        ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
            METRICS.increment_request_counter(OP_BACKUP_RESTORE);
            self.backup_operator.backup_restore(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_BACKUP_RESTORE, tag);
            })
        }

        #[tracing::instrument(skip(self, _request))]
        async fn get_key_material_availability(
            &self,
            _request: Request<Empty>,
        ) -> Result<Response<KeyMaterialAvailabilityResponse>, Status> {
            // Get preprocessing IDs from the preprocessor
            let preprocessing_ids = self.keygen_preprocessor.get_all_preprocessing_ids().await?;

            // Get storage references from backup_operator
            let backup_response = self.backup_operator.get_key_material_availability(Request::new(Empty {})).await?;
            let mut response = backup_response.into_inner();

            // Update the response with preprocessing IDs
            response.preprocessing_ids = preprocessing_ids;

            Ok(Response::new(response))
        }

        #[tracing::instrument(skip(self, _request))]
        async fn custodian_recovery_init(
            &self,
            _request: Request<kms_grpc::kms::v1::Empty>,
        ) -> Result<Response<kms_grpc::kms::v1::RecoveryRequest>, Status> {
            Err(Status::unimplemented(
                "custodian_recovery_init is not implemented",
            ))
        }

        #[tracing::instrument(skip(self, _request))]
        async fn get_health_status(
            &self,
            _request: Request<Empty>,
        ) -> Result<Response<kms_grpc::kms::v1::HealthStatusResponse>, Status> {

            // Get own key material directly from backup_operator (avoid redundant gRPC call to self)
            let backup_response = self.backup_operator.get_key_material_availability(Request::new(Empty {})).await?;
            let mut own_material = backup_response.into_inner();

            // Add preprocessing IDs from the preprocessor
            own_material.preprocessing_ids = self.keygen_preprocessor.get_all_preprocessing_ids().await?;

            // Check peer health
            let mut peer_health_infos = Vec::new();
            let mut nodes_reachable = 1; // Count self as reachable

            if let Some(peers) = &self.config.peers {
                for peer in peers {
                    // Skip self-check - we already know we're healthy
                    if peer.party_id == self.config.my_id {
                        continue;
                    }

                    // Determine gRPC port: use explicit config or apply convention
                    let service_port = match peer.service_port {
                    Some(port) => port,
                    None => {
                        // Convention: P2P port 5000X maps to gRPC port 50X00
                        // e.g., 50001 -> 50100, 50002 -> 50200, etc.
                        if peer.port >= 50000 && peer.port < 50100 {
                            let offset = peer.port - 50000;
                            50000 + (offset * 100)
                        } else {
                            // For non-standard ports, assume gRPC = P2P + 99
                            peer.port + 99
                        }
                    }
                };
                // gRPC health check endpoints are always HTTP (TLS is for P2P, not gRPC)
                let protocol = "http";

                // TODO: Determine protocol based on TLS configuration if/when needed
                // let protocol = if peer.tls_cert.is_some() {
                //     "https"
                // } else {
                //     "http"
                // };

                let endpoint = format!("{}://{}:{}", protocol, peer.address, service_port);
                let start = Instant::now();

                let peer_info = match Channel::from_shared(endpoint.clone()) {
                    Ok(channel_builder) => {
                        match channel_builder
                            .timeout(std::time::Duration::from_secs(5))
                            .connect()
                            .await
                        {
                            Ok(channel) => {
                                let mut client = CoreServiceEndpointClient::new(channel);
                                match client.get_key_material_availability(Empty {}).await {
                                    Ok(response) => {
                                        let resp = response.into_inner();
                                        nodes_reachable += 1;
                                        PeerHealth {
                                            peer_id: peer.party_id as u32,
                                            endpoint: endpoint.clone(),
                                            reachable: true,
                                            latency_ms: start.elapsed().as_millis() as u32,
                                            storage_info: resp.storage_info,
                                            error: String::new(),
                                            fhe_key_ids: resp.fhe_key_ids,
                                            crs_ids: resp.crs_ids,
                                            preprocessing_key_ids: resp.preprocessing_ids,
                                        }
                                    }
                                    Err(e) => PeerHealth {
                                        peer_id: peer.party_id as u32,
                                        endpoint: endpoint.clone(),
                                        reachable: false,
                                        latency_ms: start.elapsed().as_millis() as u32,
                                        storage_info: String::new(),
                                        error: e.to_string(),
                                        fhe_key_ids: Vec::new(),
                                        crs_ids: Vec::new(),
                                        preprocessing_key_ids: Vec::new(),
                                    },
                                }
                            }
                            Err(e) => PeerHealth {
                                peer_id: peer.party_id as u32,
                                endpoint: endpoint.clone(),
                                reachable: false,
                                latency_ms: 0,
                                storage_info: String::new(),
                                error: format!("Connection failed: {}", e),
                                fhe_key_ids: Vec::new(),
                                crs_ids: Vec::new(),
                                preprocessing_key_ids: Vec::new(),
                            },
                        }
                    }
                    Err(e) => PeerHealth {
                        peer_id: peer.party_id as u32,
                        endpoint: endpoint.clone(),
                        reachable: false,
                        latency_ms: 0,
                        storage_info: String::new(),
                        error: format!("Invalid endpoint: {}", e),
                        fhe_key_ids: Vec::new(),
                        crs_ids: Vec::new(),
                        preprocessing_key_ids: Vec::new(),
                    },
                };

                    peer_health_infos.push(peer_info);
                }
            }

            // Calculate threshold requirements
            let threshold_required = self.config.threshold as u32;
            // peers list includes self, so we use len() directly
            let total_nodes = self.config.peers.as_ref().map_or(1, |p| p.len() as u32);

            let min_nodes_for_healthy = (2 * total_nodes) / 3 + 1; // 2/3 majority + 1

            // Determine overall health status
            let status = if nodes_reachable >= total_nodes {
                1 // HEALTH_STATUS_OPTIMAL - all nodes online and reachable
            } else if nodes_reachable >= min_nodes_for_healthy {
                2 // HEALTH_STATUS_HEALTHY - sufficient 2/3 majority but not all nodes
            } else if nodes_reachable > threshold_required {
                3 // HEALTH_STATUS_DEGRADED - above minimum threshold but below 2/3
            } else {
                4 // HEALTH_STATUS_UNHEALTHY - insufficient nodes for operations
            };

            let response = HealthStatusResponse {
                status,
                peers: peer_health_infos,
                my_fhe_key_ids: own_material.fhe_key_ids,
                my_crs_ids: own_material.crs_ids,
                my_preprocessing_key_ids: own_material.preprocessing_ids,
                my_storage_info: own_material.storage_info,
                node_type: 2, // NODE_TYPE_THRESHOLD
                my_party_id: self.config.my_id as u32,
                threshold_required,
                nodes_reachable,
            };

            Ok(Response::new(response))
        }
    }
}
