use crate::engine::threshold::threshold_kms::ThresholdKms;
use crate::engine::threshold::traits::{
    CrsGenerator, Initiator, KeyGenPreprocessor, KeyGenerator, PublicDecryptor, Resharer,
    UserDecryptor,
};
#[cfg(feature = "insecure")]
use crate::engine::threshold::traits::{InsecureCrsGenerator, InsecureKeyGenerator};
use crate::engine::traits::{BackupOperator, ContextManager};
use kms_grpc::kms::v1::{
    CrsGenRequest, CrsGenResult, DestroyMpcContextRequest, Empty, HealthStatus, InitRequest,
    InitiateResharingRequest, InitiateResharingResponse, KeyGenPreprocRequest, KeyGenPreprocResult,
    KeyGenRequest, KeyGenResult, KeyMaterialAvailabilityResponse, NewMpcContextRequest, NodeType,
    PeersFromContext, PublicDecryptionRequest, PublicDecryptionResponse, RequestId,
    ResharingResultResponse, UserDecryptionRequest, UserDecryptionResponse,
};
use kms_grpc::kms::v1::{HealthStatusResponse, PeerHealth};
use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpoint;
use observability::{
    metrics::METRICS,
    metrics_names::{
        map_tonic_code_to_metric_err_tag, OP_CRS_GEN_REQUEST, OP_CRS_GEN_RESULT,
        OP_CUSTODIAN_BACKUP_RECOVERY, OP_CUSTODIAN_RECOVERY_INIT, OP_DESTROY_CUSTODIAN_CONTEXT,
        OP_DESTROY_MPC_CONTEXT, OP_FETCH_PK, OP_GET_INITIATE_RESHARING_RESULT, OP_INIT,
        OP_INITIATE_RESHARING, OP_KEYGEN_PREPROC_REQUEST, OP_KEYGEN_PREPROC_RESULT,
        OP_KEYGEN_REQUEST, OP_KEYGEN_RESULT, OP_NEW_CUSTODIAN_CONTEXT, OP_NEW_MPC_CONTEXT,
        OP_PUBLIC_DECRYPT_REQUEST, OP_PUBLIC_DECRYPT_RESULT, OP_RESTORE_FROM_BACKUP,
        OP_USER_DECRYPT_REQUEST, OP_USER_DECRYPT_RESULT,
    },
};
use threshold_fhe::networking::health_check::HealthCheckStatus;
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
                RE: Resharer + Sync + Send + 'static,
            > CoreServiceEndpoint for ThresholdKms<IN, UD, PD, KG, PP, CG, CM, BO, RE> $implementations

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
                RE: Resharer + Sync + Send + 'static,
            > CoreServiceEndpoint for ThresholdKms<IN, UD, PD, KG, IKG, PP, CG, ICG, CM, BO, RE> $implementations
    }
}

impl_endpoint! {
    // See the proto file for the documentation of each method.
    impl CoreServiceEndpoint {
        async fn init(&self, request: Request<InitRequest>) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_INIT);
            self.initiator.init(request).await.map_err(|e| e.into())
        }

        #[tracing::instrument(skip(self, request))]
        async fn key_gen_preproc(
            &self,
            request: Request<KeyGenPreprocRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_KEYGEN_PREPROC_REQUEST);
            self.keygen_preprocessor.key_gen_preproc(request).await.map_err(|e| e.into())
        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn partial_key_gen_preproc(
            &self,
            request: Request<kms_grpc::kms::v1::PartialKeyGenPreprocRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_KEYGEN_PREPROC_REQUEST);
            self.keygen_preprocessor.partial_key_gen_preproc(request).await.map_err(|e| e.into())
        }

        #[tracing::instrument(skip(self, request))]
        async fn get_key_gen_preproc_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<KeyGenPreprocResult>, Status> {
            METRICS.increment_request_counter(OP_KEYGEN_PREPROC_RESULT);
            self.keygen_preprocessor.get_result(request).await.map_err(|e| e.into())
        }

        #[tracing::instrument(skip(self, request))]
        async fn key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_KEYGEN_REQUEST);
            self.key_generator.key_gen(request).await.map_err(|e| e.into())
        }

        #[tracing::instrument(skip(self, request))]
        async fn get_key_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<KeyGenResult>, Status> {
            METRICS.increment_request_counter(OP_KEYGEN_RESULT);
            self.key_generator.get_result(request).await.map_err(|e| e.into())
        }

        #[tracing::instrument(skip(self, request))]
        async fn user_decrypt(
            &self,
            request: Request<UserDecryptionRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_USER_DECRYPT_REQUEST);
            self.user_decryptor.user_decrypt(request).await.map_err(|e| e.into())

        }

        #[tracing::instrument(skip(self, request))]
        async fn get_user_decryption_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<UserDecryptionResponse>, Status> {
            METRICS.increment_request_counter(OP_USER_DECRYPT_RESULT);
            self.user_decryptor.get_result(request).await.map_err(|e| e.into())


        }

        #[tracing::instrument(skip(self, request))]
        async fn public_decrypt(
            &self,
            request: Request<PublicDecryptionRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_PUBLIC_DECRYPT_REQUEST);
            self.decryptor.public_decrypt(request).await.map_err(|e| e.into())
        }

        #[tracing::instrument(skip(self, request))]
        async fn get_public_decryption_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<PublicDecryptionResponse>, Status> {
            METRICS.increment_request_counter(OP_PUBLIC_DECRYPT_RESULT);
            self.decryptor.get_result(request).await.map_err(|e| e.into())
       }


        #[tracing::instrument(skip(self, request))]
        async fn crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_CRS_GEN_REQUEST);
            self.crs_generator.crs_gen(request).await.map_err(|e| e.into())
        }

        #[tracing::instrument(skip(self, request))]
        async fn get_crs_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<CrsGenResult>, Status> {
            METRICS.increment_request_counter(OP_CRS_GEN_RESULT);
            self.crs_generator.get_result(request).await.map_err(|e| e.into())
        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn insecure_key_gen(&self, request: Request<KeyGenRequest>) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(observability::metrics_names::OP_INSECURE_KEYGEN_REQUEST);
            self.insecure_key_generator.insecure_key_gen(request).await.map_err(|e| e.into())
        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn get_insecure_key_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<KeyGenResult>, Status> {
            METRICS.increment_request_counter(observability::metrics_names::OP_INSECURE_KEYGEN_RESULT);
            self.insecure_key_generator.get_result(request).await.map_err(|e| e.into())
        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn insecure_crs_gen(&self, request: Request<CrsGenRequest>) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(observability::metrics_names::OP_INSECURE_CRS_GEN_REQUEST);
            self.insecure_crs_generator.insecure_crs_gen(request).await.map_err(|e| e.into())
        }

        #[cfg(feature = "insecure")]
        #[tracing::instrument(skip(self, request))]
        async fn get_insecure_crs_gen_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<CrsGenResult>, Status> {
            METRICS.increment_request_counter(observability::metrics_names::OP_INSECURE_CRS_GEN_RESULT);
            self.insecure_crs_generator.get_result(request).await.map_err(|e| e.into())
        }

        // TODO(#2868) refactor to use MetricedError
        #[tracing::instrument(skip(self, request))]
        async fn new_mpc_context(
            &self,
            request: Request<NewMpcContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_NEW_MPC_CONTEXT);
            self.context_manager.new_mpc_context(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_err_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_NEW_MPC_CONTEXT, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn destroy_mpc_context(
            &self,
            request: Request<DestroyMpcContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_DESTROY_MPC_CONTEXT);
            self.context_manager.destroy_mpc_context(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_err_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_DESTROY_MPC_CONTEXT, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn initiate_resharing(
            &self,
            request: Request<InitiateResharingRequest>,
        ) -> Result<Response<InitiateResharingResponse>, Status> {
            METRICS.increment_request_counter(OP_INITIATE_RESHARING);
            self.resharer.initiate_resharing(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn get_resharing_result(
            &self,
            request: Request<RequestId>,
        ) -> Result<Response<ResharingResultResponse>, Status> {
            METRICS.increment_request_counter(OP_GET_INITIATE_RESHARING_RESULT);
            self.resharer.get_resharing_result(request).await
        }

        #[tracing::instrument(skip(self, request))]
        async fn new_custodian_context(
            &self,
            request: Request<kms_grpc::kms::v1::NewCustodianContextRequest>,
        ) -> Result<Response<Empty>, Status> {
            METRICS.increment_request_counter(OP_NEW_CUSTODIAN_CONTEXT);
            self.context_manager.new_custodian_context(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_err_tag(err.code());
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
                let tag = map_tonic_code_to_metric_err_tag(err.code());
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
                let tag = map_tonic_code_to_metric_err_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_FETCH_PK, tag);
            })

        }

        #[tracing::instrument(skip(self, request))]
        async fn custodian_backup_recovery(
            &self,
            request: Request<kms_grpc::kms::v1::CustodianRecoveryRequest>,
        ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
            METRICS.increment_request_counter(OP_CUSTODIAN_BACKUP_RECOVERY);
            self.backup_operator.custodian_backup_recovery(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_err_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_CUSTODIAN_BACKUP_RECOVERY, tag);
            })
        }

        #[tracing::instrument(skip(self, request))]
        async fn restore_from_backup(
            &self,
            request: Request<kms_grpc::kms::v1::Empty>,
        ) -> Result<Response<kms_grpc::kms::v1::Empty>, Status> {
            METRICS.increment_request_counter(OP_RESTORE_FROM_BACKUP);
            self.backup_operator.restore_from_backup(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_err_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_RESTORE_FROM_BACKUP, tag);
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

        #[tracing::instrument(skip(self, request))]
        async fn custodian_recovery_init(
            &self,
            request: Request<kms_grpc::kms::v1::CustodianRecoveryInitRequest>,
        ) -> Result<Response<kms_grpc::kms::v1::RecoveryRequest>, Status> {
            METRICS.increment_request_counter(OP_CUSTODIAN_RECOVERY_INIT);
            self.backup_operator.custodian_recovery_init(request).await.inspect_err(|err| {
                let tag = map_tonic_code_to_metric_err_tag(err.code());
                let _ = METRICS
                    .increment_error_counter(OP_CUSTODIAN_RECOVERY_INIT, tag);
            })
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

            let health_check_sessions = self.session_maker.get_healthcheck_session_all_contexts().await
            .map_err(|e| {tonic::Status::internal(format!("Failed to get health check sessions: {}", e))})?;

            let mut peers_from_all_contexts = Vec::new();
            for (context_id,health_check_session) in health_check_sessions {
                let my_role = health_check_session.get_my_role().one_based() as u32;
                let total_nodes = health_check_session.get_num_parties() as u32;
                let min_nodes_for_healthy = (2 * total_nodes) / 3 + 1; // 2/3 majority + 1
                let min_threshold = (total_nodes / 3) + 1; // Minimum threshold to be able to reconstruct anything
                let health_check_results = health_check_session.run_healthcheck().await;
                let mut peers_status = Vec::new();
                let mut nodes_reachable = 1; //I am reachable
                if let Ok(results) = health_check_results {
                    for ((role, identity), result) in results.into_iter() {
                        let peer_status = match result {
                            HealthCheckStatus::Ok(latency) => {
                                nodes_reachable += 1;
                                PeerHealth {
                                    peer_id: role.one_based() as u32,
                                    endpoint: identity.hostname().to_string(),
                                    reachable: true,
                                    latency_ms: latency.as_millis() as u32,
                                    error: String::new(),
                                }
                            }
                            HealthCheckStatus::Error((latency, error)) => PeerHealth {
                                peer_id: role.one_based() as u32,
                                endpoint: identity.hostname().to_string(),
                                reachable: false,
                                latency_ms: latency.as_millis() as u32,
                                error: format!("Error : {}", error.message()),
                            },
                            HealthCheckStatus::TimeOut(elapsed) => {PeerHealth {
                                peer_id: role.one_based() as u32,
                                endpoint: identity.hostname().to_string(),
                                reachable: false,
                                latency_ms: 0,
                                error: format!("Timeout after {:?} s", elapsed.as_secs()),
                            }},
                        };
                        peers_status.push(peer_status);
                    }
                } else {
                    tracing::warn!("Health check failed for context {:?}", context_id);
                }

                 // Determine overall health status
                let status = if nodes_reachable >= total_nodes {
                    HealthStatus::Optimal.into() // HEALTH_STATUS_OPTIMAL - all nodes online and reachable
                } else if nodes_reachable >= min_nodes_for_healthy {
                    HealthStatus::Healthy.into() // HEALTH_STATUS_HEALTHY - sufficient 2/3 majority but not all nodes
                } else if nodes_reachable > min_threshold {
                    HealthStatus::Degraded.into() // HEALTH_STATUS_DEGRADED - above minimum threshold but below 2/3
                } else {
                    HealthStatus::Unhealthy.into() // HEALTH_STATUS_UNHEALTHY - insufficient nodes for operations
                };

                let peers_from_context = PeersFromContext {
                    context_id: Some(context_id.into()),
                    my_party_id: my_role,
                    threshold_required: min_threshold,
                    nodes_reachable,
                    status,
                    peers: peers_status,
                };
                peers_from_all_contexts.push(peers_from_context)
            }


            let response = HealthStatusResponse {
                peers_from_all_contexts,
                my_fhe_key_ids: own_material.fhe_key_ids,
                my_crs_ids: own_material.crs_ids,
                my_preprocessing_key_ids: own_material.preprocessing_ids,
                my_storage_info: own_material.storage_info,
                node_type: NodeType::Threshold.into(),
            };

            Ok(Response::new(response))
        }
    }
}
