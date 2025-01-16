# We don't implement it for KMS Centralized because it is
# currently out of sync with main but it would be mostly the
# same thing
kubectl port-forward -n kms-threshold-staging svc/kms-threshold-blockchain-staging-faucet 8000:8000 & \
	kubectl port-forward -n kms-threshold-staging kms-threshold-blockchain-staging-rpc-0 9090:9090 & \
	kubectl port-forward -n kms-threshold-staging kms-threshold-blockchain-staging-rpc-0 36657:26657 & \
	kubectl port-forward -n kms-threshold-staging kms-threshold-kv-staging-kv-store-0 8088:8088
