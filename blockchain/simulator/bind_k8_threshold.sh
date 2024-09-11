# We don't implement it for KMS Centralized because it is
# currently out of sync with main but it would be mostly the
# same thing
kubectl port-forward -n kms-threshold kms-blockchain-faucet-cbbd7cd66-gkgrt 8000:8000 & \
	kubectl port-forward -n kms-threshold kms-blockchain-validator-0 9090:9090 & \
	kubectl port-forward -n kms-threshold kms-blockchain-validator-0 36657:26657 & \
	kubectl port-forward -n kms-threshold kms-blockchain-kv-store-0 8088:8088
