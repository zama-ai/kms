# Port-forwards the faucet, validator and kv-store services of the
# kms-threshold namespace to localhost.
kubectl port-forward -n kms-threshold kms-blockchain-faucet-ff588d788-gm8dv 8000:8000 & \
	kubectl port-forward -n kms-threshold kms-blockchain-validator-0 9090:9090 & \
	kubectl port-forward -n kms-threshold kms-blockchain-validator-0 36657:26657 & \
	kubectl port-forward -n kms-threshold kv-store-kv-store-0 8088:8088
