build-compose-base:
	docker compose -vvv -f docker-compose-core-base.yml build

build-compose-threshold:
	docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml -f docker-compose-core-gateway-threshold.yml build

start-compose-threshold:
	docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml up -d --wait

stop-compose-threshold:
	docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml down --volumes --remove-orphans

build-compose-centralized:
	docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-centralized.yml build

start-compose-centralized:
	docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-centralized.yml up -d --wait

stop-compose-centralized:
	docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-centralized.yml down --volumes --remove-orphans

## TODO not sure what we do about these:
# start-compose-threshold-observability:
# 	docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml -f docker-compose-core-observability.yml up -d --wait

# start-compose-threshold-observability-ghcr:
# 	docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml -f docker-compose-core-observability.yml -f docker-compose-core-threshold-ghcr.yml up -d --wait

# stop-compose-threshold-observability:
# 	docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml -f docker-compose-core-observability.yml down --volumes --remove-orphans

test-backward-compatibility: pull-lfs-files
	cargo test --test backward_compatibility_* -- --include-ignored

# Check if Git LFS is installed and enabled
check-git-lfs:
	@if git lfs version > /dev/null 2>&1; then \
		echo "Git LFS is installed and enabled."; \
	else \
		echo "Error: Git LFS is not installed or not enabled. Please"; \
		exit 1; \
	fi

pull-lfs-files: check-git-lfs
	git lfs pull

linting-all:
	cargo clippy --all-targets --all-features -- -D warnings

linting-package:
	@if [ -z "$(PACKAGE)" ]; then \
		echo "Error: PACKAGE is not set. Usage: make clippy-package PACKAGE=<package-name>"; \
		exit 1; \
	fi
	cargo clippy --all-targets --all-features --package $(PACKAGE) -- -D warnings
