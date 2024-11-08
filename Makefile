build-compose-base:
	docker compose -vvv -f docker-compose-kms-base.yml build

build-compose-threshold:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml -f docker-compose-kms-gateway-threshold.yml build

start-compose-threshold:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml up -d --wait

stop-compose-threshold:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml down --volumes --remove-orphans

build-compose-centralized:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-centralized.yml -f docker-compose-kms-gateway-threshold.yml build

start-compose-centralized:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-centralized.yml up -d --wait

stop-compose-centralized:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-centralized.yml down --volumes --remove-orphans

start-compose-threshold-observability:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml -f docker-compose-kms-observability.yml up -d --wait

start-compose-threshold-observability-ghcr:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml -f docker-compose-kms-observability.yml -f docker-compose-kms-threshold-ghcr.yml up -d --wait

stop-compose-threshold-observability:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml -f docker-compose-kms-observability.yml down --volumes --remove-orphans

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
	RUSTFLAGS="-Aclippy::doc-lazy-continuation" cargo clippy --all-targets --all-features -- -D warnings

linting-package:
	@if [ -z "$(PACKAGE)" ]; then \
		echo "Error: PACKAGE is not set. Usage: make clippy-package PACKAGE=<package-name>"; \
		exit 1; \
	fi
	RUSTFLAGS="-Aclippy::doc-lazy-continuation" cargo clippy --all-targets --all-features --package $(PACKAGE) -- -D warnings

