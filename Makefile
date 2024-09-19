build-compose-threshold:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml build

start-compose-threshold:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml up -d --wait

start-compose-threshold-ghcr:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml -f docker-compose-kms-threshold-ghcr.yml up -d --wait

stop-compose-threshold:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml down --volumes --remove-orphans

start-compose-threshold-ghcr:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml -f docker-compose-kms-threshold-ghcr.yml up -d --wait

stop-compose:
	docker compose down -v --remove-orphans

test_backward_compatibility: pull-lfs-files
	cargo test --test backward_compatibility_*

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
