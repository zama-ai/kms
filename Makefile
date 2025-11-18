build-compose-base:
	docker compose -vvv -f docker-compose-core-base.yml build

build-compose-threshold:
	docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml build

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

test-backward-compatibility-local:
	cargo test --test backward_compatibility_* -- --include-ignored --no-capture

clean-backward-compatibility-data:
	rm -f backward-compatibility/data/kms.ron
	rm -f backward-compatibility/data/kms-grpc.ron
	rm -f backward-compatibility/data/threshold-fhe.ron
	rm -rf backward-compatibility/data/0_11_0
	rm -rf backward-compatibility/data/0_11_1
	rm -rf backward-compatibility/data/0_13_0

generate-backward-compatibility-v0.11.0:
	cd backward-compatibility/generate-v0.11.0 && cargo run --release --locked

generate-backward-compatibility-v0.11.1:
	cd backward-compatibility/generate-v0.11.1 && cargo run --release --locked

generate-backward-compatibility-v0.13.0:
	cd backward-compatibility/generate-v0.13.0 && cargo run --release

generate-backward-compatibility-all: clean-backward-compatibility-data generate-backward-compatibility-v0.11.0 generate-backward-compatibility-v0.11.1 generate-backward-compatibility-v0.13.0
	@echo "Generated backward compatibility data for all versions"

# Test material generation targets
generate-test-material-all:
	cargo run --bin generate-test-material -- all --output ./test-material --verbose

generate-test-material-testing:
	@echo "Generating testing material..."
	cargo run --bin generate-test-material -- --output ./test-material --verbose testing

generate-test-material-default:
	cargo run --bin generate-test-material -- --features slow_tests default --output ./test-material --verbose

validate-test-material:
	cargo run --bin generate-test-material -- validate --output ./test-material --verbose

clean-test-material:
	cargo run --bin generate-test-material -- clean --output ./test-material --verbose

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

# Isolated Test Targets (No Docker Required)
.PHONY: test-isolated test-isolated-centralized test-isolated-threshold test-isolated-integration test-isolated-parallel

# Run all isolated tests (centralized + threshold + integration)
test-isolated: generate-test-material-testing
	@echo "Running all isolated tests..."
	@echo "Running centralized tests..."
	cargo test --lib --features insecure,testing centralized::misc_tests_isolated -- --test-threads=1
	cargo test --lib --features insecure,testing centralized::restore_from_backup_tests_isolated -- --test-threads=1
	@echo "Running threshold tests..."
	cargo test --lib --features insecure,testing threshold::key_gen_tests_isolated -- --test-threads=1
	cargo test --lib --features insecure,testing threshold::misc_tests_isolated -- --test-threads=1
	cargo test --lib --features insecure,testing threshold::restore_from_backup_tests_isolated -- --test-threads=1
	@echo "Running integration tests..."
	cargo test --test integration_test_backup --features insecure -- --test-threads=1

# Run centralized isolated tests only
test-isolated-centralized: generate-test-material-testing
	@echo "Running centralized isolated tests..."
	cargo test --lib --features insecure,testing centralized::misc_tests_isolated -- --test-threads=1
	cargo test --lib --features insecure,testing centralized::restore_from_backup_tests_isolated -- --test-threads=1

# Run threshold isolated tests only
test-isolated-threshold: generate-test-material-testing
	@echo "Running threshold isolated tests..."
	cargo test --lib --features insecure,testing threshold::key_gen_tests_isolated -- --test-threads=1
	cargo test --lib --features insecure,testing threshold::misc_tests_isolated -- --test-threads=1
	cargo test --lib --features insecure,testing threshold::restore_from_backup_tests_isolated -- --test-threads=1

# Run integration tests only
test-isolated-integration: generate-test-material-testing
	@echo "Running integration tests..."
	cargo test --test integration_test_backup --features insecure -- --test-threads=1

# Run isolated tests with parallel execution (where safe - non-PRSS tests)
test-isolated-parallel: generate-test-material-testing
	@echo "Running isolated tests in parallel..."
	cargo test --lib --features insecure,testing misc_tests_isolated -- --test-threads=4

# Clean up test artifacts
clean-test-artifacts:
	@echo "Cleaning test artifacts..."
	rm -rf target/debug/deps/kms_lib-*
	rm -rf /tmp/kms-test-*
	@echo "Test artifacts cleaned"

# Full test suite
test-full: generate-test-material-all test-isolated test-backward-compatibility
	@echo "Full test suite completed successfully"

# Quick test suite (testing material only, no backward compatibility)
test-quick: generate-test-material-testing test-isolated
	@echo "Quick test suite completed successfully"
