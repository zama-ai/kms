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

start-compose-threshold-telemetry:
	docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml -f docker-compose-telemetry.yml up -d --wait

stop-compose-threshold-telemetry:
	docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml -f docker-compose-telemetry.yml down --volumes --remove-orphans

build-compose-heap-profiling:
	docker compose -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml -f profiling/docker-compose-heap-profiling.yml -f docker-compose-telemetry.yml build

start-compose-heap-profiling:
	docker compose -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml -f profiling/docker-compose-heap-profiling.yml -f docker-compose-telemetry.yml up -d --wait

stop-compose-heap-profiling:
	docker compose -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml -f profiling/docker-compose-heap-profiling.yml -f docker-compose-telemetry.yml down --volumes --remove-orphans

# Dump heap profiles from all cores and copy them locally for analysis
dump-heap-profiles:
	@mkdir -p profiling/heap-dumps
	@for i in 1 2 3 4; do \
		echo "Dumping heap profile for dev-kms-core-$$i..."; \
		docker compose -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml -f profiling/docker-compose-heap-profiling.yml \
			exec dev-kms-core-$$i killall -USR1 kms-server 2>/dev/null || true; \
	done
	@sleep 1
	@for i in 1 2 3 4; do \
		echo "Copying dumps from dev-kms-core-$$i..."; \
		docker compose -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml -f profiling/docker-compose-heap-profiling.yml \
			cp dev-kms-core-$$i:/tmp/kms-heap/ ./profiling/heap-dumps/core-$$i/ 2>/dev/null || true; \
		echo "Capturing /proc/maps for dev-kms-core-$$i..."; \
		docker compose -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml -f profiling/docker-compose-heap-profiling.yml \
			exec -T dev-kms-core-$$i sh -c 'cat /proc/$$(pidof kms-server)/maps' \
			> ./profiling/heap-dumps/core-$$i/maps.txt 2>/dev/null || true; \
	done
	@echo "Copying kms-server binary for symbol resolution..."
	@docker compose -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml -f profiling/docker-compose-heap-profiling.yml \
		cp dev-kms-core-1:/app/kms/core/service/bin/kms-server ./profiling/heap-dumps/kms-server 2>/dev/null || true
	@echo "Done. Analyze with: ./profiling/analyze-heap.sh ./profiling/heap-dumps/kms-server ./profiling/heap-dumps/core-1/"

# Test backwards compatibility with LFS files. This will pull the LFS files from git before running the tests.
test-backward-compatibility: pull-lfs-files
	cargo test --test backward_compatibility_* -- --include-ignored

# Do not run LFS pull and use locally generated files to test backward compatibility.
test-backward-compatibility-local:
	cargo test --test backward_compatibility_* -- --include-ignored --no-capture

clean-backward-compatibility-data:
	rm -f backward-compatibility/data/kms.ron
	rm -f backward-compatibility/data/kms-grpc.ron
	rm -f backward-compatibility/data/threshold-fhe.ron
	rm -rf backward-compatibility/data/0_11_0
	rm -rf backward-compatibility/data/0_11_1
	rm -rf backward-compatibility/data/0_13_0
	rm -rf backward-compatibility/data/0_13_10

generate-backward-compatibility-v0.11.0:
	cd backward-compatibility/generate-v0.11.0 && cargo run --release

generate-backward-compatibility-v0.11.1:
	cd backward-compatibility/generate-v0.11.1 && cargo run --release

generate-backward-compatibility-v0.13.0:
	cd backward-compatibility/generate-v0.13.0 && cargo run --release

generate-backward-compatibility-v0.13.10:
	cd backward-compatibility/generate-v0.13.10 && cargo run --release

generate-backward-compatibility-all: clean-backward-compatibility-data generate-backward-compatibility-v0.11.0 generate-backward-compatibility-v0.11.1 generate-backward-compatibility-v0.13.0 generate-backward-compatibility-v0.13.10
	@echo "Generated backward compatibility data for all versions"

# Test material generation targets
generate-test-material-all:
	cargo run -p generate-test-material --features slow_tests -- --output ./test-material --verbose all

generate-test-material-testing:
	@echo "Generating testing material..."
	cargo run -p generate-test-material -- --output ./test-material --verbose testing

generate-test-material-default:
	cargo run -p generate-test-material --features slow_tests -- --output ./test-material --verbose default

validate-test-material:
	cargo run -p generate-test-material -- --output ./test-material --verbose validate

clean-test-material:
	cargo run -p generate-test-material -- --output ./test-material --verbose clean

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
