
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

linting:
	RUSTFLAGS="-Aclippy::doc-lazy-continuation" cargo clippy --all-features -- -D warnings

generate-data: check-duplicate
	cargo run --release --features="generate"

check-duplicate:
	cargo check
	 ./scripts/check_duplicate_tfhe_versions.sh