# 🚀 KMS Core CI/CD Workflows

> A comprehensive guide to our CI/CD pipeline structure and automation

## 📋 Overview

This document describes the CI/CD workflow structure for the KMS Core project. Our pipeline is designed to ensure code quality, run comprehensive tests, and automate releases through intelligent change detection and parallel execution.

## 🔄 Main Workflow File

[`.github/workflows/main.yml`](main.yml)

### Trigger Types

| Trigger | Timing | Purpose |
|---------|--------|---------|
| 🌙 **Scheduled (Nightly)** | Every weekday at 00:00 UTC | Comprehensive testing with nightly test suites |
| 🔍 **Pull Requests** | On PR creation/update | Code validation & testing based on changes |
| 🎯 **Main/Release** | On push to main/release/* | Testing & conditional Docker builds |
| 🏷️ **Docker Label** | On PR with "docker" label | Triggers Docker image builds |

---

## 🏗️ Component-Specific Jobs

### 🔍 Change Detection System
Our CI uses intelligent change detection to only run tests for modified components:
- **Path-based filtering**: Only runs jobs when relevant files change
- **Concurrent execution**: Jobs run in parallel when triggered
- **Dependency awareness**: Core changes trigger dependent component tests

### 📦 Helm Chart Component
<details>
<summary><b>View Component Details</b></summary>

#### 🧪 Test Job [`test-helm-chart`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | On charts/** changes |
| 🎯 Main | ✅ | On charts/** changes |

#### 🔍 Lint Job [`lint-helm-chart`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | On charts/** changes |
| 🎯 Main | ✅ | On charts/** changes |

#### 📦 Release Job [`release-helm-chart`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🎯 Main | ✅ | On charts/** changes (non-scheduled) |
</details>

### 📚 Documentation Component
<details>
<summary><b>View Component Details</b></summary>

#### 🔍 Check Job [`check-docs`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | On docs/** changes |
| 🎯 Main | ✅ | Always runs |

> Performs link checking and validation using Python's linkcheckmd
</details>

### 🔄 Backward Compatibility Testing
<details>
<summary><b>View Component Details</b></summary>

#### 🧪 Test Job [`test-backward-compatibility`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | On core service/threshold/grpc/CI changes |
| 🎯 Main | ✅ | Always runs |

> Uses big instance for comprehensive backward compatibility validation
</details>

### 📱 Core Client Component
<details>
<summary><b>View Component Details</b></summary>

#### 🧪 Integration Tests [`test-core-client`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | On core-client/service/threshold/grpc/CI changes |
| 🎯 Main | ✅ | Always runs |

**Test Matrix**: Runs threshold and centralized tests in parallel

#### 🔬 Unit Tests [`test-core-client-unit`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | On core-client/** changes only |
| 🎯 Main | ❌ | Skip integration tests |

#### 🐳 Docker Build [`docker-core-client`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | When labeled with "docker" |
| 🎯 Main | ❌ | Manual trigger only |
</details>

### 🌐 GRPC Component
<details>
<summary><b>View Component Details</b></summary>

#### 🧪 Test Job [`test-grpc`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | On core/grpc/** changes |
| 🎯 Main | ✅ | On core/grpc/** changes |

> Tests all features using big instance infrastructure
</details>

### ⚙️ Core Service Component
<details>
<summary><b>View Component Details</b></summary>

#### 🧪 Test Job [`test-core-service`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | On core/service/** changes |
| 🎯 Main | ✅ | On core/service/** changes |

##### Test Matrix Configuration
- 🌙 **Nightly Tests**: `--release -F slow_tests -F s3_tests -F insecure nightly`
- 🔍 **PR/Main Tests** (4 parallel jobs):
  1. **Library Tests**: `-F testing --lib`
  2. **Default User Decryption**: `-F slow_tests -F s3_tests -F insecure default_user_decryption_threshold`
  3. **Threshold Tests**: `-F slow_tests -F s3_tests -F insecure threshold` (excludes default_user_decryption)
  4. **Base Tests**: `-F slow_tests -F s3_tests -F insecure` (excludes threshold tests)

> **Infrastructure**: Uses big instance with MinIO and WASM support

#### 🌐 WASM Tests [`test-wasm`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | On core/service/** changes |
| 🎯 Main | ✅ | On core/service/** changes |

#### 🐳 Docker Build [`docker-core-service`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | When labeled with "docker" |
| 🎯 Main | ❌ | Manual trigger only |

#### 🛡️ Nitro Enclave [`docker-nitro-enclave`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | When labeled with "docker" (after core service) |
| 🎯 Main | ❌ | Manual trigger only |
</details>

### 🔐 Threshold Component
<details>
<summary><b>View Component Details</b></summary>

#### 🧪 PR Tests [`test-core-threshold-pr`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | On core/threshold/** changes |
| 🎯 Main | ❌ | PR only |

> **Config**: `-F slow_tests --lib` with 4 parallel test threads

#### 🧪 Main Tests [`test-core-threshold-main`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ❌ | Never runs |
| 🎯 Main | ✅ | On core/threshold/** changes |

> **Config**: `-F slow_tests --lib` with Redis integration and 4 parallel test threads

#### 🤖 Dependabot Build [`build-dependabot`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | Only for dependabot/** branches |
| 🎯 Main | ❌ | Dependabot only |

> **Simplified**: `--lib` tests only for dependency validation
</details>

### 🏗️ Infrastructure Components
<details>
<summary><b>View Component Details</b></summary>

#### 🐳 Golden Image [`docker-golden-image`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | When labeled with "docker" |
| 🎯 Main | ❌ | Manual trigger only |

> **Purpose**: Builds base Rust image with dependencies for KMS components

#### 📊 Test Reporter [`test-reporter`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | Always runs after all tests complete |
| 🎯 Main | ❌ | PR only |

> **Function**: Aggregates and reports test results from all components
</details>

---

## 🚀 Release Workflows

### 1. 📦 NPM Release
[`.github/workflows/npm-release.yml`](npm-release.yml)

| Trigger | Status | Condition |
|---------|--------|-----------|
| 🏷️ Release | ✅ | When GitHub release is published |

#### Features
- 🌐 **Dual Package Build**: Creates separate Node.js and web WASM packages
- 📝 **Package Variants**:
  - `node-tkms`: Node.js target with `--target nodejs`
  - `tkms`: Web target with `--target web`
- 🔄 **Version Tagging**: Automatic latest/prerelease tag assignment
- 🔐 **Security**: Uses NPM_TOKEN for authentication

### 2. 🐳 Release Docker Images
[`.github/workflows/on-release-images.yml`](on-release-images.yml)

| Trigger | Status | Condition |
|---------|--------|-----------|
| 🏷️ Release | ✅ | When GitHub release is published |
| 🔄 Manual | ✅ | Via workflow_dispatch (configurable ref) |

#### Features
- 🏗️ **Multi-Stage Build Pipeline**: Sequential Docker image construction
- 🐳 **Container Images Built**:
  - `kms/rust-golden-image`: Base Rust image with all dependencies
  - `kms/core-client`: KMS core client application
  - `kms/core-service`: Main KMS service (uses big instance)
  - `kms/core-service-enclave`: AWS Nitro Enclave variant
- 🔐 **Security Features**:
  - OIDC authentication for secure publishing
  - Build attestations for supply chain security
  - CGR (Container Registry) integration
- 📦 **Publishing**: Pushes to both GitHub Container Registry and CGR
- ⚡ **Optimization**: Caching via app-cache-dir for faster builds

---

## 🔍 Quality Assurance Workflows

### 1. 🧹 CI Lint and Security
[`.github/workflows/ci_lint.yml`](ci_lint.yml)

| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | Always runs |

#### Features
- 🔄 **Concurrency Control**: Auto-cancels for non-main branches
- 🛠️ **Workflow Validation**: Uses `actionlint` v1.6.27
- 🔒 **Security Enforcement**: SHA-pinned actions validation
- 🔍 **SAST Analysis**: Static security scanning with Zizmor

### 2. 📦 Dependencies Analysis
[`.github/workflows/dependencies_analysis.yml`](dependencies_analysis.yml)

| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | All branches |
| 🎯 Push | ✅ | main, test branches |

#### Features
- 🔄 **Concurrency Control**: Auto-cancels for non-main branches
- 🦀 **Rust Toolchain**: Uses stable Rust with efficient tool installation
- 📝 **Cargo.lock Validation**: Ensures lock file integrity
- 🔐 **Security Scanning**:
  - **License Compliance**: `cargo-deny` v0.16.2 for license whitelist
  - **Vulnerability Detection**: `cargo-audit` v0.21.0 for security issues
- 🚀 **Efficient Installation**: Uses `cargo-binstall` for faster tool setup

---

## 🛠️ Reusable Workflow Infrastructure

### 1. 🖥️ Big Instance Testing
[`.github/workflows/common-testing-big-instance.yml`](common-testing-big-instance.yml)

#### Architecture
- 🚀 **EC2 Runner Management**: Uses Zama SLAB for dynamic runner provisioning
- 🔄 **Workflow Delegation**: Proxies to `common-testing.yml` with enhanced resources
- 🛑 **Guaranteed Cleanup**: Always stops runners even on failure

#### Supported Services
- **MinIO**: Object storage testing (`run-minio: true`)
- **Redis**: Caching and state testing (`run-redis: true`)
- **WASM Runtime**: WebAssembly execution testing (`run-wasm: true`)

### 2. 🏗️ Common Testing Pipeline
[`.github/workflows/common-testing.yml`](common-testing.yml)

#### Pipeline Stages
| Stage | Actions | Key Features |
|-------|---------|--------------|
| 🔧 **Setup** | Checkout, Git LFS, Registry login | Multi-registry support (GHCR, CGR) |
| 🌍 **Environment** | Rust toolchain, Protoc, Dependencies | Version-pinned from `toolchain.txt` |
| 🗄️ **Caching** | Cargo cache, Build artifacts | S3-backed caching with runs-on/cache |
| ✨ **Quality** | Formatting, Clippy, Dylint | Multiple lint passes (default + all features) |
| 🧪 **Testing** | Nextest execution, Artifact collection | Configurable parallelism and retries |
| 📚 **Documentation** | Doc building and deployment | Optional GitHub Pages publication |

#### Advanced Testing Features
- **Nextest Integration**: Modern test runner with better output
- **Test Parallelism**: Configurable via `nextest-test-threads`
- **Retry Logic**: `NEXTEST_RETRIES: 3` for flaky test handling
- **Artifact Collection**: JUnit XML and log preservation
- **Slack Integration**: Nightly test result notifications

### 3. 🌐 WASM Testing Pipeline
[`.github/workflows/wasm-testing.yml`](wasm-testing.yml)

#### Specialized WASM Workflow
- **Test Generation**: Runs Rust tests to create WASM test fixtures
- **WASM Pack Build**: Creates Node.js WASM packages
- **Node.js Testing**: Validates WASM functionality with `node --test`
- **Dry-run Publishing**: Tests NPM package creation without actual publish

### 4. 🐳 Specialized Docker Workflows
- **Nitro Enclave**: [`common-nitro-enclave.yml`](common-nitro-enclave.yml) - AWS secure execution
- **ArgoCD Updates**: [`common-update-argocd.yml`](common-update-argocd.yml) - Staging deployments
