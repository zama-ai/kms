# 🚀 KMS Core CI/CD Workflows

> A comprehensive guide to our CI/CD pipeline structure and automation

## 📋 Overview

This document describes the CI/CD workflow structure for the KMS Core project. Our pipeline is designed to ensure code quality, run comprehensive tests, and automate deployments.

## 🔄 Main Workflow File

[`.github/workflows/main.yml`](main.yml)

### Trigger Types

| Trigger | Timing | Purpose |
|---------|--------|---------|
| 🌙 **Scheduled (Nightly)** | Every weekday at 00:00 UTC | Comprehensive testing & staging updates |
| 🔍 **Pull Requests** | On PR creation/update | Code validation & testing |
| 🎯 **Main/Release** | On push to main/release/* | Testing & image building |
| 🏷️ **Docker Label** | On PR with "docker" label | Triggers Docker image builds |

---

## 🏗️ Component-Specific Jobs

### 📦 Helm Chart Component
<details>
<summary><b>View Component Details</b></summary>

#### 🧪 Test Job [`test-helm-chart`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | On chart changes |
| 🎯 Main | ✅ | On chart changes |

#### 🔍 Lint Job [`lint-helm-chart`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | On chart changes |
| 🎯 Main | ✅ | On chart changes |

#### 📦 Release Job [`release-helm-chart`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🎯 Main | ✅ | On chart changes |
</details>

### 📚 Documentation Component
<details>
<summary><b>View Component Details</b></summary>

#### 🔍 Check Job [`check-docs`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | On docs changes |
| 🎯 Main | ✅ | All changes |

> Performs link checking and validation using Python's linkcheckmd
</details>

###  Core Client Component
<details>
<summary><b>View Component Details</b></summary>

#### 🧪 Test Job [`test-core-client`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | On core-client/service/threshold/grpc changes |
| 🎯 Main | ✅ | Always |

#### 🐳 Docker Job [`docker-core-client`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🌙 Nightly | ✅ | On main/release branch |
| 🔍 PR | ✅ | When labeled with "docker" |
| 🎯 Main | ✅ | After successful tests |
</details>

### 🌐 GRPC Component
<details>
<summary><b>View Component Details</b></summary>

#### 🧪 Test Job [`test-grpc`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🌙 Nightly | ✅ | Always runs |
| 🔍 PR | ✅ | On GRPC/CI changes |
| 🎯 Main | ✅ | On GRPC/CI changes |
</details>

### ⚙️ Core Service Component
<details>
<summary><b>View Component Details</b></summary>

#### 🧪 Test Job [`test-core-service`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🌙 Nightly | ✅ | Comprehensive suite |
| 🔍 PR | ✅ | On service changes |
| 🎯 Main | ✅ | Always |

##### Test Configuration Details
- 🌙 **Nightly Tests**:
  - Runs comprehensive test suite in release mode
  - Features: `slow_tests`, `s3_tests`, `insecure`, `nightly_tests`

- 🔍 **PR/Main Tests** (Run in Parallel):
  1. Default user decryption Tests
     - Features: `slow_tests`, `s3_tests`, `insecure`
     - Focus: `default_user_decryption_threshold`
  2. Threshold Tests
     - Features: `slow_tests`, `s3_tests`, `insecure`
     - Excludes: Default user decryption
  3. Base Tests
     - Features: `slow_tests`, `s3_tests`, `insecure`
     - Excludes: Threshold tests

#### 🐳 Docker Job [`docker-core-service`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🌙 Nightly | ✅ | On main/release branch |
| 🔍 PR | ✅ | When labeled with "docker" |
| 🎯 Main | ✅ | After successful tests |

#### 🛡️ Nitro Enclave [`docker-nitro-enclave`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🌙 Nightly | ✅ | On main/release branch |
| 🔍 PR | ✅ | When labeled with "docker" |
| 🎯 Main | ✅ | After Docker build |
</details>

### 🔐 Threshold Component
<details>
<summary><b>View Component Details</b></summary>

#### 🧪 Test Job [`test-core-threshold-main`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🌙 Nightly | ✅ | On main/release branch |
| 🔍 PR | ❌ | Never runs |
| 🎯 Main | ✅ | On threshold changes |

> Includes Redis integration tests
</details>

### 🚢 ArgoCD Staging Update
<details>
<summary><b>View Component Details</b></summary>

#### 📦 Deploy Job [`update-argocd-staging`](main.yml)
| Trigger | Status | Condition |
|---------|--------|-----------|
| 🌙 Nightly | ✅ | Always runs |
| 🔍 PR | ❌ | Never runs |
| 🎯 Main | ❌ | Never runs |

> Updates kms-threshold-staging namespace with latest changes
</details>

---

## 🚀 Release Workflows

### 1. 📦 NPM Release
[`.github/workflows/npm-release.yml`](npm-release.yml)

| Trigger | Status | Condition |
|---------|--------|-----------|
| 🏷️ Release | ✅ | When published |

#### Features
- 🔄 Uses big instance for build environment
- 🌐 WASM support enabled
- 🔑 Handles NPM authentication and publishing
- 🏗️ Builds and tests library before release
- 🔐 Secure handling of tokens and credentials

### 2. 🐳 Release Docker Images
[`.github/workflows/on-release-images.yml`](on-release-images.yml)

| Trigger | Status | Condition |
|---------|--------|-----------|
| 🏷️ Release | ✅ | When published |
| 🔄 Manual | ✅ | Via workflow_dispatch |

#### Features
- 🏗️ Builds multiple Docker images:
  - KMS Core Client
  - KMS Connector
  - KMS Service
- 🔐 Proper permissions handling for each job
- 📤 Pushes images to container registry
- 🎯 Supports custom ref targeting (branch/tag/SHA)

---

## 🔍 Additional Workflows

### 1. 🧹 CI Lint and Checks
[`.github/workflows/ci_lint.yml`](ci_lint.yml)

| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | Always runs |

#### Features
- 🔄 Concurrent execution with auto-cancellation for non-main branches
- 🛠️ Uses `actionlint` v1.6.27 for workflow validation
- 🔒 Enforces SHA-pinned actions for security
- 🚫 Prevents workflow drift and ensures consistent CI behavior

### 2. 📦 Dependencies Analysis
[`.github/workflows/dependencies_analysis.yml`](dependencies_analysis.yml)

| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | All branches |
| 🎯 Push | ✅ | main, test branches |

#### Features
- 🔄 Concurrent execution with auto-cancellation for non-main branches
- 🦀 Uses stable Rust toolchain
- 📝 Validates Cargo.lock integrity
- 🔐 Security checks:
  - License whitelist verification using `cargo-deny`
  - Security vulnerability scanning using `cargo-audit`
- 🛠️ Tools:
  - `cargo-audit` v0.21.0
  - `cargo-deny` v0.16.2
  - `cargo-binstall` for efficient tool installation

### 3. 📝 Dockerfile PR Validation
[`.github/workflows/workflow-pr-dockerfile.yml`](workflow-pr-dockerfile.yml)

| Trigger | Status | Condition |
|---------|--------|-----------|
| 🔍 PR | ✅ | On .dockerfile changes |

#### Features
- 🔍 Detects changed Dockerfile paths
- 🧹 Uses `hadolint` for Dockerfile linting
- 🔄 Processes multiple Dockerfiles in batch
- 🔒 SHA-pinned action versions for security
- 🔍 Scanned images for vulnerabilities with Trivy
- 🚫 Auto-triggers only on relevant changes

---

## 🛠️ Reusable Workflows

### 1. 🖥️ Common Build Big Instance
[`.github/workflows/common-testing-big-instance.yml`](common-testing-big-instance.yml)
- 🚀 Starts EC2 runner using SLAB
- 🔄 Delegates to common-testing workflow
- 📦 Supports:
  - MinIO for object storage
  - Redis for caching
  - WASM runtime for WebAssembly tests

### 2. 🏗️ Common Build
[`.github/workflows/common-testing.yml`](common-testing.yml)

| Stage | Actions |
|-------|---------|
| 🔧 **Setup** | Code checkout, Git LFS, Registry login |
| 🌍 **Environment** | Rust toolchain, Cache config, Dependencies |
| ✨ **Quality** | Formatting, Linting |
| 🧪 **Testing** | Unit tests, WASM tests, Coverage |
| 📚 **Docs** | Build & deploy documentation |

### 3. 🐳 Docker Build Workflows

| Workflow | Purpose | File |
|----------|---------|------|
| 📦 **Common Docker** | Standard builds | [`.github/workflows/common-docker.yml`](common-docker.yml) |
| 💪 **Big Instance** | Large builds | [`.github/workflows/common-docker-big-instance.yml`](common-docker-big-instance.yml) |
| 🛡️ **Nitro Enclave** | AWS Secure Env | [`.github/workflows/common-nitro-enclave.yml`](common-nitro-enclave.yml) |

### 4. 🚢 ArgoCD Update
[`.github/workflows/common-update-argocd.yml`](common-update-argocd.yml)
- 🌙 Runs during nightly builds
- 📦 Updates staging environment
- 🎯 Deploys to kms-threshold-staging
