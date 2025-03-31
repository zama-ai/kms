# MinIO S3 Mock for KMS Connector Testing

> TODO: Remove this Mock after HTTPZ and ZWS teams fully implement testnet and real S3 service

This directory contains a setup for mocking S3 buckets using MinIO, specifically configured for testing the KMS Connector's ciphertext retrieval functionality.

## Features

- Mimics AWS S3 bucket structure with `ct64` and `ct128` buckets
- Supports the URL formats used by the KMS Connector:
  - Virtual-hosted style: `https://ct128.s3.${REGION_CODE}.amazonaws.com/${hex(snsCiphertextDigest)}`
  - Path-style: `https://s3.${REGION_CODE}.amazonaws.com/ct128/${hex(snsCiphertextDigest)}`
- Automatically uploads test ciphertexts from `../../core-client/artifacts/`
- Optimized for high-frequency retrieval testing (500ms intervals)

## Prerequisites

- Docker and Docker Compose

## Quick Start

Use the provided helper script to manage the MinIO server:

```bash
# Navigate to the minio-s3-mock directory
cd kms-connector/emulation/minio-s3-mock

# Start the MinIO server and set up buckets
./minio-test-helper.sh start

# List available buckets
./minio-test-helper.sh list-buckets

# List contents of a specific bucket
./minio-test-helper.sh list-contents ct64
./minio-test-helper.sh list-contents ct128

# Test URL formats with different regions
./minio-test-helper.sh test-url us-east-1

# Stop the MinIO server
./minio-test-helper.sh stop
```

## Integration with KMS Connector Tests

To use the MinIO S3 mock in your KMS Connector tests, configure the S3 settings in your test configuration file:

```toml
# In your test config file
[s3_config]
region = "us-east-1"
bucket = "ct128"  # or "ct64" depending on your test
endpoint = "http://localhost:9000"
```

This will direct the KMS Connector to use the local MinIO server for ciphertext retrieval during tests.

## Testing S3 URL Formats

The helper script includes a command to test and visualize the different S3 URL formats supported by the KMS Connector:

```bash
# Test URL formats with a specific region (defaults to us-east-1)
./minio-test-helper.sh test-url us-east-1
```

This command will:

1. Fetch a sample digest from the ct128 bucket
2. Display the virtual-hosted style URL format
3. Display the path-style URL format
4. Show the local MinIO equivalent URLs
5. Provide a command to download the file

Example output:

```bash
Testing URL format with:
Region: us-east-1
Digest: 1c37ba3cfd0151dd03584cd4819c6296d6a8b4d7ac3e31554fb0e842eab8ada9

Virtual-hosted style URL:
https://ct128.s3.us-east-1.amazonaws.com/1c37ba3cfd0151dd03584cd4819c6296d6a8b4d7ac3e31554fb0e842eab8ada9
Local equivalent:
http://localhost:9000/ct128/1c37ba3cfd0151dd03584cd4819c6296d6a8b4d7ac3e31554fb0e842eab8ada9

Path-style URL:
https://s3.us-east-1.amazonaws.com/ct128/1c37ba3cfd0151dd03584cd4819c6296d6a8b4d7ac3e31554fb0e842eab8ada9
Local equivalent:
http://localhost:9000/ct128/1c37ba3cfd0151dd03584cd4819c6296d6a8b4d7ac3e31554fb0e842eab8ada9
```

## Configuring KMS Connector to Use the Mock S3

To configure your KMS Connector to use this mock S3 server:

1. Set the S3 endpoint URL in your environment or config:

   ```bash
   S3_ENDPOINT_URL=http://localhost:9000
   ```

2. Use the standard S3 URL format in your coprocessor configuration:

   ```bash
   https://ct64.s3.us-east-1.amazonaws.com/${hex(snsCiphertextDigest)}
   https://ct128.s3.us-east-1.amazonaws.com/${hex(snsCiphertextDigest)}
   ```

3. The KMS Connector's S3 URL processing will extract:
   - Region: `us-east-1`
   - Bucket: `ct64` or `ct128`
   - And redirect requests to your local endpoint

## Downloading Files Locally

There are two simple ways to download files from the mock S3 server:

### 1. Using the helper script

```bash
# Download a file from a bucket using its digest
./minio-test-helper.sh download ct128 1c37ba3cfd0151dd03584cd4819c6296d6a8b4d7ac3e31554fb0e842eab8ada9 ./downloaded-file.bin
```

### 2. Using direct HTTP requests

```bash
# Download a file using curl
curl -o direct-download.bin "http://localhost:9000/ct128/1c37ba3cfd0151dd03584cd4819c6296d6a8b4d7ac3e31554fb0e842eab8ada9"
```

## Web Console Access

- URL: `http://localhost:9001`
- Username: minioadmin
- Password: minioadmin

## Troubleshooting

- If you encounter connection issues, make sure ports 9000 and 9001 are not in use
- Check Docker logs for detailed error messages:

  ```bash
  docker-compose logs minio
  docker-compose logs aws-cli
  ```

- For permission issues, verify that the setup scripts are executable:

  ```bash
  chmod +x setup-scripts/setup.sh
  ```
