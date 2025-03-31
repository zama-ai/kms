#!/bin/sh
# Exit on command errors and treat unset variables as an error
set -e

# Wait for MinIO to be ready
echo "Waiting for MinIO to be ready..."
sleep 5

# Configure AWS CLI to use MinIO
echo "Configuring AWS CLI..."
aws configure set default.s3.addressing_style path
aws configure set default.s3.signature_version s3v4

# Create endpoint configuration for MinIO
echo "Configuring MinIO endpoint..."
aws configure set default.s3.endpoint_url http://minio:9000

# Create the buckets (ignore errors if they already exist)
echo "Creating S3 buckets (if they don't exist)..."
aws s3 mb s3://ct64 --endpoint-url http://minio:9000 || echo "Bucket ct64 already exists"
aws s3 mb s3://ct128 --endpoint-url http://minio:9000 || echo "Bucket ct128 already exists"

# Set bucket policy to allow public read access - one policy per bucket
echo "Setting bucket policies..."

# Policy for ct64
cat > /tmp/ct64-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::ct64/*"
        }
    ]
}
EOF

# Policy for ct128
cat > /tmp/ct128-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::ct128/*"
        }
    ]
}
EOF

echo "Applying bucket policies..."
aws s3api put-bucket-policy --bucket ct64 --policy file:///tmp/ct64-policy.json --endpoint-url http://minio:9000 || echo "Failed to set policy for ct64"
aws s3api put-bucket-policy --bucket ct128 --policy file:///tmp/ct128-policy.json --endpoint-url http://minio:9000 || echo "Failed to set policy for ct128"

# Check if the artifacts directory exists and has files
echo "Checking artifacts directory..."
ls -la /artifacts || echo "Warning: Artifacts directory not accessible"

# Upload ciphertext files to the buckets
echo "Uploading ciphertext files..."

# For ct64 bucket (smaller ciphertexts)
echo "Uploading to ct64 bucket..."
for file in /artifacts/output-file-1.bin /artifacts/output-file-2.bin; do
  if [ -f "$file" ]; then
    DIGEST=$(sha256sum "$file" | cut -d' ' -f1)
    echo "Uploading $file with digest $DIGEST to ct64"
    aws s3 cp "$file" "s3://ct64/$DIGEST" --endpoint-url http://minio:9000
  else
    echo "Warning: File $file not found"
  fi
done

# For ct128 bucket (larger ciphertexts)
echo "Uploading to ct128 bucket..."
for file in /artifacts/output-file-3.bin /artifacts/output-file-4.bin /artifacts/output-file-5.bin; do
  if [ -f "$file" ]; then
    DIGEST=$(sha256sum "$file" | cut -d' ' -f1)
    echo "Uploading $file with digest $DIGEST to ct128"
    aws s3 cp "$file" "s3://ct128/$DIGEST" --endpoint-url http://minio:9000
  else
    echo "Warning: File $file not found"
  fi
done

# List the contents of the buckets to verify
echo "Listing bucket contents:"
echo "ct64 bucket:"
aws s3 ls s3://ct64 --endpoint-url http://minio:9000
echo "ct128 bucket:"
aws s3 ls s3://ct128 --endpoint-url http://minio:9000

echo "Setup complete!"
