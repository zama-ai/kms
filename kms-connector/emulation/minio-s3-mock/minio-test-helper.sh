#!/bin/bash
set -e

# Colors for better readability
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

MINIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$MINIO_DIR"

# Function to run AWS CLI commands via Docker
function run_aws_cli() {
    docker run --rm --network minio-s3-mock_default \
        -e AWS_ACCESS_KEY_ID=minioadmin \
        -e AWS_SECRET_ACCESS_KEY=minioadmin \
        -e AWS_DEFAULT_REGION=us-east-1 \
        amazon/aws-cli:latest \
        --endpoint-url http://minio:9000 "$@"
}

function start_minio() {
    echo -e "${GREEN}Starting MinIO S3 mock server...${NC}"
    docker-compose up -d
    
    # Wait for setup to complete
    echo -e "${YELLOW}Waiting for setup to complete...${NC}"
    docker-compose logs -f aws-cli | grep -q "Setup complete!" || sleep 15
    
    echo -e "${GREEN}MinIO S3 mock server is running!${NC}"
    echo -e "${BLUE}Web console: http://localhost:9001${NC}"
    echo -e "${BLUE}S3 API endpoint: http://localhost:9000${NC}"
    echo -e "${BLUE}Login credentials: minioadmin / minioadmin${NC}"
}

function stop_minio() {
    echo -e "${GREEN}Stopping MinIO S3 mock server...${NC}"
    docker-compose down
    echo -e "${GREEN}MinIO S3 mock server stopped.${NC}"
}

function list_buckets() {
    echo -e "${GREEN}Listing buckets:${NC}"
    run_aws_cli s3 ls
}

function list_bucket_contents() {
    local bucket=$1
    if [ -z "$bucket" ]; then
        echo -e "${YELLOW}Please specify a bucket name (ct64 or ct128)${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Listing contents of bucket $bucket:${NC}"
    run_aws_cli s3 ls s3://$bucket/
}

function test_url_format() {
    local region=${1:-us-east-1}
    
    # Get a digest from the bucket
    echo -e "${YELLOW}Fetching a sample digest from the bucket...${NC}"
    local digest=$(run_aws_cli s3 ls s3://ct128/ | head -1 | awk '{print $4}')
    
    if [ -z "$digest" ]; then
        echo -e "${YELLOW}No files found in ct128 bucket. Using a placeholder digest.${NC}"
        digest="sample-digest-placeholder"
    fi
    
    echo -e "${GREEN}Testing URL format with:${NC}"
    echo -e "${BLUE}Region: $region${NC}"
    echo -e "${BLUE}Digest: $digest${NC}"
    
    # Virtual-hosted style URL
    echo -e "${YELLOW}Virtual-hosted style URL:${NC}"
    echo -e "https://ct128.s3.$region.amazonaws.com/$digest"
    echo -e "${YELLOW}Local equivalent:${NC}"
    echo -e "http://localhost:9000/ct128/$digest"
    
    # Path-style URL
    echo -e "${YELLOW}Path-style URL:${NC}"
    echo -e "https://s3.$region.amazonaws.com/ct128/$digest"
    echo -e "${YELLOW}Local equivalent:${NC}"
    echo -e "http://localhost:9000/ct128/$digest"
    
    echo -e "${GREEN}To download the file using Docker:${NC}"
    echo -e "docker run --rm --network minio-s3-mock_default -v \$(pwd):/data -e AWS_ACCESS_KEY_ID=minioadmin -e AWS_SECRET_ACCESS_KEY=minioadmin amazon/aws-cli:latest s3 cp s3://ct128/$digest /data/downloaded-ciphertext.bin --endpoint-url http://minio:9000"
}

function download_file() {
    local bucket=$1
    local digest=$2
    local output_file=$3
    
    if [ -z "$bucket" ] || [ -z "$digest" ]; then
        echo -e "${YELLOW}Please specify bucket and digest${NC}"
        echo -e "Usage: $0 download BUCKET DIGEST [OUTPUT_FILE]"
        return 1
    fi
    
    if [ -z "$output_file" ]; then
        output_file="./downloaded-ciphertext.bin"
    fi
    
    echo -e "${GREEN}Downloading file from s3://$bucket/$digest to $output_file...${NC}"
    docker run --rm --network minio-s3-mock_default \
        -v "$(pwd):/data" \
        -e AWS_ACCESS_KEY_ID=minioadmin \
        -e AWS_SECRET_ACCESS_KEY=minioadmin \
        amazon/aws-cli:latest \
        s3 cp s3://$bucket/$digest /data/$(basename "$output_file") --endpoint-url http://minio:9000
    
    echo -e "${GREEN}File downloaded to $output_file${NC}"
}

function show_help() {
    echo -e "${GREEN}MinIO S3 Mock Test Helper${NC}"
    echo -e "Usage: $0 [command]"
    echo -e ""
    echo -e "Commands:"
    echo -e "  ${BLUE}start${NC}              Start the MinIO S3 mock server"
    echo -e "  ${BLUE}stop${NC}               Stop the MinIO S3 mock server"
    echo -e "  ${BLUE}list-buckets${NC}       List all buckets"
    echo -e "  ${BLUE}list-contents${NC} BUCKET  List contents of the specified bucket (ct64 or ct128)"
    echo -e "  ${BLUE}test-url${NC} [REGION]  Test URL formats with optional region"
    echo -e "  ${BLUE}download${NC} BUCKET DIGEST [OUTPUT_FILE]  Download a file from the bucket"
    echo -e "  ${BLUE}help${NC}               Show this help message"
    echo -e ""
    echo -e "Example usage for KMS Connector testing:"
    echo -e "  1. Start the MinIO server: ${YELLOW}$0 start${NC}"
    echo -e "  2. Configure your KMS Connector to use these S3 bucket URLs:"
    echo -e "     - ${YELLOW}https://ct64.s3.us-east-1.amazonaws.com/\${hex(snsCiphertextDigest)}${NC}"
    echo -e "     - ${YELLOW}https://ct128.s3.us-east-1.amazonaws.com/\${hex(snsCiphertextDigest)}${NC}"
    echo -e "  3. Override the AWS endpoint in your KMS Connector config:"
    echo -e "     ${YELLOW}S3_ENDPOINT_URL=http://localhost:9000${NC}"
    echo -e "  4. When done testing, stop the server: ${YELLOW}$0 stop${NC}"
}

case "$1" in
    start)
        start_minio
        ;;
    stop)
        stop_minio
        ;;
    list-buckets)
        list_buckets
        ;;
    list-contents)
        list_bucket_contents "$2"
        ;;
    test-url)
        test_url_format "$2"
        ;;
    download)
        download_file "$2" "$3" "$4"
        ;;
    help|--help|-h|"")
        show_help
        ;;
    *)
        echo -e "${YELLOW}Unknown command: $1${NC}"
        show_help
        exit 1
        ;;
esac
