#!/bin/bash

# Simple MetaStore Status API exploration script
# Usage: ./test_metastore_status_apis.sh [--request-id <id1> [<id2> ...]] [--help]

SERVER="localhost:50100"
PROTO_PATH="core/grpc/proto"
PROTO_FILE="metastore-status.v1.proto"

# Parse command line arguments
REQUEST_IDS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --request-id)
            shift
            # Collect all request IDs until next option or end
            while [[ $# -gt 0 && ! "$1" =~ ^-- ]]; do
                REQUEST_IDS+=("$1")
                shift
            done
            ;;
        --help)
            echo "Usage: $0 [--request-id <id1> [<id2> ...]] [--help]"
            echo ""
            echo "Options:"
            echo "  --request-id <id1> [<id2> ...]  Call GetRequestStatuses with one or more request IDs"
            echo "  --help                          Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                                    # List all stores and requests"
            echo "  $0 --request-id abc123                               # Get status for one request"
            echo "  $0 --request-id abc123 def456 ghi789                 # Get status for multiple requests"
            echo ""
            echo "Without --request-id: calls GetMetaStoreInfo and ListRequests"
            echo "With --request-id: calls GetRequestStatuses only for the specified ID(s)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check server connectivity
if ! grpcurl -plaintext -import-path "$PROTO_PATH" -proto "$PROTO_FILE" -d '{}' "$SERVER" metastore_status.v1.MetaStoreStatusService/GetMetaStoreInfo >/dev/null 2>&1; then
    echo "Error: Cannot connect to server at $SERVER"
    exit 1
fi

# If request IDs provided, only call GetRequestStatuses
if [[ ${#REQUEST_IDS[@]} -gt 0 ]]; then
    # Build JSON array from request IDs
    json_array=""
    for i in "${!REQUEST_IDS[@]}"; do
        if [[ $i -eq 0 ]]; then
            json_array="\"${REQUEST_IDS[$i]}\""
        else
            json_array="$json_array, \"${REQUEST_IDS[$i]}\""
        fi
    done
    
    echo "=== GetRequestStatuses for ${#REQUEST_IDS[@]} ID(s): ${REQUEST_IDS[*]} ==="
    grpcurl -plaintext -import-path "$PROTO_PATH" -proto "$PROTO_FILE" \
        -d "{\"request_ids\": [$json_array]}" \
        "$SERVER" metastore_status.v1.MetaStoreStatusService/GetRequestStatuses
    exit 0
fi

# Otherwise, call GetMetaStoreInfo and ListRequests
echo "=== GetMetaStoreInfo ==="
grpcurl -plaintext -import-path "$PROTO_PATH" -proto "$PROTO_FILE" -d '{}' "$SERVER" metastore_status.v1.MetaStoreStatusService/GetMetaStoreInfo

echo ""
echo "=== ListRequests ==="

# List requests for each meta-store type
for store_type in "KEY_GENERATION" "PUBLIC_DECRYPTION" "USER_DECRYPTION" "CRS_GENERATION" "PREPROCESSING"; do
    echo "--- $store_type ---"
    grpcurl -plaintext -import-path "$PROTO_PATH" -proto "$PROTO_FILE" \
        -d "{\"meta_store_type\": \"$store_type\", \"status_filter\": \"ANY\"}" \
        "$SERVER" metastore_status.v1.MetaStoreStatusService/ListRequests
done
