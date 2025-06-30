# MetaStore Status API Exploration Script

Explore MetaStore Status service gRPC APIs in the KMS system.

## Purpose

The script serves as a convenience tool for:

- Exploring meta-store capacity and configuration
- Checking the status of requests across different meta-store types  
- Understanding the current state of the KMS system
- Learning how to interact with the MetaStore Status service APIs

## System Prerequisites

Before using these scripts, you need a running KMS system. For development setup instructions, see the [Development Environment](../../README.md#development-environment) section in the main README.

Also, make sure you have installed the required dependencies:

- `bash` (latest version)
- `curl` (latest version)
- `grpcurl` (latest version)
- `jq` (latest version)

Run the script from a directory with write permissions (e.g. your app home directory)

## Usage

```bash
chmod +x ./core/grpc/api_test_suite/test_metastore_status_apis.sh                    # Make script executable
./core/grpc/api_test_suite/test_metastore_status_apis.sh                            # Basic exploration
./core/grpc/api_test_suite/test_metastore_status_apis.sh --request-id <id>          # Single request status lookup
./core/grpc/api_test_suite/test_metastore_status_apis.sh --request-id <id1> <id2>   # Multiple request status lookup
./core/grpc/api_test_suite/test_metastore_status_apis.sh --help                     # Show help
```

## API Endpoints

### 1. GetMetaStoreInfo

- **Purpose**: Get capacity and configuration information for all meta-stores
- **Returns**: List of meta-stores with their types and capacity limits

### 2. ListRequests  

- **Purpose**: List requests for each meta-store type
- **Coverage**: Tests all 5 meta-store types:
  - KEY_GENERATION
  - PUBLIC_DECRYPTION  
  - USER_DECRYPTION
  - CRS_GENERATION
  - PREPROCESSING

### 3. GetRequestStatuses (Optional)

- **Purpose**: Check status of specific request IDs
- **Usage**: Modify the script to include actual request IDs from previous operations
- **Default**: Shows example usage with dummy IDs (will return NotFound)

## API Response Examples

### GetMetaStoreInfo

```json
{
  "metaStores": [
    {
      "type": "KEY_GENERATION",
      "capacity": -1,      // -1 = infinite capacity
      "currentCount": 2    // Current number of received requests 
    },
    {
      "type": "PUBLIC_DECRYPTION",
      "capacity": 10000
    },
    {                           
      "type": "USER_DECRYPTION",
      "capacity": 10000        
    },
    {
      "type": "CRS_GENERATION",                                                        
      "capacity": -1          
    },
    {
      "type": "PREPROCESSING",                                                         
      "capacity": -1,                                                                  
      "currentCount": 1                 
    }
  ]
}
```

### ListRequests

```json
--- KEY_GENERATION ---
{
  "requests": [
    {
      "requestId": "bc0cbac18cb2b4a03c3fd2ebc0865dca421424a5b1ca9d2a42037a1f90109938",
      "metaStoreType": "KEY_GENERATION",
      "status": "COMPLETED"                                                                                                    
    },
    {
      "requestId": "8366a89bc317c29ecacffe1585414f515cc3786fa99f1b6225153947f75a20a1",
      "metaStoreType": "KEY_GENERATION"   
      // Missing status field = PROCESSING
    }
  ]
}                                                                                                             
--- PUBLIC_DECRYPTION ---
{}

--- USER_DECRYPTION ---
{}

--- CRS_GENERATION ---
{}

--- PREPROCESSING ---
{
  "requests": [
    {
      "requestId": "c145eea84c3e67dea78fc56dbecab3313de3f76a4bf647129ac7982520f5ef9d",
      "metaStoreType": "PREPROCESSING",
      "status": "COMPLETED"
    }
  ]
}
```

### GetRequestStatuses

```json
{
  "statuses": [
    {
      "requestId": "fe01a0436af259fcaeb24965086f89f7b8d60b5f65c8025e32bdd273bf89e63b",
      "metaStoreType": "PREPROCESSING"
      // Missing status field = PROCESSING
    }
  ]
}

{
  "statuses": [
    {
      "requestId": "bc0cbac18cb2b4a03c3fd2ebc0865dca421424a5b1ca9d2a42037a1f90109938",
      "metaStoreType": "KEY_GENERATION",
      "status": "COMPLETED"
    }
  ]
}
```

## Important: Status Field Behavior

**Protobuf3 JSON Serialization:** The `status` field follows protobuf3 conventions where fields with default values are omitted from JSON output for efficiency.

**Status Field Rules:**

- **Missing `status` field** = `PROCESSING` (default value, enum = 0)
- **Explicit `status` field** = `COMPLETED` (enum = 1) or `FAILED` (enum = 2)

**Examples:**

```json
// Request in PROCESSING state (most common)
{
  "requestId": "abc123",
  "metaStoreType": "PREPROCESSING"
  // No status field = PROCESSING
}

// Request in COMPLETED state  
{
  "requestId": "def456",
  "metaStoreType": "KEY_GENERATION",
  "status": "COMPLETED"
}

// Request in FAILED state
{
  "requestId": "ghi789",
  "metaStoreType": "USER_DECRYPTION", 
  "status": "FAILED",
  "errorMessage": "Decryption failed"
}
```

This behavior optimizes network efficiency by reducing payload size while maintaining semantic clarity.

## Configuration

You can modify these variables at the top of the script:

- `SERVER_HOST`: gRPC server address (default: `localhost:50100`)
- `IMPORT_PATH`: Path to proto files (default: `core/grpc/proto`)  
- `PROTO_FILE`: MetaStore Status proto file name

## Expected Results

### With No Active Operations

- **GetMetaStoreInfo**: Shows meta-store capacities and types
- **ListRequests**: Returns empty results `{}` for all store types
- **GetRequestStatuses**: Returns NotFound errors for dummy request IDs

### With Active Operations  

- **ListRequests**: Shows actual request data with IDs, status, meta-store type
- **GetRequestStatuses**: Returns detailed status information for the requested RequestIDs

## Troubleshooting

- **Connection errors**: Ensure the KMS server is running on the correct port
- **Proto file errors**: Verify the proto files exist in the expected location
- **Permission errors**: Make sure the script is executable (`chmod +x test_metastore_status_apis.sh`)

## Notes

- The server doesn't support gRPC reflection, so the script calls endpoints directly
- Empty results are normal when no operations have been performed
- The script is designed for exploration and learning, not automated testing
