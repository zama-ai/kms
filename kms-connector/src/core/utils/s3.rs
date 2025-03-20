use alloy::primitives::Address;
use alloy::providers::Provider;
use aws_config::BehaviorVersion;
use aws_sdk_s3::{config::Region, Client as S3Client};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use sha3::{Digest, Keccak256};
use std::{sync::Arc, time::Duration};
use tracing::{debug, error, info, warn};

use crate::{
    core::config::S3Config,
    error::{Error, Result},
    gwl2_contracts::HTTPZ,
};

// Global cache for coprocessor S3 bucket URLs
static S3_BUCKET_CACHE: Lazy<DashMap<Address, String>> = Lazy::new(DashMap::new);

/// Retrieves the S3 bucket URL for a coprocessor from the HTTPZ contract
pub async fn call_httpz_to_get_s3_url<P: Provider + Clone>(
    coprocessor_address: Address,
    httpz_address: Address,
    provider: Arc<P>,
) -> Result<String> {
    // Try to find a cached S3 bucket URL for any of the coprocessors
    if let Some(url) = S3_BUCKET_CACHE.get(&coprocessor_address) {
        debug!(
            "Using cached S3 bucket URL for coprocessor {:?}: {}",
            coprocessor_address,
            url.value()
        );
        return Ok(url.value().clone());
    }

    // If no cached URL found, query the HTTPZ contract for the first available coprocessor
    info!(
        "Querying HTTPZ contract for coprocessor {:?} S3 bucket URL",
        coprocessor_address
    );

    // Create HTTPZ contract instance
    let contract = HTTPZ::new(httpz_address, provider);

    // Call getCoprocessor method
    let coprocessor = contract
        .coprocessors(coprocessor_address)
        .call()
        .await
        .map_err(|e| {
            Error::S3Error(format!(
                "Failed to get coprocessor from HTTPZ contract: {}",
                e
            ))
        })?;

    // Extract S3 bucket URL from the coprocessor
    let s3_bucket_url = coprocessor.s3BucketUrl.to_string();

    if s3_bucket_url.is_empty() {
        return Err(Error::S3Error(format!(
            "Coprocessor {:?} has empty S3 bucket URL",
            coprocessor_address
        )));
    }

    // Cache the URL for future use
    S3_BUCKET_CACHE.insert(coprocessor_address, s3_bucket_url.clone());

    info!(
        "Retrieved and cached S3 bucket URL for coprocessor {:?}: {}",
        coprocessor_address, s3_bucket_url
    );
    Ok(s3_bucket_url)
}

/// Process an S3 bucket URL to extract the region, endpoint URL, and bucket name
///
/// Handles various S3 URL formats:
/// - Standard AWS URLs: https://bucket-name.s3.region.amazonaws.com
/// - Path-style URLs: https://s3.region.amazonaws.com/bucket-name
/// - Custom endpoints: https://custom-endpoint.com/bucket-name
///
/// Returns Option with tuple of (region, endpoint_url, bucket) or None if extraction fails
fn process_s3_bucket_url(s3_bucket_url: String) -> Option<(String, String, String)> {
    // Parse the URL
    let url = match url::Url::parse(&s3_bucket_url) {
        Ok(url) => url,
        Err(_) => {
            // If URL parsing fails, extract region from original URL if possible
            warn!("Failed to parse S3 bucket URL: {}", s3_bucket_url);

            // Try to extract region from raw URL string
            if let Some(_region) = extract_region_from_raw_url(&s3_bucket_url) {
                // For raw URLs, we can't reliably extract the bucket
                warn!(
                    "Could extract region but not bucket from unparseable URL: {}",
                    s3_bucket_url
                );
                return None;
            }

            // If we can't extract region, log and return None
            warn!(
                "Could not extract region from S3 bucket URL: {}",
                s3_bucket_url
            );
            return None;
        }
    };

    // Extract hostname
    let host = match url.host_str() {
        Some(host) => host,
        None => {
            warn!("No host in S3 bucket URL: {}", s3_bucket_url);
            return None;
        }
    };

    // Check if it's an AWS S3 URL
    if host.contains("amazonaws.com") {
        // Try to extract region from hostname
        let parts: Vec<&str> = host.split('.').collect();

        // Handle bucket-name.s3.region.amazonaws.com format (virtual-hosted style)
        if parts.len() >= 4 && parts[1] == "s3" {
            let bucket = parts[0].to_string();
            return Some((parts[2].to_string(), format!("https://{}", host), bucket));
        }

        // Handle s3.region.amazonaws.com/bucket-name format (path-style)
        if parts.len() >= 3 && parts[0] == "s3" {
            // For path-style URLs, the bucket is the first path segment
            if let Some(path) = url.path_segments() {
                let path_segments: Vec<&str> = path.collect();
                if !path_segments.is_empty() {
                    let bucket = path_segments[0].to_string();
                    return Some((parts[1].to_string(), format!("https://{}", host), bucket));
                }
            }

            // If we can't extract the bucket from the path, log and return None
            warn!(
                "Could not extract bucket from path-style S3 URL: {}",
                s3_bucket_url
            );
            return None;
        }
    }

    // For custom endpoints, check path segments for region and bucket
    let path_segments: Vec<&str> = url
        .path_segments()
        .map_or(Vec::new(), |segments| segments.collect());

    // Check for region in path (some S3-compatible services put region in path)
    for (i, segment) in path_segments.iter().enumerate() {
        if *segment == "s3" && i + 1 < path_segments.len() {
            // Region is at i+1, bucket might be at i+2
            let region = path_segments[i + 1].to_string();

            // Try to extract bucket from the path
            if i + 2 < path_segments.len() {
                let bucket = path_segments[i + 2].to_string();
                return Some((region, format!("{}://{}", url.scheme(), host), bucket));
            }

            // If we can't extract the bucket, log and return None
            warn!(
                "Could extract region but not bucket from URL: {}",
                s3_bucket_url
            );
            return None;
        }
    }

    // If we can't determine the region, log and return None
    warn!(
        "Could not extract region from S3 bucket URL: {}",
        s3_bucket_url
    );
    None
}

/// Try to extract region from a raw URL string when URL parsing fails
fn extract_region_from_raw_url(raw_url: &str) -> Option<String> {
    // Look for patterns like .s3.REGION.amazonaws.com or s3.REGION.amazonaws.com
    if let Some(idx) = raw_url.find("amazonaws.com") {
        let prefix = &raw_url[..idx];

        // Try to find s3.REGION. pattern
        if let Some(s3_idx) = prefix.find("s3.") {
            let after_s3 = &prefix[s3_idx + 3..];
            if let Some(dot_idx) = after_s3.find('.') {
                return Some(after_s3[..dot_idx].to_string());
            }
        }
    }

    None
}

/// Compute Keccak256 digest of a byte array
pub fn compute_digest(ct: &[u8]) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(ct);
    hasher.finalize().to_vec()
}

/// Retrieves a ciphertext from S3 using the bucket URL and ciphertext digest
pub async fn call_s3_ciphertext_retrieval(
    s3_bucket_url: String,
    ciphertext_digest: Vec<u8>,
    s3_config: Option<S3Config>,
) -> Result<Vec<u8>> {
    let digest_hex = alloy::hex::encode(&ciphertext_digest);
    info!(
        "Retrieving ciphertext with digest {} from S3 bucket {}",
        digest_hex, s3_bucket_url
    );

    // Process S3 bucket URL to extract region and endpoint
    let (extracted_region, s3_url, extracted_bucket) =
        match process_s3_bucket_url(s3_bucket_url.clone()) {
            Some((extracted_region, url, extracted_bucket)) => {
                (Some(extracted_region), Some(url), Some(extracted_bucket))
            }
            None => {
                // Fall back to provided region and bucket if URL processing fails
                warn!(
                    "Using default fallback region, s3 endpoint and bucket for S3 URL: {}",
                    s3_bucket_url
                );
                match &s3_config {
                    Some(config) => (
                        Some(config.region.clone()),
                        config.endpoint.clone(),
                        Some(config.bucket.clone()),
                    ),
                    None => (None, None, None),
                }
            }
        };

    // If we don't have all required S3 configuration, we can't proceed
    if extracted_region.is_none() || s3_url.is_none() || extracted_bucket.is_none() {
        return Err(Error::S3Error(format!(
            "Cannot retrieve ciphertext - missing required S3 configuration for URL: {}",
            s3_bucket_url
        )));
    }

    let region = extracted_region.unwrap();
    let endpoint_url = s3_url.unwrap();
    let bucket = extracted_bucket.unwrap();

    // Create S3 client with custom timeout and retry configs
    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region))
        .endpoint_url(&endpoint_url)
        .timeout_config(
            aws_sdk_s3::config::timeout::TimeoutConfig::builder()
                .operation_timeout(Duration::from_secs(1))
                .operation_attempt_timeout(Duration::from_millis(750))
                .build(),
        )
        .retry_config(
            aws_sdk_s3::config::retry::RetryConfig::standard()
                .with_max_attempts(2)
                .with_initial_backoff(Duration::from_millis(50)),
        )
        .load()
        .await;

    let client = S3Client::new(&config);

    // Get the object from S3
    let resp = client
        .get_object()
        .bucket(bucket)
        .key(digest_hex)
        .send()
        .await
        .map_err(|e| Error::S3Error(format!("Failed to retrieve object from S3: {}", e)))?;

    // Read the object body
    let body = resp
        .body
        .collect()
        .await
        .map_err(|e| Error::S3Error(format!("Failed to read S3 object body: {}", e)))?;

    let ciphertext = body.into_bytes().to_vec();
    debug!(
        "Successfully retrieved ciphertext of size {} bytes",
        ciphertext.len()
    );

    // Verify the digest of the retrieved ciphertext
    let calculated_digest = compute_digest(&ciphertext);
    if calculated_digest != ciphertext_digest {
        return Err(Error::S3Error(format!(
            "Digest mismatch for ciphertext retrieved from S3. Expected: {}, Got: {}",
            alloy::hex::encode(&ciphertext_digest),
            alloy::hex::encode(&calculated_digest)
        )));
    }
    debug!("Successfully verified ciphertext digest");

    Ok(ciphertext)
}

/// Prefetches and caches S3 bucket URLs to return a list of coprocessor s3 urls
pub async fn prefetch_coprocessor_buckets<P: Provider + Clone>(
    coprocessor_addresses: Vec<Address>,
    httpz_address: Address,
    provider: Arc<P>,
) -> Result<Vec<String>> {
    info!(
        "Prefetching S3 bucket URLs for {} coprocessors",
        coprocessor_addresses.len()
    );
    let mut s3_urls = Vec::new();
    let mut success_count = 0;
    for address in &coprocessor_addresses {
        if S3_BUCKET_CACHE.contains_key(address) {
            debug!("S3 bucket URL for coprocessor {:?} already cached", address);
            success_count += 1;
            continue;
        }

        match call_httpz_to_get_s3_url(*address, httpz_address, provider.clone()).await {
            Ok(s3_url) => {
                success_count += 1;
                s3_urls.push(s3_url);
            }
            Err(e) => {
                error!(
                    "Failed to prefetch S3 bucket URL for coprocessor {:?}: {}",
                    address, e
                );
            }
        };
    }

    info!(
        "Successfully prefetched {}/{} S3 bucket URLs",
        success_count,
        coprocessor_addresses.len()
    );
    Ok(s3_urls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_s3_bucket_url_virtual_hosted() {
        // Test virtual-hosted style URL (bucket-name.s3.region.amazonaws.com)
        let url = "https://my-bucket.s3.us-west-2.amazonaws.com/path/to/object".to_string();
        let result = process_s3_bucket_url(url);
        assert!(result.is_some());
        let (region, endpoint, bucket) = result.unwrap();
        assert_eq!(region, "us-west-2");
        assert_eq!(endpoint, "https://my-bucket.s3.us-west-2.amazonaws.com");
        assert_eq!(bucket, "my-bucket");
    }

    #[test]
    fn test_process_s3_bucket_url_path_style() {
        // Test path-style URL (s3.region.amazonaws.com/bucket-name)
        let url = "https://s3.eu-central-1.amazonaws.com/my-bucket/path/to/object".to_string();
        let result = process_s3_bucket_url(url);
        assert!(result.is_some());
        let (region, endpoint, bucket) = result.unwrap();
        assert_eq!(region, "eu-central-1");
        assert_eq!(endpoint, "https://s3.eu-central-1.amazonaws.com");
        assert_eq!(bucket, "my-bucket");
    }

    #[test]
    fn test_process_s3_bucket_url_path_region() {
        // Test URL with region in path
        let url = "https://storage.example.com/s3/ap-southeast-1/my-bucket/object".to_string();
        let result = process_s3_bucket_url(url);
        assert!(result.is_some());
        let (region, endpoint, bucket) = result.unwrap();
        assert_eq!(region, "ap-southeast-1");
        assert_eq!(endpoint, "https://storage.example.com");
        assert_eq!(bucket, "my-bucket");
    }

    #[test]
    fn test_extract_region_from_raw_url() {
        // Test extracting region from raw URL string
        let raw_url = "https://bucket.s3.ca-central-1.amazonaws.com/object";
        let region = extract_region_from_raw_url(raw_url);
        assert_eq!(region, Some("ca-central-1".to_string()));
    }

    #[test]
    fn test_extract_region_from_raw_url_no_region() {
        // Test extracting region from raw URL with no region
        let raw_url = "https://storage.example.com/bucket/object";
        let region = extract_region_from_raw_url(raw_url);
        assert_eq!(region, None);
    }

    #[test]
    fn test_process_s3_bucket_url_no_region() {
        // Test URL with no extractable region - should return None
        let url = "https://storage.example.com/bucket/object".to_string();
        let result = process_s3_bucket_url(url);
        assert!(result.is_none());
    }

    #[test]
    fn test_process_s3_bucket_url_with_dashes() {
        // Test URL with region containing dashes
        let url = "https://my-bucket.s3.us-east-1.amazonaws.com/object".to_string();
        let result = process_s3_bucket_url(url);
        assert!(result.is_some());
        let (region, endpoint, bucket) = result.unwrap();
        assert_eq!(region, "us-east-1");
        assert_eq!(endpoint, "https://my-bucket.s3.us-east-1.amazonaws.com");
        assert_eq!(bucket, "my-bucket");
    }

    #[test]
    fn test_process_s3_bucket_url_with_numbers() {
        // Test URL with region containing numbers
        let url = "https://s3.ap-northeast-2.amazonaws.com/my-bucket/object".to_string();
        let result = process_s3_bucket_url(url);
        assert!(result.is_some());
        let (region, endpoint, bucket) = result.unwrap();
        assert_eq!(region, "ap-northeast-2");
        assert_eq!(endpoint, "https://s3.ap-northeast-2.amazonaws.com");
        assert_eq!(bucket, "my-bucket");
    }

    #[test]
    fn test_compute_digest_empty_input() {
        // Test digest calculation for empty input
        let empty_data: Vec<u8> = vec![];
        let digest = compute_digest(&empty_data);

        // Keccak256 of empty input is a known value
        let expected_hex = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
        let expected_bytes = alloy::hex::decode(expected_hex).unwrap();

        assert_eq!(digest, expected_bytes);
        assert_eq!(digest.len(), 32); // Keccak256 produces 32 bytes
    }

    #[test]
    fn test_compute_digest_known_input() {
        // Test digest calculation for a known input
        let data = b"hello world";
        let digest = compute_digest(data);

        // Known Keccak256 hash of "hello world"
        let expected_hex = "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad";
        let expected_bytes = alloy::hex::decode(expected_hex).unwrap();

        assert_eq!(digest, expected_bytes);
    }

    #[test]
    fn test_compute_digest_different_inputs() {
        // Test that different inputs produce different digests
        let data1 = b"test data 1";
        let data2 = b"test data 2";

        let digest1 = compute_digest(data1);
        let digest2 = compute_digest(data2);

        assert_ne!(digest1, digest2);
    }

    #[test]
    fn test_compute_digest_large_input() {
        // Test digest calculation for a larger input
        let large_data = vec![0u8; 1024 * 1024]; // 1MB of zeros
        let digest = compute_digest(&large_data);

        // Verify the digest length is correct
        assert_eq!(digest.len(), 32);
    }
}
