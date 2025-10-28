use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use validator::Validate;

/// Rate limiter configuration.
///
/// The bucket size is the maximum number of tokens in the bucket.
/// The other fields are the number of tokens consumed for the
/// different operations.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Validate)]
pub struct RateLimiterConfig {
    #[validate(range(min = 1))]
    pub bucket_size: usize,
    // Everything else is u32 because semaphore works with u32
    #[validate(range(min = 1))]
    pub pub_decrypt: u32,
    #[validate(range(min = 1))]
    pub user_decrypt: u32,
    #[validate(range(min = 1))]
    pub crsgen: u32,
    #[validate(range(min = 1))]
    pub preproc: u32,
    #[validate(range(min = 1))]
    pub keygen: u32,
    #[validate(range(min = 1))]
    pub reshare: u32,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            bucket_size: 50000,
            pub_decrypt: 1,
            user_decrypt: 1,
            crsgen: 100,
            preproc: 25000,
            keygen: 1000,
            reshare: 1,
        }
    }
}

/// This is a token based rate limiter.
/// It uses Arc internally so clones of the object
/// are cheap and the internal bucket is shared.
///
/// The way it works is it setup an initial bucket of config.bucket_size
/// tokens and then every time an operation is started a certain number
/// of tokens are removed from the bucket.
/// If an operation brings the number of tokens below 0,
/// then the operation is rejected.
/// After an operation completes, the tokens held by the operation
/// is returned to the bucket.
///
/// How this is done in practice is using a semaphore.
/// The semaphore is initialized with a fixed number of tokens
/// (at the moment we do not allow dynamically increasing the bucket size).
/// Acquiring a certain number of tokens produces a permit.
/// If the acquisition operation fails then it means the rate limit has exceeded.
/// Otherwise, the permit should be held until the operation is completed.
/// Dropping the permit releases the tokens back to the bucket.
#[derive(Clone)]
pub struct RateLimiter {
    config: RateLimiterConfig,
    bucket: Arc<Semaphore>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(RateLimiterConfig::default())
    }
}

macro_rules! impl_rate_limiter_for {
    ($fn_name:ident, $token_name:ident, $token_str:expr) => {
        /// Create a rate limiting permit for the $token_name request.
        /// If the result is an error, then it means there are no more
        /// resource to support the $token_name request.
        /// The resource is returned when the permit is dropped.
        ///
        /// If there's an error, we return `ResourceExhausted`.
        pub(crate) async fn $fn_name(
            &self,
        ) -> Result<OwnedSemaphorePermit, kms_grpc::utils::tonic_result::BoxedStatus> {
            let num_tokens = self.config.$token_name;
            let cloned_bucket = Arc::clone(&self.bucket);

            let permit = cloned_bucket
                .try_acquire_many_owned(num_tokens)
                .map_err(|e| {
                    tonic::Status::resource_exhausted(format!(
                        "not enough tokens in bucket for {}, need {} from {}: {}",
                        $token_str,
                        num_tokens,
                        self.bucket.available_permits(),
                        e
                    ))
                })?;
            Ok(permit)
        }
    };
}

impl RateLimiter {
    /// Create a new rate limiter with some given configuration.
    /// The caller must ensure the configuration works well for the given operations.
    pub fn new(config: RateLimiterConfig) -> Self {
        let bucket = Arc::new(Semaphore::new(config.bucket_size));
        Self { config, bucket }
    }

    // NOTE: unfortunately macro easily cannot add prefix/suffix to identifiers
    // without using nightly or introducing extra dependencies,
    // so we we need to repeat XXX in (start_XXX, XXX).
    // We also cannot interpret an identifier as a &str expression.
    impl_rate_limiter_for!(start_pub_decrypt, pub_decrypt, "pub_decrypt");
    impl_rate_limiter_for!(start_user_decrypt, user_decrypt, "user_decrypt");
    impl_rate_limiter_for!(start_crsgen, crsgen, "crsgen");
    impl_rate_limiter_for!(start_preproc, preproc, "preproc");
    impl_rate_limiter_for!(start_keygen, keygen, "keygen");
    impl_rate_limiter_for!(start_reshare, reshare, "reshare");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiting_1() {
        let rl = RateLimiter::default();
        let permit = rl.start_pub_decrypt().await.unwrap();
        {
            assert_eq!(
                rl.bucket.available_permits(),
                rl.config.bucket_size - rl.config.pub_decrypt as usize
            );
        }
        drop(permit);
        {
            assert_eq!(rl.bucket.available_permits(), rl.config.bucket_size);
        }
    }

    #[tokio::test]
    async fn test_rate_limiting_more() {
        let rl = RateLimiter::default();
        let permit = rl.start_pub_decrypt().await.unwrap();
        {
            assert_eq!(
                rl.bucket.available_permits(),
                rl.config.bucket_size - rl.config.pub_decrypt as usize
            );
        }
        let rl2 = &rl.clone();
        let permit2 = rl2.start_crsgen().await.unwrap();
        {
            assert_eq!(
                rl2.bucket.available_permits(),
                rl2.config.bucket_size - (rl2.config.pub_decrypt + rl2.config.crsgen) as usize
            );
        }
        drop(permit);
        drop(permit2);
        {
            assert_eq!(rl.bucket.available_permits(), rl.config.bucket_size);
        }
    }

    #[tokio::test]
    async fn test_rate_limiting_refusal() {
        let rl = RateLimiter::new(RateLimiterConfig {
            bucket_size: 10,
            pub_decrypt: 10,
            user_decrypt: 1,
            crsgen: 1,
            preproc: 1,
            keygen: 1,
            reshare: 1,
        });

        // first pub_decryptryption is ok, but uses all tokens
        let _permit = rl.start_pub_decrypt().await.unwrap();
        {
            assert_eq!(
                rl.bucket.available_permits(),
                rl.config.bucket_size - rl.config.pub_decrypt as usize
            );
        }

        // second operation should be refused
        rl.start_user_decrypt().await.unwrap_err();

        // drop the first permit
        drop(_permit);

        // second operation should work fine
        let _permit_2 = rl.start_user_decrypt().await.unwrap();
    }
}
