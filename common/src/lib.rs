#[cfg(feature = "testing")]
use {
    backward_compatibility::load::{load_versioned_auxiliary, DataFormat, TestFailure},
    backward_compatibility::TestType,
    std::path::Path,
    tfhe_versionable::Unversionize,
};

/// The maximum number of iterations before terminating a loop that is expected to only iterate a couple of times.
pub const MAX_ITER: u64 = 30;

/// Helper macro to try a piece of code until it succeeds but not more than [`MAX_ITER`] times.
/// The [`func`] argument is a function that should return a `Result<Option<T>>` where `T` is the type of the result.
/// If the function returns `Ok(None)`, then the loop will continue.
/// If the function returns `Ok(Some(T))`, then the loop will stop and return `Ok(T)`.
/// If the function returns `Err(e)`, then the loop will stop and return `Err(e)`.
/// The [`max_iter`] argument is specifies the maximum number of iterations.
#[macro_export]
macro_rules! loop_fn {
    ($func:expr,$max_iter:expr) => {{
        let mut ctr = 0;
        loop {
            if ctr > $max_iter {
                break Err(anyhow::anyhow!(
                    "Failed to get result after {} tries",
                    $max_iter
                ));
            }
            ctr += 1;
            match $func().await {
                Ok(Some(inner_res)) => {
                    break Ok(inner_res);
                }
                Ok(None) => {
                    // No result is done yet so we need to go again
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
                Err(e) => {
                    // An error happened so we return this
                    break Err(anyhow::anyhow!("Loop failed with the internal error: {e}"));
                }
            }
        }
    }};
    ($func:expr) => {{
        use kms_common::MAX_ITER;
        loop_fn!($func, MAX_ITER)
    }};
}

#[macro_export]
macro_rules! impl_generic_versionize {
    ($t:ty) => {
        impl tfhe_versionable::Versionize for $t {
            type Versioned<'vers> = &'vers $t;

            fn versionize(&self) -> Self::Versioned<'_> {
                self
            }
        }

        impl tfhe_versionable::VersionizeOwned for $t {
            type VersionedOwned = $t;
            fn versionize_owned(self) -> Self::VersionedOwned {
                self
            }
        }

        impl tfhe_versionable::Unversionize for $t {
            fn unversionize(
                versioned: Self::VersionedOwned,
            ) -> Result<Self, tfhe_versionable::UnversionizeError> {
                Ok(versioned)
            }
        }

        impl tfhe_versionable::NotVersioned for $t {}
    };
}

#[cfg(feature = "testing")]
pub fn load_and_unversionize<Data: Unversionize, P: AsRef<Path>, T: TestType>(
    dir: P,
    test: &T,
    format: DataFormat,
) -> Result<Data, TestFailure> {
    let versioned = format.load_versioned_test(dir, test)?;

    Data::unversionize(versioned).map_err(|e| test.failure(e, format))
}

#[cfg(feature = "testing")]
pub fn load_and_unversionize_auxiliary<Data: Unversionize, P: AsRef<Path>, T: TestType>(
    dir: P,
    test: &T,
    auxiliary_filename: &str,
    format: DataFormat,
) -> Result<Data, TestFailure> {
    let versioned = load_versioned_auxiliary(dir, &test.test_filename(), auxiliary_filename)
        .map_err(|e| test.failure(e, format))?;

    Data::unversionize(versioned).map_err(|e| test.failure(e, format))
}
