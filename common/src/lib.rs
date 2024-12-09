#[cfg(feature = "testing")]
use {
    backward_compatibility::load::{load_versioned_auxiliary, DataFormat, TestFailure},
    backward_compatibility::TestType,
    std::path::Path,
    tfhe_versionable::Unversionize,
};

/// The maximum number of iterations before terminating a loop that is expected to only iterate a couple of times.
pub const MAX_ITER: u64 = 30;
/// The number of milliseconds to sleep between iterations of a loop.
pub const SLEEP_MS: u64 = 1000;

/// Helper macro to try a piece of code until it succeeds but not more than [`MAX_ITER`] times with a constant sleep time after each iteration.
/// The [`func`] argument is a function that should return a `Result<T>`.
/// If the function returns `Ok(T)`, then the loop will stop and return `Ok(T)`.
/// If the function returns `Err(e)`, then the loop will continue.
/// The [`max_iter`] argument is specifies the maximum number of iterations.
#[macro_export]
macro_rules! loop_fn {
    ($func:expr,$ms_sleep:expr,$max_iter:expr) => {{
        let mut ctr = 0;
        let mut last_error = "".to_string();
        loop {
            if ctr > $max_iter {
                break Err(anyhow::anyhow!(
                    "Loop failed to get result after {} tries. The last error was: {}.",
                    $max_iter,
                    last_error
                )
                .into());
            }
            match $func().await {
                Ok(inner_res) => {
                    break Ok(inner_res);
                }
                Err(e) => {
                    // An error happened so we try again
                    tracing::info!("Loop failed with the error: {e}");
                    tokio::time::sleep(tokio::time::Duration::from_millis($ms_sleep)).await;
                    ctr += 1;
                    last_error = e.to_string();
                }
            }
        }
    }};
    ($func:expr) => {{
        use kms_common::{MAX_ITER, SLEEP_MS};
        loop_fn!($func, SLEEP_MS, MAX_ITER)
    }};
}

#[macro_export]
macro_rules! exp_loop_fn {
    ($func:expr,$ms_sleep:expr,$max_iter:expr) => {{
        let mut ctr = 0;
        let mut sleep_time = $ms_sleep;
        let mut last_error = "".to_string();
        loop {
            if ctr > $max_iter {
                break Err(anyhow::anyhow!(
                    "Exponential loop failed to get result after {} tries. The last error was: {}.",
                    $max_iter,
                    last_error
                )
                .into());
            }
            match $func().await {
                Ok(inner_res) => {
                    break Ok(inner_res);
                }
                Err(e) => {
                    // An error happened so we try again
                    tracing::info!("Exponential loop failed with the error: {e}");
                    tokio::time::sleep(tokio::time::Duration::from_millis(sleep_time)).await;
                    sleep_time *= 2;
                    ctr += 1;
                    last_error = e.to_string();
                }
            }
        }
    }};
    ($func:expr) => {{
        use kms_common::{MAX_ITER, SLEEP_MS};
        exp_loop_fn!($func, SLEEP_MS, MAX_ITER)
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
