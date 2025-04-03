use std::{error::Error, fmt};

/// The maximum number of iterations before terminating a loop that is expected to only iterate a couple of times.
pub const RETRY_MAX_ITER: u64 = 30;
/// The number of milliseconds to sleep between iterations of a loop.
pub const RETRY_SLEEP_MS: u64 = 1000;

pub enum TimeoutStrategy {
    /// The timeout is constant for each iteration.
    Constant,
    /// The timeout is increased exponentially after each iteration.
    Exponential,
}

#[macro_export]
/// Helper macro to try a piece of code until it succeeds but not more than `$max_iter` times with a constant sleep time after each iteration.
/// This macro has the same functionality as `retry_fatal_loop!` when all errors are transient.
/// The macro will ensure appropriate logging in case of both fatal and non-fatal errors.
///
/// # Arguments
///
/// * `$func` - The asynchronous function to be retried. It should return a `Result`.
/// * `$ms_sleep` - The initial sleep time in milliseconds between retries.
/// * `$max_iter` - The maximum number of retry attempts.
/// * `$timeout_strategy` - The strategy to use for timeout between retries.
///   It can be either `TimeoutStrategy::Constant` or `TimeoutStrategy::Exponential`.
///
/// # Usage
///
/// Try to run the code at most 30 times with a sleep time of 1000 ms after the first iteration, 2000 ms for the next, then 4000 ms, and so on.
/// ```ignore
/// use kms_common::retry_loop;
/// retry_loop!(async_function, 1000, 30, TimeoutStrategy::Exponential);
/// retry_loop!(async_function, 1000, 30);
/// retry_loop!(async_function);
/// ```
///
/// # Errors
///
/// If the function fails after the maximum number of retries, it returns an error with the last encountered error message.
macro_rules! retry_loop {
    ($func:expr,$ms_sleep:expr,$max_iter:expr,$timeout_strategy:expr) => {{
        use $crate::util::retry::TimeoutStrategy;

        let mut ctr = 0;
        let mut sleep_time = $ms_sleep;
        let mut last_error = "".to_string();
        loop {
            if ctr > $max_iter {
                let msg = format!(
                    "Loop failed to get result after {} tries. The last error was: {}.",
                    $max_iter, last_error
                );
                tracing::error!(msg);
                break Err(anyhow::anyhow!(msg).into());
            }
            match $func().await {
                Ok(inner_res) => break Ok(inner_res),
                Err(e) => {
                    // An error happened so we try again
                    tracing::warn!("Loop failed with transient error: {e}");
                    match $timeout_strategy {
                        TimeoutStrategy::Constant => {
                            // Sleep time remains the same
                        }
                        TimeoutStrategy::Exponential => {
                            // Sleep time is doubled every time
                            sleep_time *= 2;
                        }
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(sleep_time)).await;
                    ctr += 1;
                    last_error = e.to_string();
                }
            }
        }
    }};
    ($func:expr,$ms_sleep:expr,$max_iter:expr) => {{
        retry_loop!($func, $ms_sleep, $max_iter, TimeoutStrategy::Constant)
    }};
    ($func:expr) => {{
        retry_loop!(
            $func,
            $crate::retry::RETRY_SLEEP_MS,
            $crate::retry::RETRY_MAX_ITER
        )
    }};
}

// TODO Termination and Transient are never used in our code.
#[derive(Debug)]
pub enum LoopErr<E> {
    Termination(anyhow::Error),
    Fatal(E),
    Transient(E),
}
impl<E: fmt::Display> fmt::Display for LoopErr<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoopErr::Fatal(err) => write!(f, "Fatal error: {}", err),
            LoopErr::Transient(err) => write!(f, "Transient error: {}", err),
            LoopErr::Termination(err) => write!(f, "{}", err),
        }
    }
}
impl<E: fmt::Debug + fmt::Display> Error for LoopErr<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}
impl<E> LoopErr<E> {
    pub fn fatal(err: E) -> Self {
        LoopErr::Fatal(err)
    }

    pub fn transient(err: E) -> Self {
        LoopErr::Transient(err)
    }
}
impl From<anyhow::Error> for LoopErr<anyhow::Error> {
    fn from(e: anyhow::Error) -> Self {
        LoopErr::Fatal(e)
    }
}
impl<E> LoopErr<E> {
    pub fn is_fatal(&self) -> bool {
        match self {
            LoopErr::Termination(_) => true,
            LoopErr::Fatal(_) => true,
            LoopErr::Transient(_) => false,
        }
    }
}

#[macro_export]
/// Helper macro to try a piece of code until it succeeds but not more than `$max_iter` times with a constant sleep time after each iteration.
/// The macro will ensure appropriate logging in case of both fatal and non-fatal errors.
///
/// # Arguments
///
/// * `$func` - The asynchronous function to be retried. It should return a `Result` with a `LoopErr`.
///   If LoopErr is `Fatal`, the loop will stop and return the error. If LoopErr is `Transient`, the loop will continue.
/// * `$ms_sleep` - The initial sleep duration in milliseconds between retries.
/// * `$max_iter` - The maximum number of retry attempts.
/// * `$timeout_strategy` - The strategy to use for increasing the sleep duration between retries.
///   It can be either `TimeoutStrategy::Constant` or `TimeoutStrategy::Exponential`.
///
/// # Usage
///
/// To execute `my_async_function` at most 5 times with a 100ms sleep time between retries:
/// ```ignore
/// use kms_common::retry_fatal_loop;
/// retry_fatal_loop!(my_async_function, 100, 5, TimeoutStrategy::Constant);
/// ```
///
/// # Errors
///
/// The macro returns an error if the maximum number of retry attempts is reached or if a fatal error occurs.
macro_rules! retry_fatal_loop {
    ($func:expr,$ms_sleep:expr,$max_iter:expr,$timeout_strategy:expr) => {{
        use $crate::util::retry::LoopErr;
        use $crate::util::retry::TimeoutStrategy;

        let mut ctr = 0;
        let mut sleep_time = $ms_sleep;
        let mut last_error = "".to_string();
        loop {
            if ctr > $max_iter {
                let msg = format!(
                    "Loop failed to get result after {} tries. The last error was: {}.",
                    $max_iter, last_error
                );
                tracing::error!(msg);
                break Err(LoopErr::Termination(anyhow::anyhow!(msg)));
            }
            match $func().await {
                Ok(inner_res) => break Ok(inner_res),
                Err(error) => match error {
                    LoopErr::Termination(inner_err) => {
                        tracing::error!("Loop failed with termination error: {}", &inner_err);
                        break Err(LoopErr::Termination(inner_err));
                    }
                    LoopErr::Fatal(inner_err) => {
                        tracing::error!("Loop failed with fatal error: {}", &inner_err);
                        break Err(LoopErr::Fatal(inner_err));
                    }
                    LoopErr::Transient(inner_err) => {
                        tracing::warn!("Loop failed with transient error: {inner_err}");
                        match $timeout_strategy {
                            TimeoutStrategy::Constant => {
                                // Sleep time remains the same
                            }
                            TimeoutStrategy::Exponential => {
                                // Sleep time is doubled every time
                                sleep_time *= 2;
                            }
                        }
                        tokio::time::sleep(tokio::time::Duration::from_millis(sleep_time)).await;
                        ctr += 1;
                        last_error = inner_err.to_string();
                    }
                },
            }
        }
    }};
    ($func:expr,$ms_sleep:expr,$max_iter:expr) => {{
        retry_fatal_loop!($func, $ms_sleep, $max_iter, TimeoutStrategy::Constant)
    }};
    ($func:expr) => {{
        use $crate::{RETRY_MAX_ITER, RETRY_SLEEP_MS};
        retry_fatal_loop!($func, RETRY_SLEEP_MS, RETRY_MAX_ITER)
    }};
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tokio::sync::Mutex;

    use crate::util::retry::LoopErr;

    #[tokio::test]
    async fn sunshine_retry_loop() {
        let number_mutex = Arc::new(Mutex::new(0));
        let res: Result<i32, anyhow::Error> = retry_loop!(
            || {
                let number_mutex = number_mutex.clone();
                async move {
                    let mut number = number_mutex.lock().await;
                    if *number < 5 {
                        *number += 1;
                        Err(anyhow::anyhow!("error".to_string()))
                    } else {
                        Ok(*number)
                    }
                }
            },
            10, // ms sleep
            7   // iterations
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 5);
    }

    #[tokio::test]
    async fn retry_loop_fails() {
        let res: Result<i32, anyhow::Error> = retry_loop!(
            || async { Err(anyhow::anyhow!("error".to_string())) },
            10, // ms sleep
            3   // iterations
        );
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn sunshine_fatal_loop() {
        let number_mutex = Arc::new(Mutex::new(0));
        let res: Result<i32, LoopErr<anyhow::Error>> = retry_fatal_loop!(
            || {
                let number_mutex = number_mutex.clone();
                async move {
                    let mut number = number_mutex.lock().await;
                    if *number < 5 {
                        *number += 1;
                        Err(LoopErr::Transient(anyhow::anyhow!("Transient")))
                    } else {
                        Ok(*number)
                    }
                }
            },
            10, // ms sleep
            7   // iterations
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 5);
    }

    #[tokio::test]
    async fn fatal_loop_fails() {
        let number_mutex = Arc::new(Mutex::new(0));
        let res: Result<i32, LoopErr<anyhow::Error>> = retry_fatal_loop!(
            || {
                let number_mutex = number_mutex.clone();
                async move {
                    let mut number = number_mutex.lock().await;
                    if *number < 5 {
                        *number += 1;
                        Err(LoopErr::Transient(anyhow::anyhow!("Transient")))
                    } else {
                        Ok(*number)
                    }
                }
            },
            10, // ms sleep
            3   // iterations
        );
        assert!(res.is_err_and(|e| e.is_fatal()));
    }
}
