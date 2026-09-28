//! Liveness and readiness of a KMS server.
//!
//! A [`HealthState`] feeds two consumers with the same answer: the named gRPC health services
//! [`LIVENESS_SERVICE`] and [`READINESS_SERVICE`] on the service port, which the Kubernetes probes
//! query, and the HTTP endpoints on the metrics port, which operators query by hand.
//!
//! Liveness fails only when a component reports a fault that the process cannot recover from
//! without a restart, because Kubernetes restarts the pod on a liveness failure. A restart drops the
//! in-memory meta stores and every running protocol, so a slow or overloaded node stays live.
//!
//! The results of the dependency checks, such as storage reachability, change neither liveness nor
//! readiness. They only change the overall health that `/healthz` and the
//! `kms_health_dependency_up` metric report, for monitoring and alerts.

use crate::metrics::METRICS;
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex, OnceLock, PoisonError,
    atomic::{AtomicBool, Ordering},
};
use tonic_health::{
    ServingStatus,
    pb::health_server::{Health, HealthServer},
    server::HealthReporter,
};

/// Name of the gRPC health service that reports liveness.
pub const LIVENESS_SERVICE: &str = "liveness";
/// Name of the gRPC health service that reports readiness.
pub const READINESS_SERVICE: &str = "readiness";

/// Shared handle to the liveness, readiness and overall health of one KMS server.
///
/// Clones share the same state. A server is live until [`HealthState::report_fatal`] is called. It
/// is ready when it is live, [`HealthState::mark_initialized`] was called, and
/// [`HealthState::mark_shutting_down`] was not called. It is healthy when it is ready and every
/// dependency that [`HealthState::set_dependency`] recorded passed its last check.
#[derive(Clone)]
pub struct HealthState {
    inner: Arc<HealthInner>,
}

struct HealthInner {
    reporter: HealthReporter,
    initialized: AtomicBool,
    shutting_down: AtomicBool,
    fatal_component: OnceLock<&'static str>,
    dependencies: Mutex<BTreeMap<&'static str, bool>>,
    // Serializes the updates of the gRPC statuses, so that a slow update cannot overwrite a
    // later one with a stale status.
    publish_lock: tokio::sync::Mutex<()>,
}

impl HealthState {
    /// Returns a new state that is live and not ready, and the gRPC health service that reports it.
    pub async fn new() -> (Self, HealthServer<impl Health>) {
        let (reporter, service) = tonic_health::server::health_reporter();
        let state = Self {
            inner: Arc::new(HealthInner {
                reporter,
                initialized: AtomicBool::new(false),
                shutting_down: AtomicBool::new(false),
                fatal_component: OnceLock::new(),
                dependencies: Mutex::new(BTreeMap::new()),
                publish_lock: tokio::sync::Mutex::new(()),
            }),
        };
        state.publish().await;
        (state, service)
    }

    /// Returns the gRPC health reporter, to set the status of other gRPC services on the same server.
    pub fn reporter(&self) -> &HealthReporter {
        &self.inner.reporter
    }

    /// Returns `true` until a component reports a fatal fault.
    pub fn is_live(&self) -> bool {
        self.inner.fatal_component.get().is_none()
    }

    /// Returns `true` when the server is live, initialized, and not shutting down.
    pub fn is_ready(&self) -> bool {
        self.is_live()
            && self.inner.initialized.load(Ordering::Acquire)
            && !self.inner.shutting_down.load(Ordering::Acquire)
    }

    /// Returns `true` after [`HealthState::mark_shutting_down`] was called.
    pub fn is_shutting_down(&self) -> bool {
        self.inner.shutting_down.load(Ordering::Acquire)
    }

    /// Returns `true` when the server is ready and every recorded dependency passed its last check.
    pub fn is_healthy(&self) -> bool {
        self.health_snapshot().0
    }

    /// Returns [`HealthState::is_healthy`] and the dependency results that the answer is based on,
    /// from one read of the dependency results.
    pub fn health_snapshot(&self) -> (bool, BTreeMap<&'static str, bool>) {
        let dependencies = self.dependencies();
        let healthy = self.is_ready() && dependencies.values().all(|healthy| *healthy);
        (healthy, dependencies)
    }

    /// Returns the result of the last check of each dependency, by dependency name.
    pub fn dependencies(&self) -> BTreeMap<&'static str, bool> {
        self.lock_dependencies().clone()
    }

    /// Records the result of the last check of the dependency `name`.
    ///
    /// The caller logs the cause of a failed check. This function logs when a dependency recovers.
    pub fn set_dependency(&self, name: &'static str, healthy: bool) {
        let previous = self.lock_dependencies().insert(name, healthy);
        METRICS.record_health_dependency(name, healthy);
        if healthy && previous == Some(false) {
            tracing::info!(dependency = name, "Health dependency check passes again");
        }
    }

    // A panic while the lock is held cannot leave the map inconsistent, because every access
    // is a single map operation. So a poisoned lock is safe to use.
    fn lock_dependencies(&self) -> std::sync::MutexGuard<'_, BTreeMap<&'static str, bool>> {
        self.inner
            .dependencies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Records that the server finished its startup and accepts requests.
    pub async fn mark_initialized(&self) {
        self.inner.initialized.store(true, Ordering::Release);
        self.publish().await;
    }

    /// Records that the server started its shutdown. The server stays not ready after this call.
    pub async fn mark_shutting_down(&self) {
        self.inner.shutting_down.store(true, Ordering::Release);
        self.publish().await;
    }

    /// Records a fault that `component` cannot recover from, and makes liveness fail.
    ///
    /// The probe responses do not contain `component` or `reason`, so that they do not leak
    /// internal details. The log line identifies both. The first reported component is kept.
    pub async fn report_fatal(&self, component: &'static str, reason: &str) {
        tracing::error!(
            component,
            reason,
            "Fatal fault in a KMS component: the liveness checks fail from now on"
        );
        let _ = self.inner.fatal_component.set(component);
        self.publish().await;
    }

    async fn publish(&self) {
        let _guard = self.inner.publish_lock.lock().await;
        self.inner
            .reporter
            .set_service_status(LIVENESS_SERVICE, serving_status(self.is_live()))
            .await;
        self.inner
            .reporter
            .set_service_status(READINESS_SERVICE, serving_status(self.is_ready()))
            .await;
    }
}

fn serving_status(ok: bool) -> ServingStatus {
    if ok {
        ServingStatus::Serving
    } else {
        ServingStatus::NotServing
    }
}

static PROCESS_HEALTH: OnceLock<HealthState> = OnceLock::new();

/// Error of [`register_process_health`] when the process already has a registered state.
#[derive(Debug, thiserror::Error)]
#[error(
    "A health state is already registered for the HTTP health endpoints of this process; register only the state of the server that the process runs"
)]
pub struct HealthAlreadyRegistered;

/// Makes `state` the one that the HTTP health endpoints of this process report.
///
/// Call it once per process, for the server that the process runs.
///
/// # Errors
///
/// Returns [`HealthAlreadyRegistered`] if a state is already registered in this process.
pub fn register_process_health(state: HealthState) -> Result<(), HealthAlreadyRegistered> {
    PROCESS_HEALTH
        .set(state)
        .map_err(|_| HealthAlreadyRegistered)
}

/// Returns the state registered with [`register_process_health`], or `None` before registration.
pub(crate) fn process_health() -> Option<&'static HealthState> {
    PROCESS_HEALTH.get()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic_health::pb::{HealthCheckRequest, health_check_response};
    use tonic_health::server::HealthService;

    async fn grpc_status(
        state: &HealthState,
        service: &str,
    ) -> health_check_response::ServingStatus {
        let health_service = HealthService::from_health_reporter(state.reporter().clone());
        let response = health_service
            .check(tonic::Request::new(HealthCheckRequest {
                service: service.to_string(),
            }))
            .await
            .unwrap();
        health_check_response::ServingStatus::try_from(response.into_inner().status).unwrap()
    }

    async fn assert_grpc(state: &HealthState, live: bool, ready: bool) {
        let expected = |ok: bool| {
            if ok {
                health_check_response::ServingStatus::Serving
            } else {
                health_check_response::ServingStatus::NotServing
            }
        };
        assert_eq!(grpc_status(state, LIVENESS_SERVICE).await, expected(live));
        assert_eq!(grpc_status(state, READINESS_SERVICE).await, expected(ready));
    }

    #[tokio::test]
    async fn new_state_is_live_and_not_ready() {
        let (state, _service) = HealthState::new().await;
        assert!(state.is_live());
        assert!(!state.is_ready());
        assert_grpc(&state, true, false).await;
    }

    #[tokio::test]
    async fn initialized_state_is_ready() {
        let (state, _service) = HealthState::new().await;
        state.mark_initialized().await;
        assert!(state.is_live());
        assert!(state.is_ready());
        assert_grpc(&state, true, true).await;
    }

    #[tokio::test]
    async fn shutting_down_state_is_live_and_not_ready() {
        let (state, _service) = HealthState::new().await;
        state.mark_initialized().await;
        state.mark_shutting_down().await;
        assert!(state.is_live());
        assert!(!state.is_ready());
        assert_grpc(&state, true, false).await;

        // A late initialization must not make a shutting-down server ready again.
        state.mark_initialized().await;
        assert!(!state.is_ready());
        assert_grpc(&state, true, false).await;
    }

    #[tokio::test]
    async fn fatal_fault_fails_liveness_and_readiness() {
        let (state, _service) = HealthState::new().await;
        state.mark_initialized().await;
        state.report_fatal("test_component", "test reason").await;
        assert!(!state.is_live());
        assert!(!state.is_ready());
        assert_grpc(&state, false, false).await;

        // A second fault keeps the state not live.
        state.report_fatal("other_component", "other reason").await;
        assert!(!state.is_live());
        assert_eq!(state.inner.fatal_component.get(), Some(&"test_component"));
    }

    #[tokio::test]
    async fn failed_dependency_fails_health_but_not_readiness() {
        let (state, _service) = HealthState::new().await;
        state.mark_initialized().await;
        assert!(state.is_healthy());

        state.set_dependency("test_storage", true);
        state.set_dependency("test_peers", false);
        assert!(!state.is_healthy());
        assert!(state.is_ready());
        assert!(state.is_live());
        assert_grpc(&state, true, true).await;
        assert_eq!(
            state.dependencies(),
            BTreeMap::from([("test_peers", false), ("test_storage", true)])
        );

        state.set_dependency("test_peers", true);
        assert!(state.is_healthy());
    }

    /// Returns the value of `kms_health_dependency_up` for `dependency`, or `None` without a sample.
    fn dependency_gauge(dependency: &str) -> Option<f64> {
        let family = prometheus::gather()
            .into_iter()
            .find(|family| family.name() == "kms_health_dependency_up")?;
        let metric = family.get_metric().iter().find(|metric| {
            metric
                .get_label()
                .iter()
                .any(|label| label.name() == "dependency" && label.value() == dependency)
        })?;
        Some(metric.get_gauge().value())
    }

    #[tokio::test]
    async fn set_dependency_updates_the_metric() {
        let (state, _service) = HealthState::new().await;
        // A name that no other test uses, because the metrics registry is global.
        let dependency = "test_metric_dependency";
        assert_eq!(dependency_gauge(dependency), None);

        state.set_dependency(dependency, true);
        assert_eq!(dependency_gauge(dependency), Some(1.0));
        state.set_dependency(dependency, false);
        assert_eq!(dependency_gauge(dependency), Some(0.0));
    }

    #[tokio::test]
    async fn health_snapshot_matches_its_dependencies() {
        let (state, _service) = HealthState::new().await;
        state.mark_initialized().await;
        assert_eq!(state.health_snapshot(), (true, BTreeMap::new()));

        state.set_dependency("test_storage", false);
        assert_eq!(
            state.health_snapshot(),
            (false, BTreeMap::from([("test_storage", false)]))
        );

        state.set_dependency("test_storage", true);
        assert_eq!(
            state.health_snapshot(),
            (true, BTreeMap::from([("test_storage", true)]))
        );
    }

    #[tokio::test]
    async fn not_ready_state_is_not_healthy() {
        let (state, _service) = HealthState::new().await;
        state.set_dependency("test_storage", true);
        assert!(!state.is_healthy());
        state.mark_initialized().await;
        assert!(state.is_healthy());
        state.mark_shutting_down().await;
        assert!(state.is_shutting_down());
        assert!(!state.is_healthy());
    }

    #[tokio::test]
    async fn second_process_registration_fails() {
        let (first, _service) = HealthState::new().await;
        let (second, _service) = HealthState::new().await;
        // Other tests in this binary do not register, so the first call succeeds.
        register_process_health(first).unwrap();
        assert!(process_health().is_some());
        assert!(register_process_health(second).is_err());
    }
}
