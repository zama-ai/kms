//! Bench knobs of the core-to-core transport, read once from the environment.
//!
//! Every knob defaults to the current behaviour, so an unset environment is a no-op. Inside a
//! Nitro enclave the process environment is not inherited from the pod: set the variables
//! through the `[tuning.env]` table of the kms-server config (the chart renders
//! `kmsCore.tuning.env` there), which `kms-server` exports into its own environment before the
//! transport is built. See `BENCH-DIAGNOSTICS.md`.
//!
//! | Variable | Default | Effect |
//! |---|---|---|
//! | `MPC_C2C_CONNECTIONS_PER_PEER` | `1` | HTTP/2 connections (TCP + TLS sessions) opened to each peer; sessions are spread over them round-robin. |
//! | `MPC_C2C_H2_ADAPTIVE_WINDOW` | `1` | hyper's BDP-driven flow-control windows. **Setting any window below forces this off**, because hyper's adaptive mode resets both windows to 65 535 bytes. |
//! | `MPC_C2C_H2_STREAM_WINDOW_BYTES` | unset | `SETTINGS_INITIAL_WINDOW_SIZE` for both the client channels and the core-to-core server. |
//! | `MPC_C2C_H2_CONN_WINDOW_BYTES` | unset | Connection-level receive window for both sides. |
//! | `MPC_C2C_H2_MAX_FRAME_BYTES` | unset | `SETTINGS_MAX_FRAME_SIZE` (16 KiB default; up to 16 MiB − 1). |
//! | `MPC_C2C_H2_MAX_CONCURRENT_STREAMS` | unset | `SETTINGS_MAX_CONCURRENT_STREAMS` advertised by the core-to-core server (hyper default 200). |

use std::sync::LazyLock;

fn env_parse<T: std::str::FromStr>(name: &str) -> Option<T> {
    let raw = std::env::var(name).ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    match raw.parse::<T>() {
        Ok(value) => {
            tracing::info!("Using tuning value {raw} from env var {name}");
            Some(value)
        }
        Err(_) => {
            tracing::warn!("Invalid value {raw:?} for env var {name}; ignoring it");
            None
        }
    }
}

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            other => {
                tracing::warn!("Invalid bool value {other:?} for env var {name}; using {default}");
                default
            }
        },
        Err(_) => default,
    }
}

/// Number of HTTP/2 connections per peer (`MPC_C2C_CONNECTIONS_PER_PEER`, min 1).
pub static C2C_CONNECTIONS_PER_PEER: LazyLock<usize> = LazyLock::new(|| {
    env_parse::<usize>("MPC_C2C_CONNECTIONS_PER_PEER")
        .unwrap_or(1)
        .max(1)
});

/// HTTP/2 flow-control settings shared by the client channels and the core-to-core server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H2Settings {
    pub adaptive_window: bool,
    pub stream_window_bytes: Option<u32>,
    pub conn_window_bytes: Option<u32>,
    pub max_frame_bytes: Option<u32>,
    pub max_concurrent_streams: Option<u32>,
}

impl H2Settings {
    /// The settings in force before any knob existed.
    pub const DEFAULT: Self = Self {
        adaptive_window: true,
        stream_window_bytes: None,
        conn_window_bytes: None,
        max_frame_bytes: None,
        max_concurrent_streams: None,
    };

    fn from_env() -> Self {
        let settings = Self::resolve(
            env_bool("MPC_C2C_H2_ADAPTIVE_WINDOW", true),
            env_parse::<u32>("MPC_C2C_H2_STREAM_WINDOW_BYTES"),
            env_parse::<u32>("MPC_C2C_H2_CONN_WINDOW_BYTES"),
            env_parse::<u32>("MPC_C2C_H2_MAX_FRAME_BYTES"),
            env_parse::<u32>("MPC_C2C_H2_MAX_CONCURRENT_STREAMS"),
        );
        tracing::info!("Core-to-core HTTP/2 settings: {settings:?}");
        settings
    }

    /// Combine the raw knob values: a static window turns the adaptive window off, since hyper's
    /// adaptive mode would reset both windows to 65 535 bytes and silently undo the static one.
    fn resolve(
        adaptive_window: bool,
        stream_window_bytes: Option<u32>,
        conn_window_bytes: Option<u32>,
        max_frame_bytes: Option<u32>,
        max_concurrent_streams: Option<u32>,
    ) -> Self {
        let static_windows = stream_window_bytes.is_some() || conn_window_bytes.is_some();
        if adaptive_window && static_windows {
            tracing::info!(
                "Static HTTP/2 windows requested: turning the adaptive window off, as hyper's adaptive mode would reset both windows to 65535 bytes"
            );
        }
        Self {
            adaptive_window: adaptive_window && !static_windows,
            stream_window_bytes,
            conn_window_bytes,
            max_frame_bytes,
            max_concurrent_streams,
        }
    }
}

/// The HTTP/2 settings read from the environment (once).
pub static C2C_H2_SETTINGS: LazyLock<H2Settings> = LazyLock::new(H2Settings::from_env);

/// Apply [`C2C_H2_SETTINGS`] to a client endpoint. Window sizes are set before the adaptive flag,
/// matching the order tonic applies them in.
pub fn apply_h2_client_settings(
    endpoint: tonic::transport::Endpoint,
) -> tonic::transport::Endpoint {
    let settings = *C2C_H2_SETTINGS;
    let mut endpoint = endpoint;
    if let Some(bytes) = settings.stream_window_bytes {
        endpoint = endpoint.initial_stream_window_size(bytes);
    }
    if let Some(bytes) = settings.conn_window_bytes {
        endpoint = endpoint.initial_connection_window_size(bytes);
    }
    if let Some(bytes) = settings.max_frame_bytes {
        endpoint = endpoint.max_frame_size(bytes);
    }
    endpoint.http2_adaptive_window(settings.adaptive_window)
}

/// Apply [`C2C_H2_SETTINGS`] to the core-to-core server builder.
pub fn apply_h2_server_settings(server: tonic::transport::Server) -> tonic::transport::Server {
    let settings = *C2C_H2_SETTINGS;
    let mut server = server;
    if let Some(bytes) = settings.stream_window_bytes {
        server = server.initial_stream_window_size(bytes);
    }
    if let Some(bytes) = settings.conn_window_bytes {
        server = server.initial_connection_window_size(bytes);
    }
    if let Some(bytes) = settings.max_frame_bytes {
        server = server.max_frame_size(bytes);
    }
    if let Some(streams) = settings.max_concurrent_streams {
        server = server.max_concurrent_streams(streams);
    }
    server.http2_adaptive_window(Some(settings.adaptive_window))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_knobs_resolve_to_the_current_behaviour() {
        assert_eq!(
            H2Settings::resolve(true, None, None, None, None),
            H2Settings::DEFAULT
        );
    }

    #[test]
    fn a_static_window_turns_the_adaptive_window_off() {
        let stream = H2Settings::resolve(true, Some(8 << 20), None, None, None);
        assert!(!stream.adaptive_window);
        assert_eq!(stream.stream_window_bytes, Some(8 << 20));

        let conn = H2Settings::resolve(true, None, Some(32 << 20), None, None);
        assert!(!conn.adaptive_window);

        // A frame size or stream limit alone keeps the adaptive window.
        let frame = H2Settings::resolve(true, None, None, Some(1 << 20), Some(500));
        assert!(frame.adaptive_window);
        assert_eq!(frame.max_frame_bytes, Some(1 << 20));
        assert_eq!(frame.max_concurrent_streams, Some(500));

        // Explicitly off stays off.
        assert!(!H2Settings::resolve(false, None, None, None, None).adaptive_window);
    }

    #[test]
    fn the_connection_pool_has_at_least_one_member() {
        assert!(*C2C_CONNECTIONS_PER_PEER >= 1);
    }
}
