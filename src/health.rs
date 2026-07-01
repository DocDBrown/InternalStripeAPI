//! src/health.rs — liveness and readiness probes.

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use sqlx::PgPool;

pub const HEALTHZ_PATH: &str = "/healthz";
pub const READYZ_PATH: &str = "/readyz";

#[derive(Clone)]
pub struct HealthState {
    /// Postgres pool checked by the readiness probe.
    pub db: PgPool,
}

/// Build the health router with the given state applied.
pub fn router(state: HealthState) -> Router {
    Router::new()
        .route(HEALTHZ_PATH, get(healthz))
        .route(READYZ_PATH, get(readyz))
        .with_state(state)
}

/// Liveness: the process is running. Does not touch dependencies.
async fn healthz() -> StatusCode {
    StatusCode::OK
}

/// Readiness: the service can reach its dependencies (Postgres).
async fn readyz(State(state): State<HealthState>) -> StatusCode {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => StatusCode::OK,
        Err(e) => {
            tracing::warn!(error = %e, "readiness check failed: postgres unreachable");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}
