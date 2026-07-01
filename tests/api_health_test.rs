//! API tests for the health probes.
//!
//! `healthz` and the unreachable-`readyz` case need no container (they use a lazily
//! connected pool pointed at a closed port). Only the reachable-`readyz` case
//! provisions a real Postgres via testcontainers and skips when Docker is absent.

use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use internal_stripe_api::health::{HEALTHZ_PATH, HealthState, READYZ_PATH, router};

const PG_IMAGE: &str = "postgres";
const PG_TAG: &str = "16-alpine";
const PG_PORT: u16 = 5432;

async fn start_postgres() -> Option<ContainerAsync<GenericImage>> {
    GenericImage::new(PG_IMAGE, PG_TAG)
        .with_exposed_port(PG_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_PASSWORD", "postgres")
        .with_env_var("POSTGRES_DB", "app")
        .start()
        .await
        .ok()
}

async fn connect_with_retry(url: &str) -> PgPool {
    for _ in 0..40 {
        if let Ok(pool) = PgPoolOptions::new().max_connections(5).connect(url).await {
            return pool;
        }
        sleep(Duration::from_millis(500)).await;
    }
    panic!("postgres did not become ready in time");
}

struct Server {
    _pg: Option<ContainerAsync<GenericImage>>,
    base_url: String,
    handle: JoinHandle<()>,
}

impl Server {
    async fn shutdown(self) {
        self.handle.abort();
    }
}

async fn spawn(state: HealthState, pg: Option<ContainerAsync<GenericImage>>) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let app = router(state);
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    Server {
        _pg: pg,
        base_url: format!("http://{addr}"),
        handle,
    }
}

/// Server whose DB points at a closed port (readiness will fail).
async fn bogus_db_server() -> Server {
    let db = PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(2))
        .connect_lazy("postgres://user:pass@127.0.0.1:1/none")
        .expect("lazy pool");
    spawn(HealthState { db }, None).await
}

/// Server backed by a reachable Postgres.
async fn live_db_server() -> Option<Server> {
    let pg = start_postgres().await?;
    let host = pg.get_host().await.expect("postgres host");
    let port = pg
        .get_host_port_ipv4(PG_PORT.tcp())
        .await
        .expect("postgres mapped port");
    let url = format!("postgres://postgres:postgres@{host}:{port}/app");
    let db = connect_with_retry(&url).await;
    Some(spawn(HealthState { db }, Some(pg)).await)
}

async fn get(base_url: &str, route: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(format!("{base_url}{route}"))
        .send()
        .await
        .expect("send GET request")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_healthz_returns_200() {
    let s = bogus_db_server().await;

    let resp = get(&s.base_url, HEALTHZ_PATH).await;
    assert_eq!(resp.status().as_u16(), 200);

    s.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_readyz_returns_200_when_dependencies_reachable() {
    let Some(s) = live_db_server().await else {
        eprintln!("skipping: container runtime unavailable");
        return;
    };

    let resp = get(&s.base_url, READYZ_PATH).await;
    assert_eq!(resp.status().as_u16(), 200);

    s.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_readyz_returns_503_when_postgres_unreachable() {
    let s = bogus_db_server().await;

    let resp = get(&s.base_url, READYZ_PATH).await;
    assert_eq!(resp.status().as_u16(), 503);

    s.shutdown().await;
}
