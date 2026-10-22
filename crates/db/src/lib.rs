//! SecuScan v2 — persistence layer (SQLite via sqlx).

pub mod models;
pub mod repo;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("row not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("invalid data: {0}")]
    Invalid(String),
}

pub type DbResult<T> = Result<T, DbError>;

/// Open (and create if needed) the SQLite database, apply PRAGMAs and run
/// migrations. `url` examples:
/// - `sqlite://data/secuscan.db?mode=rwc`
/// - `sqlite::memory:`
pub async fn open(url: &str) -> DbResult<SqlitePool> {
    let opts: SqliteConnectOptions = url
        .parse::<SqliteConnectOptions>()
        .map_err(|e| DbError::Invalid(format!("bad database url `{url}`: {e}")))?;
    let opts = opts
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect_with(opts)
        .await?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| DbError::Sqlx(e.into()))?;
    Ok(pool)
}

/// New random id.
pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Current UTC timestamp in RFC 3339.
pub fn now() -> String {
    secuscan_core::models::now_iso()
}

/// SHA-256 hex digest (used for token hashing).
pub fn sha256_hex(data: &str) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data.as_bytes());
    hex::encode(h.finalize())
}

/// Generate a URL-safe random token with a readable prefix, e.g.
/// `scsk_3f9a...`.
pub fn generate_token(prefix: &str) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    format!("{prefix}_{}", hex::encode(bytes))
}

/// Hex-encode caller-provided entropy under a prefix (used for refresh
/// tokens where the caller already drew OS randomness).
pub fn generate_token_from(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
