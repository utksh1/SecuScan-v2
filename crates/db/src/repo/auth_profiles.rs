//! Auth profiles — reusable credentials/cookies/headers for web scans.
//!
//! `config_json` is encrypted at rest (AES-256-GCM, see
//! `secuscan_core::crypto`) — the API server initializes the crypto layer
//! at startup, so rows written through this repo carry `enc:v1:` ciphertext;
//! legacy plaintext rows decrypt transparently on read.

use crate::{DbError, DbResult};
use crate::models::AuthProfileRow;
use crate::new_id;
use sqlx::SqlitePool;

/// Encrypt a config for storage (no-op when crypto is uninitialized).
fn seal(config_json: &str) -> Result<String, DbError> {
    secuscan_core::crypto::encrypt_to_storage(config_json)
        .map_err(|e| DbError::Invalid(format!("encrypt auth profile: {e}")))
}

/// Decrypt a stored config; falls back to the raw value (with a log line)
/// when it cannot be decrypted so listings never hard-fail.
fn open(config_json: &str) -> String {
    match secuscan_core::crypto::decrypt_from_storage(config_json) {
        Ok(plain) => plain,
        Err(e) => {
            tracing::error!("auth profile config is encrypted but undecryptable ({e}); returning raw value");
            config_json.to_string()
        }
    }
}

fn decrypt_row(mut row: AuthProfileRow) -> AuthProfileRow {
    row.config_json = open(&row.config_json);
    row
}

pub async fn create(
    db: &SqlitePool,
    workspace_id: Option<&str>,
    name: &str,
    method: &str,
    config_json: &str,
    notes: &str,
    user_id: &str,
) -> DbResult<AuthProfileRow> {
    let id = new_id();
    let now = crate::now();
    let config_json = seal(config_json)?;
    sqlx::query(
        "INSERT INTO auth_profiles (id, workspace_id, name, method, config_json, notes,
                                     created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(workspace_id)
    .bind(name)
    .bind(method)
    .bind(config_json)
    .bind(notes)
    .bind(user_id)
    .bind(&now)
    .execute(db)
    .await?;
    get(db, &id).await.map_err(Into::into)
}

pub async fn list(
    db: &SqlitePool,
    workspace_id: Option<&str>,
) -> DbResult<Vec<AuthProfileRow>> {
    match workspace_id {
        Some(ws) => sqlx::query_as::<_, AuthProfileRow>(
            "SELECT * FROM auth_profiles WHERE workspace_id = ? ORDER BY created_at DESC",
        )
        .bind(ws)
        .fetch_all(db)
        .await,
        None => sqlx::query_as::<_, AuthProfileRow>(
            "SELECT * FROM auth_profiles ORDER BY created_at DESC",
        )
        .fetch_all(db)
        .await,
    }
    .map(|rows| rows.into_iter().map(decrypt_row).collect())
    .map_err(Into::into)
}

pub async fn get(db: &SqlitePool, id: &str) -> DbResult<AuthProfileRow> {
    sqlx::query_as::<_, AuthProfileRow>("SELECT * FROM auth_profiles WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await?
        .map(decrypt_row)
        .ok_or_else(|| crate::DbError::NotFound(format!("auth profile {id}")))
}

pub async fn update(
    db: &SqlitePool,
    id: &str,
    name: &str,
    method: &str,
    config_json: &str,
    notes: &str,
) -> DbResult<()> {
    let now = crate::now();
    let config_json = seal(config_json)?;
    sqlx::query(
        "UPDATE auth_profiles SET name = ?, method = ?, config_json = ?, notes = ?, updated_at = ?
         WHERE id = ?",
    )
    .bind(name)
    .bind(method)
    .bind(config_json)
    .bind(notes)
    .bind(&now)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete(db: &SqlitePool, id: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM auth_profiles WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}
