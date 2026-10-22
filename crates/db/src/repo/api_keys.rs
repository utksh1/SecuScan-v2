//! API keys (automation access; `X-API-Key` header).
//!
//! Keys are shown once at creation and stored only as SHA-256 hashes with a
//! short prefix used for lookup hints.

use crate::models::ApiKeyRow;
use crate::{generate_token, new_id, now, sha256_hex, DbResult};
use sqlx::SqlitePool;

/// A newly created key: `raw` is shown exactly once.
pub struct CreatedApiKey {
    pub row: ApiKeyRow,
    pub raw: String,
}

pub async fn create(pool: &SqlitePool, user_id: &str, name: &str) -> DbResult<CreatedApiKey> {
    let raw = generate_token("scsk");
    let prefix = raw[..12].to_string();
    let row = ApiKeyRow {
        id: new_id(),
        user_id: user_id.to_string(),
        name: name.trim().to_string(),
        prefix: prefix.clone(),
        key_hash: sha256_hex(&raw),
        created_at: now(),
        last_used_at: None,
        revoked_at: None,
    };
    sqlx::query(
        "INSERT INTO api_keys (id, user_id, name, prefix, key_hash, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&row.id)
    .bind(&row.user_id)
    .bind(&row.name)
    .bind(&row.prefix)
    .bind(&row.key_hash)
    .bind(&row.created_at)
    .execute(pool)
    .await?;
    Ok(CreatedApiKey { row, raw })
}

/// Resolve a raw API key to its owner. Marks `last_used_at` (best effort).
pub async fn verify(pool: &SqlitePool, raw: &str) -> DbResult<Option<ApiKeyRow>> {
    let hash = sha256_hex(raw);
    let mut row = sqlx::query_as::<_, ApiKeyRow>(
        "SELECT * FROM api_keys WHERE key_hash = ?1 AND revoked_at IS NULL",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await?;
    if let Some(r) = row.as_mut() {
        let ts = now();
        let _ = sqlx::query("UPDATE api_keys SET last_used_at = ?1 WHERE key_hash = ?2")
            .bind(&ts)
            .bind(&hash)
            .execute(pool)
            .await;
        r.last_used_at = Some(ts);
    }
    Ok(row)
}

pub async fn list_for_user(pool: &SqlitePool, user_id: &str) -> DbResult<Vec<ApiKeyRow>> {
    sqlx::query_as::<_, ApiKeyRow>(
        "SELECT * FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

pub async fn revoke(pool: &SqlitePool, id: &str, user_id: &str) -> DbResult<bool> {
    let res = sqlx::query(
        "UPDATE api_keys SET revoked_at = ?1 WHERE id = ?2 AND user_id = ?3 AND revoked_at IS NULL",
    )
    .bind(now())
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}
