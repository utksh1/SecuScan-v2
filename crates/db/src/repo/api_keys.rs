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

pub async fn create(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    expires_in_days: Option<u32>,
) -> DbResult<CreatedApiKey> {
    create_with_scope(pool, user_id, name, "full", None, expires_in_days).await
}

/// Only an authenticated admin endpoint should call this factory. The owner
/// must be a dedicated scanner account, not an administrator account.
pub async fn create_mcp_scoped(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    issued_by: &str,
) -> DbResult<CreatedApiKey> {
    // Admin-issued scoped keys do not expire by default (issue #23 task 3.3
    // covers the self-service key surface).
    create_with_scope(pool, user_id, name, "mcp_scan", Some(issued_by), None).await
}

async fn create_with_scope(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    scope: &str,
    issued_by: Option<&str>,
    expires_in_days: Option<u32>,
) -> DbResult<CreatedApiKey> {
    let raw = generate_token(if scope == "mcp_scan" { "scmcp" } else { "scsk" });
    let prefix = raw[..12].to_string();
    let expires_at = expires_in_days.map(|days| {
        (chrono::Utc::now() + chrono::Duration::days(days as i64))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    });
    let row = ApiKeyRow {
        id: new_id(),
        user_id: user_id.to_string(),
        name: name.trim().to_string(),
        prefix: prefix.clone(),
        key_hash: sha256_hex(&raw),
        scope: scope.to_string(),
        issued_by: issued_by.map(str::to_string),
        created_at: now(),
        last_used_at: None,
        revoked_at: None,
        expires_at,
    };
    sqlx::query(
        "INSERT INTO api_keys (id, user_id, name, prefix, key_hash, scope, issued_by, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind(&row.id)
    .bind(&row.user_id)
    .bind(&row.name)
    .bind(&row.prefix)
    .bind(&row.key_hash)
    .bind(&row.scope)
    .bind(&row.issued_by)
    .bind(&row.created_at)
    .bind(&row.expires_at)
    .execute(pool)
    .await?;
    Ok(CreatedApiKey { row, raw })
}

/// Resolve a raw API key to its owner. Marks `last_used_at` (best effort).
/// Expired keys (Sprint 1.3) verify as rejected and get their `revoked_at`
/// stamped on first sight so the listing reflects the real state.
pub async fn verify(pool: &SqlitePool, raw: &str) -> DbResult<Option<ApiKeyRow>> {
    let hash = sha256_hex(raw);
    let mut row = sqlx::query_as::<_, ApiKeyRow>(
        "SELECT * FROM api_keys WHERE key_hash = ?1 AND revoked_at IS NULL",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await?;
    if let Some(r) = row.as_mut() {
        if let Some(exp) = &r.expires_at {
            if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(exp) {
                if exp.with_timezone(&chrono::Utc) < chrono::Utc::now() {
                    // Expired: reject and stamp revoked_at (best effort).
                    let _ = sqlx::query(
                        "UPDATE api_keys SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
                    )
                    .bind(&now())
                    .bind(&r.id)
                    .execute(pool)
                    .await;
                    return Ok(None);
                }
            }
        }
    }
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

/// Admin-only inventory of scoped keys (returns metadata, never plaintext).
pub async fn list_mcp_scoped(pool: &SqlitePool) -> DbResult<Vec<ApiKeyRow>> {
    sqlx::query_as::<_, ApiKeyRow>(
        "SELECT * FROM api_keys WHERE scope = 'mcp_scan' ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

/// Revoke an MCP-scoped key by id, independent of who owns the scanner account.
pub async fn revoke_mcp_scoped(pool: &SqlitePool, id: &str) -> DbResult<bool> {
    let res = sqlx::query(
        "UPDATE api_keys SET revoked_at = ?1
         WHERE id = ?2 AND scope = 'mcp_scan' AND revoked_at IS NULL",
    )
    .bind(now())
    .bind(id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}
