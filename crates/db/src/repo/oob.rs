//! OOB (out-of-band) callback infrastructure.
//!
//! Two tables: `oob_handlers` (user-created callback endpoints with a secret
//! URL segment) and `oob_hits` (every request received). Plus per-scan OOB
//! markers stored on `tasks.oob_marker` for blind-vuln correlation.
//!
//! The HTTP endpoint that receives callbacks lives in `crates/api/src/routes/oob.rs`.
//! It accepts any path under `/oob/:secret` and records the hit.

use crate::models::{OobHandlerRow, OobHitRow};
use crate::{new_id, now, DbError, DbResult};
use rand::RngCore;
use sqlx::SqlitePool;

/// Generate a fresh 16-char hex secret for an OOB handler.
pub fn new_secret() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Generate a fresh 12-char OOB marker for a scan (pentest-tools.com style
/// `ptt1a2b3c4d` — we use the same prefix for familiarity).
pub fn new_marker() -> String {
    let mut bytes = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("ptt{}", hex::encode(bytes))
}

pub async fn create_handler(
    db: &SqlitePool,
    workspace_id: Option<&str>,
    user_id: &str,
    name: &str,
    kind: &str,
    config_json: &str,
    ttl_seconds: i64,
) -> DbResult<OobHandlerRow> {
    if !["http_logger", "xss_exploiter"].contains(&kind) {
        return Err(DbError::Invalid(format!("unknown OOB kind: {kind}")));
    }
    if name.trim().is_empty() || name.len() > 120 {
        return Err(DbError::Invalid("name must be 1..=120 characters".into()));
    }
    let id = new_id();
    let secret = new_secret();
    let now_ts = now();
    // expires_at = now + ttl (ISO 8601)
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl_seconds);
    sqlx::query(
        "INSERT INTO oob_handlers (id, workspace_id, user_id, name, kind, config_json, secret,
                                    expires_at, created_at, hit_count, last_hit_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)",
    )
    .bind(&id)
    .bind(workspace_id)
    .bind(user_id)
    .bind(name)
    .bind(kind)
    .bind(config_json)
    .bind(&secret)
    .bind(expires_at.to_rfc3339())
    .bind(&now_ts)
    .execute(db)
    .await?;
    get_handler(db, &id).await
}

pub async fn list_handlers(
    db: &SqlitePool,
    workspace_id: Option<&str>,
) -> DbResult<Vec<OobHandlerRow>> {
    match workspace_id {
        Some(ws) => sqlx::query_as::<_, OobHandlerRow>(
            "SELECT * FROM oob_handlers WHERE workspace_id = ? ORDER BY created_at DESC",
        )
        .bind(ws)
        .fetch_all(db)
        .await
        .map_err(Into::into),
        None => sqlx::query_as::<_, OobHandlerRow>(
            "SELECT * FROM oob_handlers ORDER BY created_at DESC",
        )
        .fetch_all(db)
        .await
        .map_err(Into::into),
    }
}

pub async fn get_handler(db: &SqlitePool, id: &str) -> DbResult<OobHandlerRow> {
    sqlx::query_as::<_, OobHandlerRow>("SELECT * FROM oob_handlers WHERE id = ?")
        .bind(id)
        .fetch_one(db)
        .await
        .map_err(Into::into)
}

pub async fn get_handler_by_secret(
    db: &SqlitePool,
    secret: &str,
) -> DbResult<Option<OobHandlerRow>> {
    sqlx::query_as::<_, OobHandlerRow>("SELECT * FROM oob_handlers WHERE secret = ?")
        .bind(secret)
        .fetch_optional(db)
        .await
        .map_err(Into::into)
}

pub async fn delete_handler(db: &SqlitePool, id: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM oob_handlers WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn record_hit(
    db: &SqlitePool,
    handler_id: &str,
    task_id: Option<&str>,
    payload_json: &str,
) -> DbResult<OobHitRow> {
    let id = new_id();
    let now_ts = now();
    sqlx::query(
        "INSERT INTO oob_hits (id, handler_id, task_id, payload_json, received_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(handler_id)
    .bind(task_id)
    .bind(payload_json)
    .bind(&now_ts)
    .execute(db)
    .await?;
    // Bump hit count + last_hit_at on the handler.
    sqlx::query("UPDATE oob_handlers SET hit_count = hit_count + 1, last_hit_at = ? WHERE id = ?")
        .bind(&now_ts)
        .bind(handler_id)
        .execute(db)
        .await?;
    get_hit(db, &id).await
}

pub async fn get_hit(db: &SqlitePool, id: &str) -> DbResult<OobHitRow> {
    sqlx::query_as::<_, OobHitRow>("SELECT * FROM oob_hits WHERE id = ?")
        .bind(id)
        .fetch_one(db)
        .await
        .map_err(Into::into)
}

pub async fn list_hits(db: &SqlitePool, handler_id: &str, limit: u32) -> DbResult<Vec<OobHitRow>> {
    let limit = limit.clamp(1, 500) as i64;
    sqlx::query_as::<_, OobHitRow>(
        "SELECT * FROM oob_hits WHERE handler_id = ? ORDER BY received_at DESC LIMIT ?",
    )
    .bind(handler_id)
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(Into::into)
}

pub async fn clear_hits(db: &SqlitePool, handler_id: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM oob_hits WHERE handler_id = ?")
        .bind(handler_id)
        .execute(db)
        .await?;
    sqlx::query("UPDATE oob_handlers SET hit_count = 0, last_hit_at = NULL WHERE id = ?")
        .bind(handler_id)
        .execute(db)
        .await?;
    Ok(())
}
