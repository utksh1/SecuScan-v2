//! Notifications engine: rules + delivery log.
//!
//! A rule is a JSON document specifying triggers and actions. The runtime
//! evaluates rules when a task completes or a finding is created; matching
//! rules fire their actions (email/webhook/Slack/Teams/Discord).

use crate::models::{NotificationLogRow, NotificationRuleRow};
use crate::{new_id, now, DbResult};
use sqlx::SqlitePool;

pub async fn create_rule(
    db: &SqlitePool,
    workspace_id: Option<&str>,
    user_id: &str,
    name: &str,
    rules_json: &str,
) -> DbResult<NotificationRuleRow> {
    let id = new_id();
    let now_ts = now();
    sqlx::query(
        "INSERT INTO notification_rules (id, workspace_id, name, rules_json, enabled,
                                          created_by, created_at)
         VALUES (?, ?, ?, ?, 1, ?, ?)",
    )
    .bind(&id)
    .bind(workspace_id)
    .bind(name)
    .bind(rules_json)
    .bind(user_id)
    .bind(&now_ts)
    .execute(db)
    .await?;
    get_rule(db, &id).await
}

pub async fn list_rules(
    db: &SqlitePool,
    workspace_id: Option<&str>,
) -> DbResult<Vec<NotificationRuleRow>> {
    match workspace_id {
        Some(ws) => sqlx::query_as::<_, NotificationRuleRow>(
            "SELECT * FROM notification_rules WHERE workspace_id = ? ORDER BY created_at DESC",
        )
        .bind(ws)
        .fetch_all(db)
        .await
        .map_err(Into::into),
        None => sqlx::query_as::<_, NotificationRuleRow>(
            "SELECT * FROM notification_rules ORDER BY created_at DESC",
        )
        .fetch_all(db)
        .await
        .map_err(Into::into),
    }
}

pub async fn get_rule(db: &SqlitePool, id: &str) -> DbResult<NotificationRuleRow> {
    sqlx::query_as::<_, NotificationRuleRow>("SELECT * FROM notification_rules WHERE id = ?")
        .bind(id)
        .fetch_one(db)
        .await
        .map_err(Into::into)
}

pub async fn update_rule(
    db: &SqlitePool,
    id: &str,
    name: &str,
    rules_json: &str,
    enabled: bool,
) -> DbResult<()> {
    let now_ts = now();
    sqlx::query(
        "UPDATE notification_rules SET name = ?, rules_json = ?, enabled = ?, updated_at = ?
         WHERE id = ?",
    )
    .bind(name)
    .bind(rules_json)
    .bind(enabled)
    .bind(&now_ts)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete_rule(db: &SqlitePool, id: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM notification_rules WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn list_rules_for_workspace(
    db: &SqlitePool,
    workspace_id: Option<&str>,
) -> DbResult<Vec<NotificationRuleRow>> {
    // Returns rules for the given workspace + global rules (workspace_id IS NULL).
    match workspace_id {
        Some(ws) => sqlx::query_as::<_, NotificationRuleRow>(
            "SELECT * FROM notification_rules
             WHERE enabled = 1 AND (workspace_id = ? OR workspace_id IS NULL)
             ORDER BY created_at DESC",
        )
        .bind(ws)
        .fetch_all(db)
        .await
        .map_err(Into::into),
        None => sqlx::query_as::<_, NotificationRuleRow>(
            "SELECT * FROM notification_rules WHERE enabled = 1 AND workspace_id IS NULL
             ORDER BY created_at DESC",
        )
        .fetch_all(db)
        .await
        .map_err(Into::into),
    }
}

// --- delivery log ---

// This persistence entry point mirrors the existing notification delivery schema.
// Keep its caller-facing signature stable until the notification API is redesigned.
#[allow(clippy::too_many_arguments)]
pub async fn log_delivery(
    db: &SqlitePool,
    rule_id: &str,
    task_id: Option<&str>,
    finding_id: Option<&str>,
    channel: &str,
    status: &str,
    http_status: Option<i64>,
    error: Option<&str>,
    payload_json: &str,
) -> DbResult<NotificationLogRow> {
    let id = new_id();
    let now_ts = now();
    sqlx::query(
        "INSERT INTO notification_log (id, rule_id, task_id, finding_id, channel, status,
                                        http_status, error, payload_json, sent_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(rule_id)
    .bind(task_id)
    .bind(finding_id)
    .bind(channel)
    .bind(status)
    .bind(http_status)
    .bind(error)
    .bind(payload_json)
    .bind(&now_ts)
    .execute(db)
    .await?;
    sqlx::query_as::<_, NotificationLogRow>("SELECT * FROM notification_log WHERE id = ?")
        .bind(&id)
        .fetch_one(db)
        .await
        .map_err(Into::into)
}

pub async fn list_delivery_log(
    db: &SqlitePool,
    rule_id: Option<&str>,
    limit: u32,
) -> DbResult<Vec<NotificationLogRow>> {
    let limit = limit.clamp(1, 500) as i64;
    match rule_id {
        Some(rid) => sqlx::query_as::<_, NotificationLogRow>(
            "SELECT * FROM notification_log WHERE rule_id = ? ORDER BY sent_at DESC LIMIT ?",
        )
        .bind(rid)
        .bind(limit)
        .fetch_all(db)
        .await
        .map_err(Into::into),
        None => sqlx::query_as::<_, NotificationLogRow>(
            "SELECT * FROM notification_log ORDER BY sent_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(db)
        .await
        .map_err(Into::into),
    }
}
