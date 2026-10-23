//! VPN profile repository (OpenVPN configs).

use crate::models::VpnProfileRow;
use crate::{new_id, now, DbResult};
use sqlx::SqlitePool;

pub async fn create(
    db: &SqlitePool,
    user_id: &str,
    name: &str,
    config_text: &str,
) -> DbResult<VpnProfileRow> {
    let id = new_id();
    let ts = now();
    sqlx::query(
        "INSERT INTO vpn_profiles (id, name, config_text, status, created_by, created_at)
         VALUES (?, ?, ?, 'disconnected', ?, ?)",
    )
    .bind(&id)
    .bind(name)
    .bind(config_text)
    .bind(user_id)
    .bind(&ts)
    .execute(db)
    .await?;
    get(db, &id).await
}

pub async fn list(db: &SqlitePool) -> DbResult<Vec<VpnProfileRow>> {
    sqlx::query_as::<_, VpnProfileRow>("SELECT * FROM vpn_profiles ORDER BY created_at DESC")
        .fetch_all(db)
        .await
        .map_err(Into::into)
}

pub async fn get(db: &SqlitePool, id: &str) -> DbResult<VpnProfileRow> {
    sqlx::query_as::<_, VpnProfileRow>("SELECT * FROM vpn_profiles WHERE id = ?")
        .bind(id)
        .fetch_one(db)
        .await
        .map_err(Into::into)
}

pub async fn update_status(
    db: &SqlitePool,
    id: &str,
    status: &str,
    last_error: Option<&str>,
    process_id: Option<i64>,
    interface: Option<&str>,
) -> DbResult<()> {
    let ts = now();
    let connected_at = if status == "connected" { Some(now()) } else { None };
    sqlx::query(
        "UPDATE vpn_profiles SET status = ?, last_error = ?, process_id = ?, interface = ?,
                                connected_at = COALESCE(?, connected_at), updated_at = ?
         WHERE id = ?",
    )
    .bind(status)
    .bind(last_error)
    .bind(process_id)
    .bind(interface)
    .bind(connected_at)
    .bind(&ts)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete(db: &SqlitePool, id: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM vpn_profiles WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Attach a profile to a workspace (marks the workspace VPN-enabled).
pub async fn attach_to_workspace(
    db: &SqlitePool,
    workspace_id: &str,
    profile_id: Option<&str>,
) -> DbResult<()> {
    sqlx::query("UPDATE workspaces SET vpn_profile_id = ? WHERE id = ?")
        .bind(profile_id)
        .bind(workspace_id)
        .execute(db)
        .await?;
    Ok(())
}
