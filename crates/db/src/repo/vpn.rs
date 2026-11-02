//! VPN profile repository (OpenVPN configs).
//!
//! `config_text` is encrypted at rest (AES-256-GCM, see
//! `secuscan_core::crypto`); the vpn_manager decrypts in memory right
//! before writing the throwaway openvpn config file.

use crate::models::VpnProfileRow;
use crate::{new_id, now, DbError, DbResult};
use sqlx::SqlitePool;

fn seal(config_text: &str) -> Result<String, DbError> {
    secuscan_core::crypto::encrypt_to_storage(config_text)
        .map_err(|e| DbError::Invalid(format!("encrypt vpn config: {e}")))
}

fn open(config_text: &str) -> String {
    match secuscan_core::crypto::decrypt_from_storage(config_text) {
        Ok(plain) => plain,
        Err(e) => {
            tracing::error!("vpn config is encrypted but undecryptable ({e}); returning raw value");
            config_text.to_string()
        }
    }
}

fn decrypt_row(mut row: VpnProfileRow) -> VpnProfileRow {
    row.config_text = open(&row.config_text);
    row
}

pub async fn create(
    db: &SqlitePool,
    user_id: &str,
    name: &str,
    config_text: &str,
) -> DbResult<VpnProfileRow> {
    let id = new_id();
    let ts = now();
    let config_text = seal(config_text)?;
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
        .map(|rows| rows.into_iter().map(decrypt_row).collect())
        .map_err(Into::into)
}

pub async fn get(db: &SqlitePool, id: &str) -> DbResult<VpnProfileRow> {
    sqlx::query_as::<_, VpnProfileRow>("SELECT * FROM vpn_profiles WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await?
        .map(decrypt_row)
        .ok_or_else(|| crate::DbError::NotFound(format!("vpn profile {id}")))
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
    let connected_at = if status == "connected" {
        Some(now())
    } else {
        None
    };
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
