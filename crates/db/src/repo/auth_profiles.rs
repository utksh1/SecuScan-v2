//! Auth profiles — reusable credentials/cookies/headers for web scans.

use crate::{DbError, DbResult};
use crate::models::AuthProfileRow;
use crate::new_id;
use sqlx::SqlitePool;

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
        .await.map_err(Into::into),
        None => sqlx::query_as::<_, AuthProfileRow>(
            "SELECT * FROM auth_profiles ORDER BY created_at DESC",
        )
        .fetch_all(db)
        .await.map_err(Into::into),
    }
}

pub async fn get(db: &SqlitePool, id: &str) -> DbResult<AuthProfileRow> {
    sqlx::query_as::<_, AuthProfileRow>("SELECT * FROM auth_profiles WHERE id = ?")
        .bind(id)
        .fetch_one(db)
        .await.map_err(Into::into)
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
