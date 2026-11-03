//! Attack Surface inventory: auto-aggregated from scan outputs.
//!
//! The runtime calls [`upsert_asset`] whenever a finding carries asset-like
//! metadata (ip / hostname / port / service). The asset is keyed by a
//! canonical `asset_key` so repeated scans refresh the same row instead of
//! creating duplicates.

use crate::models::AttackSurfaceAssetRow;
use crate::new_id;
use crate::DbResult;
use sqlx::SqlitePool;

/// Canonical key for an asset. Deduplication happens on this string.
pub fn asset_key(kind: &str, value: &str) -> String {
    format!("{kind}:{value}")
}

/// Insert or refresh an asset. `metadata_merge_json` is a JSON object whose
/// top-level keys are merged into the existing `metadata_json` (shallow
/// merge; nested objects replace wholesale).
pub async fn upsert_asset(
    db: &SqlitePool,
    workspace_id: Option<&str>,
    hostname: Option<&str>,
    ip_address: Option<&str>,
    url: Option<&str>,
    metadata_merge_json: &str,
) -> DbResult<AttackSurfaceAssetRow> {
    let now = crate::now();
    // Determine the asset_key. Prefer hostname, then ip, then url.
    let (key_kind, key_value) = hostname
        .map(|h| ("host", h))
        .or_else(|| ip_address.map(|i| ("ip", i)))
        .or_else(|| url.map(|u| ("url", u)))
        .unwrap_or(("host", "unknown"));
    let asset_key = asset_key(key_kind, key_value);

    // Try to fetch existing row to merge metadata.
    let existing: Option<AttackSurfaceAssetRow> = sqlx::query_as::<_, AttackSurfaceAssetRow>(
        "SELECT * FROM attack_surface_assets WHERE asset_key = ?",
    )
    .bind(&asset_key)
    .fetch_optional(db)
    .await?;

    let merged_metadata = match existing {
        Some(ref r) => merge_json(&r.metadata_json, metadata_merge_json),
        None => metadata_merge_json.to_string(),
    };

    if existing.is_some() {
        sqlx::query(
            "UPDATE attack_surface_assets
             SET workspace_id = COALESCE(workspace_id, ?),
                 hostname = COALESCE(hostname, ?),
                 ip_address = COALESCE(ip_address, ?),
                 url = COALESCE(url, ?),
                 metadata_json = ?,
                 last_seen_at = ?
             WHERE asset_key = ?",
        )
        .bind(workspace_id)
        .bind(hostname)
        .bind(ip_address)
        .bind(url)
        .bind(&merged_metadata)
        .bind(&now)
        .bind(&asset_key)
        .execute(db)
        .await?;
    } else {
        let id = new_id();
        sqlx::query(
            "INSERT INTO attack_surface_assets
                (id, workspace_id, hostname, ip_address, url, asset_key,
                 metadata_json, first_seen_at, last_seen_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(workspace_id)
        .bind(hostname)
        .bind(ip_address)
        .bind(url)
        .bind(&asset_key)
        .bind(&merged_metadata)
        .bind(&now)
        .bind(&now)
        .bind(&now)
        .execute(db)
        .await?;
    }

    sqlx::query_as::<_, AttackSurfaceAssetRow>(
        "SELECT * FROM attack_surface_assets WHERE asset_key = ?",
    )
    .bind(&asset_key)
    .fetch_one(db)
    .await
    .map_err(Into::into)
}

/// List assets, optionally filtered by workspace and a free-text `q` (matches
/// hostname / ip / url). Ordered by `last_seen_at DESC`.
pub async fn list(
    db: &SqlitePool,
    workspace_id: Option<&str>,
    q: Option<&str>,
    limit: u32,
) -> DbResult<Vec<AttackSurfaceAssetRow>> {
    let limit = limit.clamp(1, 500) as i64;
    let pat = match q {
        Some(s) if !s.trim().is_empty() => format!("%{}%", s.trim()),
        _ => "%".to_string(),
    };
    match workspace_id {
        Some(ws) => sqlx::query_as::<_, AttackSurfaceAssetRow>(
            "SELECT * FROM attack_surface_assets
             WHERE workspace_id = ?
               AND (hostname LIKE ? OR ip_address LIKE ? OR url LIKE ?)
             ORDER BY last_seen_at DESC LIMIT ?",
        )
        .bind(ws)
        .bind(&pat)
        .bind(&pat)
        .bind(&pat)
        .bind(limit)
        .fetch_all(db)
        .await
        .map_err(Into::into),
        None => sqlx::query_as::<_, AttackSurfaceAssetRow>(
            "SELECT * FROM attack_surface_assets
             WHERE (hostname LIKE ? OR ip_address LIKE ? OR url LIKE ?)
             ORDER BY last_seen_at DESC LIMIT ?",
        )
        .bind(&pat)
        .bind(&pat)
        .bind(&pat)
        .bind(limit)
        .fetch_all(db)
        .await
        .map_err(Into::into),
    }
}

pub async fn count(db: &SqlitePool, workspace_id: Option<&str>) -> DbResult<i64> {
    match workspace_id {
        Some(ws) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM attack_surface_assets WHERE workspace_id = ?")
                .bind(ws)
                .fetch_one(db)
                .await
                .map_err(Into::into)
        }
        None => sqlx::query_scalar("SELECT COUNT(*) FROM attack_surface_assets")
            .fetch_one(db)
            .await
            .map_err(Into::into),
    }
}

/// Authorized asset inventory. Personal/NULL assets lack a reliable owner
/// column and are admin-only until their schema stores an attribution key.
pub async fn list_visible(
    db: &SqlitePool,
    user_id: Option<&str>,
    workspace_id: Option<&str>,
    q: Option<&str>,
    limit: u32,
) -> DbResult<Vec<AttackSurfaceAssetRow>> {
    let pat = q.filter(|q| !q.trim().is_empty())
        .map(|q| format!("%{}%", q.trim()))
        .unwrap_or_else(|| "%".to_string());
    sqlx::query_as::<_, AttackSurfaceAssetRow>(
        "SELECT a.* FROM attack_surface_assets a
         WHERE (?1 IS NULL OR (a.workspace_id IS NOT NULL AND EXISTS (
             SELECT 1 FROM workspaces w WHERE w.id = a.workspace_id
               AND (w.access_mode = 'shared' OR w.created_by = ?1
                 OR EXISTS (SELECT 1 FROM workspace_members wm
                     WHERE wm.workspace_id = w.id AND wm.user_id = ?1))
         )))
         AND (?2 IS NULL OR a.workspace_id = ?2)
         AND (a.hostname LIKE ?3 OR a.ip_address LIKE ?3 OR a.url LIKE ?3)
         ORDER BY a.last_seen_at DESC LIMIT ?4",
    )
    .bind(user_id)
    .bind(workspace_id)
    .bind(&pat)
    .bind(limit.clamp(1, 500) as i64)
    .fetch_all(db)
    .await
    .map_err(Into::into)
}

pub async fn count_visible(
    db: &SqlitePool,
    user_id: Option<&str>,
    workspace_id: Option<&str>,
) -> DbResult<i64> {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM attack_surface_assets a
         WHERE (?1 IS NULL OR (a.workspace_id IS NOT NULL AND EXISTS (
             SELECT 1 FROM workspaces w WHERE w.id = a.workspace_id
               AND (w.access_mode = 'shared' OR w.created_by = ?1
                 OR EXISTS (SELECT 1 FROM workspace_members wm
                     WHERE wm.workspace_id = w.id AND wm.user_id = ?1))
         )))
         AND (?2 IS NULL OR a.workspace_id = ?2)",
    )
    .bind(user_id)
    .bind(workspace_id)
    .fetch_one(db)
    .await
    .map_err(Into::into)
}

pub async fn delete(db: &SqlitePool, id: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM attack_surface_assets WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Shallow JSON object merge: keys in `patch` overwrite keys in `base`.
/// Nested objects are replaced wholesale (not deep-merged). This is good
/// enough for asset metadata, which is small and last-write-wins by design.
fn merge_json(base: &str, patch: &str) -> String {
    use serde_json::Value;
    let mut base_v: Value = serde_json::from_str(base).unwrap_or(Value::Object(Default::default()));
    let patch_v: Value = serde_json::from_str(patch).unwrap_or(Value::Object(Default::default()));
    if let (Some(base_obj), Some(patch_obj)) = (base_v.as_object_mut(), patch_v.as_object()) {
        for (k, v) in patch_obj {
            base_obj.insert(k.clone(), v.clone());
        }
    }
    serde_json::to_string(&base_v).unwrap_or_else(|_| base.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_preserves_existing_keys() {
        let out = merge_json(r#"{"a":1,"b":2}"#, r#"{"b":3,"c":4}"#);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["a"], 1);
        assert_eq!(v["b"], 3);
        assert_eq!(v["c"], 4);
    }

    #[test]
    fn asset_key_is_canonical() {
        assert_eq!(asset_key("host", "example.com"), "host:example.com");
        assert_eq!(asset_key("ip", "1.2.3.4"), "ip:1.2.3.4");
    }
}
