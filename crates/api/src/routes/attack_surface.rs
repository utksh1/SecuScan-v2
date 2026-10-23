//! Attack Surface HTTP routes — read-only views over the auto-aggregated
//! asset inventory.

use crate::auth::extractor::CurrentUser;
use crate::error::ApiResult;
use crate::state::SharedState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        .route("/attack-surface", axum::routing::get(list))
        .route("/attack-surface/summary", axum::routing::get(summary))
        .route("/attack-surface/:id", axum::routing::delete(delete_one))
}

#[derive(Deserialize, Default)]
struct ListQuery {
    #[serde(default)]
    workspace_id: Option<String>,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
}

fn asset_to_json(a: &secuscan_db::models::AttackSurfaceAssetRow) -> Value {
    json!({
        "id": a.id,
        "workspace_id": a.workspace_id,
        "hostname": a.hostname,
        "ip_address": a.ip_address,
        "url": a.url,
        "asset_key": a.asset_key,
        "metadata": serde_json::from_str::<Value>(&a.metadata_json).unwrap_or(json!({})),
        "first_seen_at": a.first_seen_at,
        "last_seen_at": a.last_seen_at,
        "created_at": a.created_at,
    })
}

async fn list(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let limit = q.limit.unwrap_or(200);
    let rows = secuscan_db::repo::attack_surface::list(
        &state.db,
        q.workspace_id.as_deref(),
        q.q.as_deref(),
        limit,
    )
    .await?;
    Ok(Json(json!({
        "items": rows.iter().map(asset_to_json).collect::<Vec<_>>(),
    })))
}

async fn summary(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let total = secuscan_db::repo::attack_surface::count(
        &state.db,
        q.workspace_id.as_deref(),
    )
    .await?;
    // Get top technologies by counting occurrences in metadata.technologies
    let rows = secuscan_db::repo::attack_surface::list(
        &state.db,
        q.workspace_id.as_deref(),
        None,
        500,
    )
    .await?;
    let mut tech_counts: std::collections::BTreeMap<String, usize> = Default::default();
    let mut service_counts: std::collections::BTreeMap<String, usize> = Default::default();
    let mut risk_counts: std::collections::BTreeMap<String, usize> = Default::default();
    for r in &rows {
        let meta: Value = serde_json::from_str(&r.metadata_json).unwrap_or(json!({}));
        if let Some(techs) = meta.get("technologies").and_then(|v| v.as_array()) {
            for t in techs {
                if let Some(s) = t.as_str() {
                    *tech_counts.entry(s.to_string()).or_default() += 1;
                }
            }
        }
        if let Some(services) = meta.get("services").and_then(|v| v.as_array()) {
            for s in services {
                if let Some(name) = s.get("product").and_then(|v| v.as_str()) {
                    *service_counts.entry(name.to_string()).or_default() += 1;
                }
            }
        }
        if let Some(risks) = meta.get("risks").and_then(|v| v.as_array()) {
            for r in risks {
                if let Some(s) = r.as_str() {
                    *risk_counts.entry(s.to_string()).or_default() += 1;
                }
            }
        }
    }
    let top_tech = tech_counts.into_iter()
        .map(|(k, v)| json!({"name": k, "count": v}))
        .collect::<Vec<_>>();
    let top_services = service_counts.into_iter()
        .map(|(k, v)| json!({"name": k, "count": v}))
        .collect::<Vec<_>>();
    let top_risks = risk_counts.into_iter()
        .map(|(k, v)| json!({"name": k, "count": v}))
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "total_assets": total,
        "top_technologies": top_tech,
        "top_services": top_services,
        "top_risks": top_risks,
    })))
}

async fn delete_one(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    secuscan_db::repo::attack_surface::delete(&state.db, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}
