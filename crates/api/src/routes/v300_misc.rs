//! v3.0.0 misc routes: scan groups, wordlists, finding templates, asset imports.

use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        // scan groups
        .route(
            "/scan-groups",
            axum::routing::get(list_scan_groups).post(create_scan_group),
        )
        .route(
            "/scan-groups/:id",
            axum::routing::get(get_scan_group).delete(delete_scan_group),
        )
        .route(
            "/scan-groups/:id/tasks",
            axum::routing::post(add_task_to_scan_group),
        )
        .route(
            "/scan-groups/:id/tasks/:task_id",
            axum::routing::delete(remove_task_from_scan_group),
        )
        // wordlists
        .route(
            "/wordlists",
            axum::routing::get(list_wordlists).post(upload_wordlist),
        )
        .route(
            "/wordlists/:id",
            axum::routing::get(get_wordlist).delete(delete_wordlist),
        )
        .route(
            "/wordlists/:id/contents",
            axum::routing::get(get_wordlist_contents),
        )
        // finding templates
        .route(
            "/finding-templates",
            axum::routing::get(list_templates).post(create_template),
        )
        .route(
            "/finding-templates/:id",
            axum::routing::delete(delete_template),
        )
        // asset imports
        .route("/asset-imports", axum::routing::post(import_assets))
        .route("/asset-imports", axum::routing::get(list_asset_imports))
}

// --- Scan Groups ----------------------------------------------------------

#[derive(Deserialize, Default)]
struct WsQuery {
    #[serde(default)]
    workspace_id: Option<String>,
}

fn scan_group_to_json(g: &secuscan_db::models::ScanGroupRow) -> Value {
    json!({
        "id": g.id, "workspace_id": g.workspace_id, "name": g.name,
        "description": g.description, "created_by": g.created_by, "created_at": g.created_at,
    })
}

async fn list_scan_groups(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Query(q): Query<WsQuery>,
) -> ApiResult<Json<Value>> {
    let rows = secuscan_db::repo::v300_misc::list_scan_groups(&state.db, q.workspace_id.as_deref())
        .await?;
    Ok(Json(
        json!({"items": rows.iter().map(scan_group_to_json).collect::<Vec<_>>()}),
    ))
}

#[derive(Deserialize)]
struct CreateScanGroupRequest {
    #[serde(default)]
    workspace_id: Option<String>,
    name: String,
    #[serde(default)]
    description: String,
}

async fn create_scan_group(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<CreateScanGroupRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    if req.name.trim().is_empty() || req.name.len() > 120 {
        return Err(ApiError::BadRequest(
            "name must be 1..=120 characters".into(),
        ));
    }
    let row = secuscan_db::repo::v300_misc::create_scan_group(
        &state.db,
        req.workspace_id.as_deref(),
        &user.0.id,
        &req.name,
        &req.description,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(scan_group_to_json(&row))))
}

async fn get_scan_group(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let row = secuscan_db::repo::v300_misc::list_scan_groups(&state.db, None)
        .await?
        .into_iter()
        .find(|g| g.id == id)
        .ok_or_else(|| ApiError::NotFound(format!("scan group {id}")))?;
    let task_ids = secuscan_db::repo::v300_misc::list_tasks_in_group(&state.db, &id).await?;
    let mut g = scan_group_to_json(&row);
    g["task_ids"] = json!(task_ids);
    Ok(Json(g))
}

async fn delete_scan_group(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    secuscan_db::repo::v300_misc::delete_scan_group(&state.db, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct AddTaskRequest {
    task_id: String,
}

async fn add_task_to_scan_group(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<AddTaskRequest>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    secuscan_db::repo::v300_misc::add_task_to_group(&state.db, &id, &req.task_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_task_from_scan_group(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path((id, task_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    sqlx::query("DELETE FROM scan_group_members WHERE scan_group_id = ? AND task_id = ?")
        .bind(&id)
        .bind(&task_id)
        .execute(&state.db)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Wordlists ------------------------------------------------------------

fn wordlist_to_json(w: &secuscan_db::models::WordlistRow) -> Value {
    json!({
        "id": w.id, "workspace_id": w.workspace_id, "name": w.name,
        "source": w.source, "file_path": w.file_path, "word_count": w.word_count,
        "size_bytes": w.size_bytes, "kind": w.kind, "created_by": w.created_by,
        "created_at": w.created_at,
    })
}

async fn list_wordlists(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Query(q): Query<WsQuery>,
) -> ApiResult<Json<Value>> {
    let rows =
        secuscan_db::repo::v300_misc::list_wordlists(&state.db, q.workspace_id.as_deref()).await?;
    Ok(Json(
        json!({"items": rows.iter().map(wordlist_to_json).collect::<Vec<_>>()}),
    ))
}

async fn upload_wordlist(
    State(state): State<SharedState>,
    user: CurrentUser,
    mut mp: Multipart,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    let mut name: Option<String> = None;
    let mut workspace_id: Option<String> = None;
    let mut kind = "generic".to_string();
    let mut content: Option<Vec<u8>> = None;
    while let Some(field) = mp
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(format!("multipart: {e}")))?
    {
        match field.name() {
            Some("file") => {
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| ApiError::BadRequest(format!("read: {e}")))?;
                if bytes.len() > 16 * 1024 * 1024 {
                    return Err(ApiError::BadRequest("wordlist must be <= 16MB".into()));
                }
                content = Some(bytes.to_vec());
            }
            Some("name") => {
                name = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| e.to_string())
                        .unwrap_or_default(),
                );
            }
            Some("workspace_id") => {
                workspace_id = Some(field.text().await.unwrap_or_default());
            }
            Some("kind") => {
                kind = field.text().await.unwrap_or_default();
            }
            _ => {}
        }
    }
    let name = name.ok_or_else(|| ApiError::BadRequest("missing name".into()))?;
    let content = content.ok_or_else(|| ApiError::BadRequest("missing file".into()))?;
    let word_count = content.iter().filter(|b| **b == b'\n').count() as i64 + 1;
    let size_bytes = content.len() as i64;
    // Write to disk under data_dir/wordlists/<id>.txt
    let id = secuscan_db::new_id();
    let dir = state.config.data_dir.join("wordlists");
    let _ = std::fs::create_dir_all(&dir);
    let file_path = dir.join(format!("{id}.txt"));
    std::fs::write(&file_path, &content).map_err(|e| ApiError::Internal(format!("write: {e}")))?;
    let row = secuscan_db::repo::v300_misc::create_wordlist(
        &state.db,
        workspace_id.as_deref(),
        &user.0.id,
        &name,
        file_path.to_str().unwrap_or(""),
        word_count,
        size_bytes,
        &kind,
        "user",
    )
    .await?;
    Ok((StatusCode::CREATED, Json(wordlist_to_json(&row))))
}

async fn get_wordlist(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let row = secuscan_db::repo::v300_misc::get_wordlist(&state.db, &id).await?;
    if row.source != "builtin" {
        crate::access::require_owner(&user, &row.created_by)?;
    }
    Ok(Json(wordlist_to_json(&row)))
}

async fn delete_wordlist(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    let row = secuscan_db::repo::v300_misc::get_wordlist(&state.db, &id).await?;
    if row.source == "builtin" {
        return Err(ApiError::Forbidden(
            "builtin wordlists cannot be deleted".into(),
        ));
    }
    crate::access::require_owner(&user, &row.created_by)?;
    // Remove file.
    let _ = std::fs::remove_file(&row.file_path);
    secuscan_db::repo::v300_misc::delete_wordlist(&state.db, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
struct ContentsQuery {
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    offset: Option<u32>,
}

async fn get_wordlist_contents(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Query(q): Query<ContentsQuery>,
) -> ApiResult<Json<Value>> {
    let row = secuscan_db::repo::v300_misc::get_wordlist(&state.db, &id).await?;
    if row.source != "builtin" {
        crate::access::require_owner(&user, &row.created_by)?;
    }
    let limit = q.limit.unwrap_or(1000) as usize;
    let offset = q.offset.unwrap_or(0) as usize;
    let content = std::fs::read_to_string(&row.file_path)
        .map_err(|e| ApiError::Internal(format!("read: {e}")))?;
    let words: Vec<&str> = content.lines().skip(offset).take(limit).collect();
    Ok(Json(json!({
        "id": id, "words": words, "truncated": (offset + words.len()) < row.word_count as usize,
    })))
}

// --- Finding Templates ----------------------------------------------------

fn template_to_json(t: &secuscan_db::models::FindingTemplateRow) -> Value {
    json!({
        "id": t.id, "scope": t.scope, "workspace_id": t.workspace_id,
        "title": t.title, "category": t.category, "severity": t.severity,
        "description": t.description, "remediation": t.remediation,
        "cwe": t.cwe, "owasp": t.owasp, "created_by": t.created_by, "created_at": t.created_at,
    })
}

#[derive(Deserialize, Default)]
struct TemplateQuery {
    #[serde(default)]
    workspace_id: Option<String>,
    #[serde(default)]
    category: Option<String>,
}

async fn list_templates(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Query(q): Query<TemplateQuery>,
) -> ApiResult<Json<Value>> {
    let rows = secuscan_db::repo::v300_misc::list_templates(
        &state.db,
        q.workspace_id.as_deref(),
        q.category.as_deref(),
    )
    .await?;
    Ok(Json(
        json!({"items": rows.iter().map(template_to_json).collect::<Vec<_>>()}),
    ))
}

#[derive(Deserialize)]
struct CreateTemplateRequest {
    #[serde(default)]
    workspace_id: Option<String>,
    title: String,
    category: String,
    severity: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    remediation: String,
    #[serde(default)]
    cwe: Option<String>,
    #[serde(default)]
    owasp: Option<String>,
}

async fn create_template(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<CreateTemplateRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    if !["critical", "high", "medium", "low", "info"].contains(&req.severity.as_str()) {
        return Err(ApiError::BadRequest("invalid severity".into()));
    }
    let scope = if req.workspace_id.is_some() {
        "workspace"
    } else {
        "public"
    };
    let row = secuscan_db::repo::v300_misc::create_template(
        &state.db,
        scope,
        req.workspace_id.as_deref(),
        &req.title,
        &req.category,
        &req.severity,
        &req.description,
        &req.remediation,
        req.cwe.as_deref(),
        req.owasp.as_deref(),
        Some(&user.0.id),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(template_to_json(&row))))
}

async fn delete_template(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    secuscan_db::repo::v300_misc::delete_template(&state.db, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Asset Imports --------------------------------------------------------

#[derive(Deserialize)]
struct ImportAssetsRequest {
    workspace_id: String,
    /// 'txt' | 'cidr' | 'aws_iam'
    source: String,
    /// For 'txt': newline-separated targets; for 'cidr': a CIDR like 10.0.0.0/24;
    /// for 'aws_iam': not implemented (returns 501).
    targets: String,
}

async fn import_assets(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<ImportAssetsRequest>,
) -> ApiResult<Json<Value>> {
    user.require_scanner()?;
    secuscan_db::repo::workspaces::get_workspace(&state.db, &req.workspace_id).await?;
    let mut created = 0i64;
    let mut skipped = 0i64;
    match req.source.as_str() {
        "txt" => {
            for line in req.targets.lines() {
                let name = line.trim();
                if name.is_empty() {
                    continue;
                }
                // Try to add as a target. If it already exists (UNIQUE constraint), skip.
                let result = sqlx::query(
                    "INSERT OR IGNORE INTO targets (id, workspace_id, name, kind, description,
                                                     created_by, created_at)
                     VALUES (?, ?, ?, ?, '', ?, ?)",
                )
                .bind(secuscan_db::new_id())
                .bind(&req.workspace_id)
                .bind(name)
                .bind(classify_target(name))
                .bind(&user.0.id)
                .bind(secuscan_db::now())
                .execute(&state.db)
                .await;
                match result {
                    Ok(r) => {
                        if r.rows_affected() > 0 {
                            created += 1;
                        } else {
                            skipped += 1;
                        }
                    }
                    Err(_) => skipped += 1,
                }
            }
        }
        "cidr" => {
            let cidr = req.targets.trim();
            let parts: Vec<&str> = cidr.split('/').collect();
            if parts.len() != 2 {
                return Err(ApiError::BadRequest("invalid CIDR (use x.x.x.x/24)".into()));
            }
            let base: Vec<u8> = parts[0].split('.').filter_map(|s| s.parse().ok()).collect();
            let prefix: u8 = parts[1]
                .parse()
                .map_err(|_| ApiError::BadRequest("invalid prefix".into()))?;
            if base.len() != 4 || prefix > 32 {
                return Err(ApiError::BadRequest("invalid CIDR".into()));
            }
            // Only support /24..=32 to avoid quota explosions.
            if prefix < 24 {
                return Err(ApiError::BadRequest(
                    "CIDR prefix must be /24 or larger".into(),
                ));
            }
            let count = 1u32 << (32 - prefix);
            let base_int: u32 = ((base[0] as u32) << 24)
                | ((base[1] as u32) << 16)
                | ((base[2] as u32) << 8)
                | (base[3] as u32);
            for i in 0..count {
                let ip_int = base_int + i;
                let name = format!(
                    "{}.{}.{}.{}",
                    (ip_int >> 24) & 0xff,
                    (ip_int >> 16) & 0xff,
                    (ip_int >> 8) & 0xff,
                    ip_int & 0xff
                );
                let result = sqlx::query(
                    "INSERT OR IGNORE INTO targets (id, workspace_id, name, kind, description,
                                                     created_by, created_at)
                     VALUES (?, ?, ?, 'ip_address', '', ?, ?)",
                )
                .bind(secuscan_db::new_id())
                .bind(&req.workspace_id)
                .bind(&name)
                .bind(&user.0.id)
                .bind(secuscan_db::now())
                .execute(&state.db)
                .await;
                match result {
                    Ok(r) => {
                        if r.rows_affected() > 0 {
                            created += 1;
                        } else {
                            skipped += 1;
                        }
                    }
                    Err(_) => skipped += 1,
                }
            }
        }
        "aws_iam" => {
            return Err(ApiError::BadRequest(
                "aws_iam import requires AWS credentials configuration (not yet implemented)"
                    .into(),
            ));
        }
        other => return Err(ApiError::BadRequest(format!("unknown source: {other}"))),
    }
    let summary = match req.source.as_str() {
        "txt" => format!(
            "{} targets from text input",
            req.targets.lines().filter(|l| !l.trim().is_empty()).count()
        ),
        "cidr" => format!("CIDR {}", req.targets.trim()),
        _ => req.source.clone(),
    };
    let row = secuscan_db::repo::v300_misc::record_asset_import(
        &state.db,
        &req.workspace_id,
        &req.source,
        &summary,
        created,
        skipped,
        &user.0.id,
    )
    .await?;
    Ok(Json(json!({
        "import_id": row.id, "created": created, "skipped": skipped, "summary": summary,
    })))
}

async fn list_asset_imports(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Query(q): Query<WsQuery>,
) -> ApiResult<Json<Value>> {
    let ws = q
        .workspace_id
        .ok_or_else(|| ApiError::BadRequest("workspace_id required".into()))?;
    let rows = secuscan_db::repo::v300_misc::list_asset_imports(&state.db, &ws).await?;
    Ok(Json(json!({
        "items": rows.iter().map(|r| json!({
            "id": r.id, "workspace_id": r.workspace_id, "source": r.source,
            "summary": r.summary, "created_count": r.created_count,
            "skipped_count": r.skipped_count, "created_by": r.created_by, "created_at": r.created_at,
        })).collect::<Vec<_>>(),
    })))
}

fn classify_target(name: &str) -> &'static str {
    if name.parse::<std::net::IpAddr>().is_ok() {
        "ip_address"
    } else if name.starts_with("http://") || name.starts_with("https://") {
        "url"
    } else {
        "hostname"
    }
}
