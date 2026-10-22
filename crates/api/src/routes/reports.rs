//! Report exports and async report jobs.
//!
//! Two surfaces:
//! * `GET /tasks/:id/report/:format` — synchronous one-shot export kept for
//!   scripts and backward compatibility (streams the rendered body).
//! * `POST /tasks/:id/reports` + `GET/DELETE /reports...` — the async job
//!   pipeline (waiting → in_progress → finished/failed) with artifact
//!   downloads and optional signed webhooks.

use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::report_jobs::{
    job_to_json, spawn_job, MAX_ACTIVE_JOBS_PER_USER, RETAINED_FINISHED_JOBS,
};
use crate::reports_render::{self, FORMATS, SEVERITY_THRESHOLDS};
use crate::routes::tasks::load_task_for_user;
use crate::state::SharedState;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use secuscan_db::repo;
use serde::Deserialize;
use serde_json::json;
use std::path::PathBuf;

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        .route("/tasks/:id/report/:format", axum::routing::get(export_sync))
        .route("/tasks/:id/reports", axum::routing::post(create_job))
        .route("/reports", axum::routing::get(list_jobs))
        .route(
            "/reports/:id",
            axum::routing::get(get_job).delete(delete_job),
        )
        .route("/reports/:id/download", axum::routing::get(download_job))
}

// ---------------------------------------------------------------------------
// Synchronous export (back-compat)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ExportQuery {
    /// Minimum severity to include (low|medium|high|critical).
    severity: Option<String>,
}

async fn export_sync(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path((id, format)): Path<(String, String)>,
    Query(q): Query<ExportQuery>,
) -> ApiResult<Response> {
    let task = load_task_for_user(&state, &user, &id).await?;
    let format = canonical_format(&format)?;
    if let Some(sev) = &q.severity {
        validate_severity(sev)?;
    }
    let findings = repo::findings::list(
        &state.db,
        &repo::findings::FindingFilters {
            task_id: Some(id.clone()),
            limit: 5000,
            ..Default::default()
        },
    )
    .await?;
    let filtered = reports_render::filter_min_severity(&findings, q.severity.as_deref());
    let owned: Vec<_> = filtered.into_iter().cloned().collect();

    let rendered = reports_render::render(&task, &owned, format).map_err(ApiError::BadRequest)?;
    Ok(text_response(
        rendered.bytes,
        rendered.content_type,
        &reports_render::report_filename(&task, rendered.ext),
    ))
}

// ---------------------------------------------------------------------------
// Async report jobs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateJobRequest {
    format: String,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    webhook_url: Option<String>,
    #[serde(default)]
    webhook_secret: Option<String>,
}

async fn create_job(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(body): Json<CreateJobRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    user.require_scanner()?;
    let format = canonical_format(&body.format)?;
    if let Some(sev) = &body.severity {
        validate_severity(sev)?;
    }
    let webhook_url = match &body.webhook_url {
        Some(u) => Some(validate_webhook_url(u)?),
        None => None,
    };
    if let Some(secret) = &body.webhook_secret {
        if secret.len() > 256 {
            return Err(ApiError::BadRequest(
                "webhook_secret exceeds 256 bytes".into(),
            ));
        }
    }
    // Task must exist and be visible to this user (owner or admin).
    load_task_for_user(&state, &user, &id).await?;

    // Admission cap: bound how many jobs one user can have in flight.
    let active = repo::reports::count_active_for_user(&state.db, &user.0.id).await?;
    if active >= MAX_ACTIVE_JOBS_PER_USER {
        return Err(ApiError::TooManyRequests(format!(
            "too many report jobs in flight ({active}); wait for them to finish"
        )));
    }

    let job = repo::reports::create(
        &state.db,
        repo::reports::NewReportJob {
            task_id: &id,
            user_id: &user.0.id,
            format,
            severity_filter: body.severity.as_deref(),
            webhook_url: webhook_url.as_deref(),
            webhook_secret: body.webhook_secret.as_deref(),
        },
    )
    .await?;

    // Retention sweep happens off the hot path but before we hand the id
    // back — the freshly created job is never pruned (it is `waiting`, and
    // only *finished* jobs are eligible).
    let user_id = user.0.id.clone();
    let sweep_state = state.clone();
    tokio::spawn(async move {
        match repo::reports::prune_finished(&sweep_state.db, &user_id, RETAINED_FINISHED_JOBS).await
        {
            Ok(files) => {
                for f in files {
                    let _ = std::fs::remove_file(&f);
                }
            }
            Err(e) => tracing::warn!("report retention sweep failed: {e}"),
        }
    });

    spawn_job(state.clone(), job.clone());
    Ok((StatusCode::ACCEPTED, Json(job_to_json(&job))))
}

#[derive(Deserialize)]
struct ListQuery {
    task_id: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn list_jobs(
    State(state): State<SharedState>,
    user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 100);
    let offset = q.offset.unwrap_or(0).max(0);
    let filters = repo::reports::ReportJobListFilters {
        user_id: if user.is_admin() {
            None
        } else {
            Some(user.0.id.clone())
        },
        task_id: q.task_id,
        limit,
        offset,
    };
    let items = repo::reports::list(&state.db, &filters).await?;
    let total = repo::reports::count(&state.db, &filters).await?;
    Ok(Json(json!({
        "items": items.iter().map(job_to_json).collect::<Vec<_>>(),
        "total": total,
        "limit": limit,
        "offset": offset,
    })))
}

async fn get_job(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let job = load_job_for_user(&state, &user, &id).await?;
    Ok(Json(job_to_json(&job)))
}

async fn download_job(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let job = load_job_for_user(&state, &user, &id).await?;
    if job.status != "finished" {
        return Err(ApiError::BadRequest(format!(
            "report job is {} — only finished jobs can be downloaded",
            job.status
        )));
    }
    let file_path = job
        .file_path
        .clone()
        .ok_or_else(|| ApiError::NotFound(format!("report job {id} has no artifact")))?;

    // Path containment: file_path is server-generated, but a tampered or
    // restored-from-backup row must not turn the download endpoint into an
    // arbitrary file reader.
    let path = PathBuf::from(&file_path);
    let contained = path
        .canonicalize()
        .ok()
        .and_then(|p| {
            state
                .config
                .reports_dir
                .canonicalize()
                .ok()
                .map(|dir| p.starts_with(dir))
        })
        .unwrap_or(false);
    if !contained {
        tracing::error!("report job {id}: artifact path escapes reports dir, refusing");
        return Err(ApiError::NotFound(format!("report job {id}")));
    }

    let bytes = std::fs::read(&path).map_err(|e| {
        tracing::error!("report job {id}: artifact unreadable: {e}");
        ApiError::NotFound(format!("report job {id} artifact is missing"))
    })?;
    // A size mismatch means the file changed under us — serve what exists
    // (it was written atomically), but log for the operator.
    if let Some(expected) = job.file_bytes {
        if expected != bytes.len() as i64 {
            tracing::warn!(
                "report job {id}: size mismatch (db {expected}, disk {})",
                bytes.len()
            );
        }
    }

    // Filename mirrors the task, not the internal job id.
    let task = repo::tasks::get(&state.db, &job.task_id).await.ok();
    let filename = match task {
        Some(t) => reports_render::report_filename(&t, ext_for(&job.format)),
        None => format!(
            "secuscan-report-{}.{}",
            &job.id[..8.min(job.id.len())],
            ext_for(&job.format)
        ),
    };
    let content_type = content_type_for(&job.format);
    Ok(text_response(bytes, content_type, &filename))
}

/// Canonical file extension for a format id ("markdown" normalizes to "md").
fn ext_for(format: &str) -> &str {
    match format {
        "markdown" => "md",
        other => other,
    }
}

async fn delete_job(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let job = load_job_for_user(&state, &user, &id).await?;
    let row = repo::reports::delete(&state.db, &job.id).await?;
    if let Some(row) = row {
        if let Some(path) = &row.file_path {
            let _ = std::fs::remove_file(path);
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn load_job_for_user(
    state: &SharedState,
    user: &CurrentUser,
    id: &str,
) -> ApiResult<secuscan_db::models::ReportJobRow> {
    let job = repo::reports::get(&state.db, id).await?;
    if !user.is_admin() && job.user_id != user.0.id {
        return Err(ApiError::NotFound(format!("report job {id}")));
    }
    Ok(job)
}

/// Accept every known format id plus the historical `markdown` alias,
/// returning the canonical id that is stored in the DB (whose CHECK
/// constraint only knows canonical ids).
fn canonical_format(format: &str) -> ApiResult<&'static str> {
    match format {
        "markdown" => Ok("md"),
        _ => match FORMATS.iter().find(|f| **f == format) {
            Some(f) => Ok(f),
            None => Err(ApiError::BadRequest(format!(
                "unknown report format `{format}` (use {})",
                FORMATS.join("|")
            ))),
        },
    }
}

fn validate_severity(sev: &str) -> ApiResult<()> {
    if SEVERITY_THRESHOLDS.contains(&sev) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "unknown severity filter `{sev}` (use {} or omit for all findings)",
            SEVERITY_THRESHOLDS.join("|")
        )))
    }
}

/// Webhook URLs must be absolute http(s) URLs. This is a scheme guard, not
/// an SSRF egress policy — see SECURITY.md for the threat model (self-hosted
/// instances trust their scanner-role users with outbound calls, exactly as
/// they already trust them with scan targets).
fn validate_webhook_url(url: &str) -> ApiResult<String> {
    if url.len() > 2048 {
        return Err(ApiError::BadRequest(
            "webhook_url exceeds 2048 bytes".into(),
        ));
    }
    match url::Url::parse(url) {
        Ok(u) if u.scheme() == "http" || u.scheme() == "https" => Ok(u.to_string()),
        _ => Err(ApiError::BadRequest(
            "webhook_url must be an absolute http(s) URL".into(),
        )),
    }
}

fn content_type_for(format: &str) -> &'static str {
    match format {
        "json" => "application/json; charset=utf-8",
        "md" | "markdown" => "text/markdown; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "html" => "text/html; charset=utf-8",
        "sarif" => "application/json; charset=utf-8",
        "pdf" => "application/pdf",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        _ => "application/octet-stream",
    }
}

fn text_response(body: Vec<u8>, content_type: &str, filename: &str) -> Response {
    let mut headers = HeaderMap::new();
    if let Ok(v) = header::HeaderValue::from_str(content_type) {
        headers.insert(header::CONTENT_TYPE, v);
    }
    if let Ok(v) = header::HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    (headers, body).into_response()
}
