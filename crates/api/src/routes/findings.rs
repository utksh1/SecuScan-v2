//! Findings explorer + triage.

use crate::access::{require_resource, WorkspacePermission};
use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::routes::workspaces::parse_workspace_scope;
use crate::state::SharedState;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::Json;
use secuscan_core::models::{AnalystStatus, Severity};
use secuscan_db::models::{FindingRow, FpMemoryRow};
use secuscan_db::repo;
use serde::Deserialize;
use serde_json::{json, Value};

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        .route("/findings", axum::routing::get(list).post(create))
        .route("/findings/bulk", axum::routing::patch(bulk_triage))
        .route("/findings/:id", axum::routing::get(get_one))
        .route("/findings/:id/triage", axum::routing::patch(triage))
}

pub fn finding_to_json(f: &FindingRow) -> Value {
    json!({
        "id": f.id,
        "task_id": f.task_id,
        "plugin_id": f.plugin_id,
        "severity": f.severity,
        "kind": f.kind,
        "analyst_status": f.analyst_status,
        "category": f.category,
        "title": f.title,
        "description": f.description,
        "remediation": f.remediation,
        "proof": f.proof,
        "url": f.url,
        "metadata": serde_json::from_str::<Value>(&f.metadata_json).unwrap_or(json!({})),
        "group_id": f.group_id,
        "cve": f.cve,
        "cvss_v3": f.cvss_v3,
        "cvss_vector": f.cvss_vector,
        "epss_score": f.epss_score,
        "epss_percentile": f.epss_percentile,
        "cisa_kev": f.cisa_kev != 0,
        "cwe": f.cwe,
        "owasp": f.owasp,
        "confidence": f.confidence,
        "created_at": f.created_at,
        // Sprint 2.4 (#15) provenance + stable identity
        "plugin_version": f.plugin_version,
        "fingerprint": f.fingerprint,
        // Sprint 2.1 analyst triage surface
        "severity_override": f.severity_override,
        "severity_original": f.severity_original,
        "risk_level": f.risk_level,
        "verified": f.verified.map(|v| v != 0),
        "triage_reason": f.triage_reason,
        "triage_by": f.triage_by,
        "triage_at": f.triage_at,
    })
}

/// Effective severity for display/sorting: analyst override wins.
fn effective_severity<'a>(f: &'a FindingRow) -> &'a str {
    f.severity_override.as_deref().unwrap_or(&f.severity)
}

/// Parsed query string supporting repeated keys (e.g.
/// `?severity=critical&severity=high`). serde_urlencoded rejects duplicate
/// keys for struct fields, so we parse the raw query ourselves.
#[derive(Default)]
struct ListQuery {
    task_id: Option<String>,
    severity: Vec<String>,
    kind: Option<String>,
    analyst_status: Option<String>,
    category: Option<String>,
    search: Option<String>,
    workspace_id: Option<String>,
    limit: i64,
    offset: i64,
    /// Sprint 2.1 keyset cursor (overrides `offset` when present).
    cursor: Option<String>,
}

impl ListQuery {
    fn parse(raw: Option<&str>) -> Self {
        let mut q = ListQuery {
            limit: 100,
            ..Default::default()
        };
        if let Some(raw) = raw {
            for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
                let v = v.to_string();
                match k.as_ref() {
                    "task_id" => q.task_id = Some(v),
                    "severity" => q.severity.push(v),
                    "kind" => q.kind = Some(v),
                    "analyst_status" => q.analyst_status = Some(v),
                    "category" => q.category = Some(v),
                    "search" => q.search = Some(v),
                    "workspace_id" => q.workspace_id = Some(v),
                    "limit" => q.limit = v.parse().unwrap_or(100),
                    "offset" => q.offset = v.parse().unwrap_or(0),
                    "cursor" => q.cursor = Some(v),
                    _ => {}
                }
            }
        }
        q
    }
}

fn validate_enums(q: &ListQuery) -> ApiResult<()> {
    for s in &q.severity {
        if secuscan_core::models::Severity::parse(s).is_none() {
            return Err(ApiError::BadRequest(format!("unknown severity `{s}`")));
        }
    }
    if let Some(k) = &q.kind {
        if secuscan_core::models::FindingKind::parse(k).is_none() {
            return Err(ApiError::BadRequest(format!("unknown kind `{k}`")));
        }
    }
    if let Some(s) = &q.analyst_status {
        if AnalystStatus::parse(s).is_none() {
            return Err(ApiError::BadRequest(format!(
                "unknown analyst_status `{s}`"
            )));
        }
    }
    Ok(())
}

async fn list(
    State(state): State<SharedState>,
    user: CurrentUser,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<Value>> {
    let q = ListQuery::parse(raw.as_deref());
    validate_enums(&q)?;
    let workspace = parse_workspace_scope(&state, &user, q.workspace_id.as_deref()).await?;
    // Access control: non-admins are scoped to their own tasks via the join.
    let filters = repo::findings::FindingFilters {
        task_id: q.task_id,
        user_id: if user.is_admin() {
            None
        } else {
            Some(user.0.id.clone())
        },
        severity: q.severity.clone(),
        kind: q.kind,
        analyst_status: q.analyst_status,
        category: q.category,
        search: q.search,
        workspace,
        limit: q.limit,
        offset: q.offset,
        cursor: q.cursor.as_deref().and_then(repo::findings::decode_cursor),
    };
    let items = repo::findings::list(&state.db, &filters).await?;
    let total = repo::findings::count(&state.db, &filters).await?;
    // Next-page cursor (Sprint 2.1): present only when the page is full —
    // clients keep offset mode working by simply ignoring it.
    let next_cursor = if items.len() as i64 == filters.limit {
        items.last().map(|last| {
            let rank = match last.severity.as_str() {
                "critical" => 0,
                "high" => 1,
                "medium" => 2,
                "low" => 3,
                _ => 4,
            };
            repo::findings::encode_cursor(rank, &last.created_at, &last.id)
        })
    } else {
        None
    };
    Ok(Json(json!({
        "items": items.iter().map(finding_to_json).collect::<Vec<_>>(),
        "total": total,
        "limit": filters.limit,
        "offset": filters.offset,
        "next_cursor": next_cursor,
    })))
}

async fn get_one(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let f = load_finding_for_user(&state, &user, &id).await?;
    let mut body = finding_to_json(&f);
    // Max-Parity Sprint 1.1 — attach the FP-memory audit trail so the UI
    // can show who marked a finding false-positive, when, and why.
    if let Ok(Some(fp)) = fp_memory_for_finding(&state, &f).await {
        body["fp_memory"] = fp_memory_to_json(&state, &fp).await;
    }
    Ok(Json(body))
}

/// Resolve the FP-memory row (if any) matching a finding's
/// (workspace, plugin, title, target-fingerprint) tuple.
async fn fp_memory_for_finding(
    state: &SharedState,
    f: &FindingRow,
) -> ApiResult<Option<FpMemoryRow>> {
    let task = repo::tasks::get(&state.db, &f.task_id).await?;
    let fingerprint =
        repo::finding_dedup::target_fingerprint(f.url.as_deref(), task.target.as_deref());
    Ok(repo::finding_dedup::is_remembered_false_positive(
        &state.db,
        task.workspace_id.as_deref(),
        &f.plugin_id,
        &f.title,
        &fingerprint,
    )
    .await?)
}

/// FP-memory row as JSON, with the deciding user's email resolved for display.
async fn fp_memory_to_json(state: &SharedState, fp: &FpMemoryRow) -> Value {
    let decided_by_email = repo::users::find_by_id(&state.db, &fp.decided_by)
        .await
        .ok()
        .flatten()
        .map(|u| u.email)
        .unwrap_or_else(|| fp.decided_by.clone());
    json!({
        "decided_by": fp.decided_by,
        "decided_by_email": decided_by_email,
        "decided_at": fp.decided_at,
        "reason": fp.reason,
    })
}

pub async fn load_finding_for_user(
    state: &SharedState,
    user: &CurrentUser,
    id: &str,
) -> ApiResult<FindingRow> {
    let f = repo::findings::get(&state.db, id).await?;
    let task = repo::tasks::get(&state.db, &f.task_id).await?;
    require_resource(
        state,
        user,
        task.workspace_id.as_deref(),
        &task.user_id,
        WorkspacePermission::Read,
    )
    .await?;
    Ok(f)
}

#[derive(Deserialize)]
struct TriageRequest {
    /// Optional since Sprint 2.1 — a request may only adjust risk/verified/
    /// severity-override. At least one field must be present.
    #[serde(default)]
    analyst_status: Option<String>,
    /// Optional justification (≤1000 chars), recorded with the acting user
    /// in the triage audit + the FP-memory trail when applicable.
    #[serde(default)]
    reason: Option<String>,
    /// Analyst risk label override (info|low|medium|high|critical).
    #[serde(default)]
    risk_level: Option<String>,
    /// Analyst-verified flag.
    #[serde(default)]
    verified: Option<bool>,
    /// Severity override: "info|low|medium|high|critical", or "" to reset
    /// to the scanner-reported severity.
    #[serde(default)]
    severity_override: Option<String>,
}

const VALID_SEVERITY_LABELS: &[&str] = &["info", "low", "medium", "high", "critical"];

fn validate_override(value: &str) -> ApiResult<()> {
    if value.is_empty() || VALID_SEVERITY_LABELS.contains(&value) {
        return Ok(());
    }
    Err(ApiError::BadRequest(format!(
        "severity_override must be one of {} or an empty string to reset",
        VALID_SEVERITY_LABELS.join("|")
    )))
}

async fn triage(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<TriageRequest>,
) -> ApiResult<Json<Value>> {
    user.require_scanner()?;
    let status = req
        .analyst_status
        .as_deref()
        .map(|s| {
            AnalystStatus::parse(s)
                .ok_or_else(|| ApiError::BadRequest(format!("unknown analyst_status `{s}`")))
        })
        .transpose()?;
    if req.analyst_status.is_none()
        && req.reason.is_none()
        && req.risk_level.is_none()
        && req.verified.is_none()
        && req.severity_override.is_none()
    {
        return Err(ApiError::BadRequest(
            "triage request must set at least one field".into(),
        ));
    }
    if let Some(reason) = &req.reason {
        if reason.chars().count() > 1000 {
            return Err(ApiError::BadRequest("reason must be ≤1000 characters".into()));
        }
    }
    if let Some(v) = &req.severity_override {
        validate_override(v)?;
    }
    if let Some(risk) = &req.risk_level {
        if !VALID_SEVERITY_LABELS.contains(&risk.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "risk_level must be one of {}",
                VALID_SEVERITY_LABELS.join("|")
            )));
        }
    }
    let finding = load_finding_for_user(&state, &user, &id).await?;
    let task = repo::tasks::get(&state.db, &finding.task_id).await?;
    require_resource(
        &state,
        &user,
        task.workspace_id.as_deref(),
        &task.user_id,
        WorkspacePermission::Write,
    )
    .await?;
    let fingerprint =
        repo::finding_dedup::target_fingerprint(finding.url.as_deref(), task.target.as_deref());

    // 1) Propagate the new status to every duplicate in the same dedup
    // group, so re-scan copies inherit the analyst's decision.
    if let Some(group_id) = finding.group_id.as_deref().filter(|g| !g.is_empty()) {
        if let Some(st) = status {
            match repo::finding_dedup::propagate_status_to_group(&state.db, group_id, st.label())
                .await
            {
                Ok(n) if n > 1 => {
                    tracing::info!(
                        "triage: propagated `{}` to {n} findings in group {group_id}",
                        st.label()
                    )
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("triage: group propagation failed: {e}"),
            }
        }
    }

    // 2) Maintain FP memory: marking false_positive remembers the tuple
    // (future scans auto-suppress it); any other status forgets it so the
    // finding reports fresh on the next scan.
    let mut remembered: Option<FpMemoryRow> = None;
    match status {
        Some(AnalystStatus::FalsePositive) => {
            remembered = Some(
                repo::finding_dedup::remember_false_positive(
                    &state.db,
                    task.workspace_id.as_deref(),
                    &finding.plugin_id,
                    &finding.title,
                    &fingerprint,
                    &user.0.id,
                    req.reason.as_deref(),
                )
                .await?,
            );
        }
        Some(_) => {
            repo::finding_dedup::forget_false_positive(
                &state.db,
                task.workspace_id.as_deref(),
                &finding.plugin_id,
                &finding.title,
                &fingerprint,
            )
            .await?;
        }
        None => {}
    }

    let updated = repo::findings::update_triage(
        &state.db,
        &id,
        status,
        req.severity_override.as_deref().map(|v| Some(v)),
        req.risk_level.as_deref(),
        req.verified,
        req.reason.as_deref(),
        &user.0.id,
    )
    .await?;
    let mut body = finding_to_json(&updated);
    if let Some(fp) = &remembered {
        body["fp_memory"] = fp_memory_to_json(&state, fp).await;
    }
    Ok(Json(body))
}

// --- Sprint 2.1: bulk triage ------------------------------------------------

#[derive(Deserialize)]
struct BulkTriageRequest {
    ids: Vec<String>,
    #[serde(default)]
    analyst_status: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

async fn bulk_triage(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<BulkTriageRequest>,
) -> ApiResult<Json<Value>> {
    user.require_scanner()?;
    if req.ids.is_empty() || req.ids.len() > 1000 {
        return Err(ApiError::BadRequest("ids must contain 1..=1000 findings".into()));
    }
    let status = req
        .analyst_status
        .as_deref()
        .map(|s| {
            AnalystStatus::parse(s)
                .ok_or_else(|| ApiError::BadRequest(format!("unknown analyst_status `{s}`")))
        })
        .transpose()?
        .ok_or_else(|| ApiError::BadRequest("analyst_status is required for bulk triage".into()))?;
    if let Some(reason) = &req.reason {
        if reason.chars().count() > 1000 {
            return Err(ApiError::BadRequest("reason must be ≤1000 characters".into()));
        }
    }
    // Authorization: every finding's task workspace must be writable. Batch
    // by distinct task to avoid N× task loads for group-heavy selections.
    let mut seen_tasks: std::collections::BTreeMap<String, ()> = Default::default();
    let mut loaded: Vec<(String, String)> = Vec::with_capacity(req.ids.len()); // (id, task_id)
    for fid in &req.ids {
        let f = repo::findings::get(&state.db, fid).await?;
        if seen_tasks.insert(f.task_id.clone(), ()).is_none() {
            let t = repo::tasks::get(&state.db, &f.task_id).await?;
            require_resource(
                &state,
                &user,
                t.workspace_id.as_deref(),
                &t.user_id,
                WorkspacePermission::Write,
            )
            .await?;
        }
        loaded.push((f.id, f.task_id));
    }

    let updated = repo::findings::bulk_update_status(
        &state.db,
        &req.ids,
        status,
        &user.0.id,
        req.reason.as_deref(),
    )
    .await?;

    // Propagate to dedup groups (same contract as single triage) + FP memory
    // for false_positive (remember each unique tuple once).
    if status == AnalystStatus::FalsePositive {
        let mut remembered_tuples: std::collections::BTreeSet<String> = Default::default();
        for (fid, task_id) in &loaded {
            let f = repo::findings::get(&state.db, fid).await.ok();
            if let Some(f) = f {
                let t = match repo::tasks::get(&state.db, task_id).await {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                let fingerprint = repo::finding_dedup::target_fingerprint(
                    f.url.as_deref(),
                    t.target.as_deref(),
                );
                let key = format!(
                    "{}|{}|{}|{}",
                    t.workspace_id.as_deref().unwrap_or(""),
                    f.plugin_id,
                    f.title,
                    fingerprint
                );
                if remembered_tuples.insert(key) {
                    let _ = repo::finding_dedup::remember_false_positive(
                        &state.db,
                        t.workspace_id.as_deref(),
                        &f.plugin_id,
                        &f.title,
                        &fingerprint,
                        &user.0.id,
                        req.reason.as_deref(),
                    )
                    .await;
                }
            }
        }
    }
    // Group propagation for distinct group ids.
    let mut groups: std::collections::BTreeSet<String> = Default::default();
    for (fid, _) in &loaded {
        if let Ok(f) = repo::findings::get(&state.db, fid).await {
            if let Some(g) = f.group_id.as_deref().filter(|g| !g.is_empty()) {
                groups.insert(g.to_string());
            }
        }
    }
    for g in &groups {
        let _ = repo::finding_dedup::propagate_status_to_group(&state.db, g, status.label()).await;
    }

    Ok(Json(json!({ "updated": updated })))
}

// --- Sprint 2.1: manual finding creation -------------------------------------

#[derive(Deserialize)]
struct CreateFindingRequest {
    /// Findings anchor to a task (report grouping, workspace auth).
    task_id: String,
    title: String,
    #[serde(default)]
    category: Option<String>,
    severity: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    remediation: Option<String>,
    #[serde(default)]
    proof: Option<String>,
    #[serde(default)]
    url: Option<String>,
    /// Pre-fill from a finding template's title/description/remediation.
    #[serde(default)]
    from_template: Option<String>,
}

async fn create(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<CreateFindingRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    let task = repo::tasks::get(&state.db, &req.task_id).await?;
    require_resource(
        &state,
        &user,
        task.workspace_id.as_deref(),
        &task.user_id,
        WorkspacePermission::Write,
    )
    .await?;
    let title = req.title.trim();
    if title.is_empty() || title.len() > 300 {
        return Err(ApiError::BadRequest("title must be 1..=300 characters".into()));
    }
    let severity = Severity::parse(&req.severity)
        .ok_or_else(|| ApiError::BadRequest(format!("unknown severity `{}`", req.severity)))?;

    let (title, description, remediation) = if let Some(tid) = &req.from_template {
        let tpl = repo::v300_misc::get_finding_template(&state.db, tid).await?;
        (
            tpl.title.clone(),
            Some(tpl.description.clone()),
            Some(tpl.remediation.clone()),
        )
    } else {
        (title.to_string(), req.description.clone(), req.remediation.clone())
    };

    let finding = secuscan_core::models::Finding {
        title,
        category: req.category.unwrap_or_else(|| "Manual Finding".into()),
        severity,
        kind: secuscan_core::models::FindingKind::Observation,
        description: description.unwrap_or_default(),
        remediation: remediation.unwrap_or_default(),
        proof: req.proof.unwrap_or_default(),
        url: req.url.clone(),
        metadata: json!({
            "manual": true,
            "created_by": user.0.id,
        }),
        confidence: None,
        ..Default::default()
    };
    let ids = repo::findings::insert_many(&state.db, &req.task_id, "manual", &[finding]).await?;
    let created = repo::findings::get(&state.db, &ids[0]).await?;
    Ok((StatusCode::CREATED, Json(finding_to_json(&created))))
}
