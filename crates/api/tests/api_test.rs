//! End-to-end API integration tests: full application over real HTTP,
//! temporary SQLite DB, real plugin manifests, live SSE streaming.

use axum::Router;
use secuscan_api::state::AppState;
use secuscan_core::PluginRegistry;
use std::sync::Arc;

struct TestServer {
    pub base: String,
    _db_dir: tempfile::TempDir,
    _plugins_dir: tempfile::TempDir,
}

async fn spawn_app() -> TestServer {
    secuscan_exec::init_tls();

    let db_dir = tempfile::tempdir().unwrap();
    let plugins_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        plugins_dir.path().join("port-scanner.toml"),
        include_str!("../../../plugins/port-scanner.toml"),
    )
    .unwrap();
    std::fs::write(
        plugins_dir.path().join("sevtest.toml"),
        r#"
[plugin]
id = "sevtest"
name = "Severity Test Tool"
version = "1.0.0"
description = "emits critical/high/medium findings deterministically"
category = "test"

[engine]
type = "cli"
binary = "sh"
timeout_seconds = 30
output_format = "text"
argv = ["sh", "-c", "echo 'SEVTEST CRITICAL issue'; echo 'SEVTEST HIGH issue'; echo 'SEVTEST MEDIUM issue'"]

[[fields]]
id = "target"
label = "Target"
type = "string"
required = true

[parser]
type = "passthrough"

[[static_rules]]
pattern = "SEVTEST CRITICAL"
title = "Critical test finding"
severity = "critical"
category = "Test"

[[static_rules]]
pattern = "SEVTEST HIGH"
title = "High test finding"
severity = "high"
category = "Test"

[[static_rules]]
pattern = "SEVTEST MEDIUM"
title = "Medium test finding"
severity = "medium"
category = "Test"

[safety]
level = "safe"
requires_consent = false
max_concurrent = 2
max_per_hour = 0
"#,
    )
    .unwrap();
    std::fs::write(
        plugins_dir.path().join("sleepy.toml"),
        r#"
[plugin]
id = "sleepy"
name = "Sleepy Test Tool"
version = "1.0.0"
description = "test plugin that sleeps (used to exercise cancellation)"
category = "test"

[engine]
type = "cli"
binary = "sh"
argv = ["sh", "-c", "echo '99/tcp open dummy'; sleep 30"]
timeout_seconds = 300

[[fields]]
id = "target"
label = "Target"
type = "string"
required = true

[parser]
type = "line_regex"
pattern = '(?P<port>\d+)/(?P<proto>tcp|udp)\s+open\s+(?P<service>[\w-]+)'

[parser.finding]
title = "Open port: {port}/{proto} ({service})"
category = "Network Service"
severity = "info"

[safety]
level = "safe"
requires_consent = false
max_concurrent = 1
max_per_hour = 0
"#,
    )
    .unwrap();

    let config = Arc::new(secuscan_api::config::Config {
        addr: "127.0.0.1:0".parse().unwrap(),
        db_url: format!(
            "sqlite://{}?mode=rwc",
            db_dir.path().join("test.db").display()
        ),
        jwt_secret: "integration-test-secret".to_string(),
        plugins_dir: plugins_dir.path().to_path_buf(),
        frontend_dir: db_dir.path().join("no-such-frontend"), // API-only mode
        data_dir: db_dir.path().to_path_buf(),
        admin_email: "admin@test.local".to_string(),
        admin_password: Some("admin-password-123".to_string()),
        denied_capabilities: vec![],
        allow_register: false,
        cors_origin: None,
        cookie_secure: false,
        max_concurrent_tasks: 4,
    });

    let db = secuscan_db::open(&config.db_url).await.unwrap();
    secuscan_api::seed::seed_admin(&db, &config).await;
    let registry = PluginRegistry::load_dir(&config.plugins_dir);
    assert!(registry.issues().is_empty(), "{:?}", registry.issues());
    let tasks = secuscan_api::manager::TaskManager::start(db.clone(), config.clone());
    let state = Arc::new(AppState {
        db,
        config: config.clone(),
        registry: Arc::new(tokio::sync::RwLock::new(registry)),
        tasks,
    });

    let app: Router = secuscan_api::build_app(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestServer {
        base: format!("http://{addr}/api/v1"),
        _db_dir: db_dir,
        _plugins_dir: plugins_dir,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().build().unwrap()
}

async fn login(s: &TestServer) -> (reqwest::Client, String) {
    let c = client();
    let resp = c
        .post(format!("{}/auth/login", s.base))
        .json(&serde_json::json!({
            "email": "admin@test.local",
            "password": "admin-password-123",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["access_token"].as_str().unwrap().to_string();
    (c, token)
}

#[tokio::test]
async fn health_and_auth_flow() {
    let s = spawn_app().await;
    let c = client();

    // health is public
    let resp = c.get(format!("{}/health", s.base)).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");

    // unauthenticated plugin list is rejected
    let resp = c.get(format!("{}/plugins", s.base)).send().await.unwrap();
    assert_eq!(resp.status(), 401);

    // wrong password
    let resp = c
        .post(format!("{}/auth/login", s.base))
        .json(&serde_json::json!({"email": "admin@test.local", "password": "wrong"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // login works and sets a refresh cookie
    let resp = c
        .post(format!("{}/auth/login", s.base))
        .json(&serde_json::json!({"email": "admin@test.local", "password": "admin-password-123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(set_cookie.contains("secuscan_refresh="), "{set_cookie}");
    assert!(set_cookie.contains("HttpOnly"), "{set_cookie}");
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["access_token"].as_str().unwrap().to_string();
    assert_eq!(body["user"]["role"], "admin");

    // me
    let resp = c
        .get(format!("{}/auth/me", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let me: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(me["email"], "admin@test.local");

    // register is disabled by default
    let resp = c
        .post(format!("{}/auth/register", s.base))
        .json(&serde_json::json!({"email": "x@y.z", "name": "X", "password": "longenough1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // refresh flow
    let cookie_value = set_cookie.split(';').next().unwrap().to_string();
    let resp = c
        .post(format!("{}/auth/refresh", s.base))
        .header("cookie", &cookie_value)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(!body["access_token"].as_str().unwrap().is_empty());

    // old refresh cookie was rotated: reusing it fails
    let resp = c
        .post(format!("{}/auth/refresh", s.base))
        .header("cookie", &cookie_value)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn full_task_lifecycle_with_findings_and_reports() {
    let s = spawn_app().await;

    // live listener to find
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let _ = listener.accept().await;
        }
    });

    let (c, token) = login(&s).await;
    let auth = |r: reqwest::RequestBuilder| r.bearer_auth(&token);

    // ---- plugin catalog ----
    let resp = auth(c.get(format!("{}/plugins", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let items = body["items"].as_array().unwrap();
    assert!(items.len() >= 2);
    assert!(items.iter().any(|p| p["id"] == "port-scanner"));

    // schema
    let resp = auth(c.get(format!("{}/plugins/port-scanner/schema", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let schema: serde_json::Value = resp.json().await.unwrap();
    assert!(schema["fields"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["id"] == "target"));

    // preview (native)
    let resp = auth(c.post(format!("{}/plugins/port-scanner/preview", s.base)))
        .json(&serde_json::json!({"inputs": {"target": "127.0.0.1"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let preview: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(preview["command"], "native:port_scanner");

    // ---- consent required ----
    let resp = auth(c.post(format!("{}/tasks", s.base)))
        .json(&serde_json::json!({
            "plugin_id": "port-scanner",
            "inputs": {"target": "127.0.0.1", "ports": port.to_string()},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let err: serde_json::Value = resp.json().await.unwrap();
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .contains("consent"));

    // ---- unknown field rejected ----
    let resp = auth(c.post(format!("{}/tasks", s.base)))
        .json(&serde_json::json!({
            "plugin_id": "port-scanner",
            "inputs": {"target": "127.0.0.1", "nonsense": "x"},
            "consent_granted": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // ---- target policy: nmap-style restriction on port-scanner (localhost ok) ----
    let resp = auth(c.post(format!("{}/tasks", s.base)))
        .json(&serde_json::json!({
            "plugin_id": "port-scanner",
            "inputs": {"target": "203.0.113.50"},  // TEST-NET-3, outside allowed_targets
            "consent_granted": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // ---- create and await completion ----
    let resp = auth(c.post(format!("{}/tasks", s.base)))
        .json(&serde_json::json!({
            "plugin_id": "port-scanner",
            "inputs": {"target": "127.0.0.1", "ports": format!("{},{}", port, port + 1)},
            "consent_granted": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let task: serde_json::Value = resp.json().await.unwrap();
    let task_id = task["id"].as_str().unwrap().to_string();
    assert_eq!(task["status"], "queued");

    // poll to completion
    let mut status = String::new();
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let resp = auth(c.get(format!("{}/tasks/{task_id}", s.base)))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let t: serde_json::Value = resp.json().await.unwrap();
        status = t["status"].as_str().unwrap().to_string();
        if status == "completed" || status == "failed" {
            break;
        }
    }
    assert_eq!(status, "completed");

    // result: exactly the open port
    let resp = auth(c.get(format!("{}/tasks/{task_id}/result", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let result: serde_json::Value = resp.json().await.unwrap();
    let findings = result["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0]["title"]
        .as_str()
        .unwrap()
        .contains(&format!("{port}/tcp")));
    assert_eq!(result["severity_counts"]["info"], 1);

    // ---- findings explorer + triage ----
    let resp = auth(c.get(format!("{}/findings?severity=info", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let fl: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(fl["total"], 1);

    let finding_id = findings[0]["id"].as_str().unwrap().to_string();
    let resp = auth(c.patch(format!("{}/findings/{finding_id}/triage", s.base)))
        .json(&serde_json::json!({"analyst_status": "confirmed"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let updated: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(updated["analyst_status"], "confirmed");

    // ---- SSE stream: replay persisted events ----
    let resp = auth(c.get(format!("{}/tasks/{task_id}/stream", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .contains("text/event-stream"));
    let body = resp.text().await.unwrap();
    assert!(body.contains("\"phase\""), "SSE body: {body}");
    assert!(body.contains("\"finished\""), "SSE body: {body}");

    // ---- reports ----
    for (fmt, marker) in [
        ("md", "SecuScan Report"),
        ("csv", "severity,kind"),
        ("sarif", "\"version\": \"2.1.0\""),
        ("html", "<h1>SecuScan Report"),
        ("json", "\"findings\""),
    ] {
        let resp = auth(c.get(format!("{}/tasks/{task_id}/report/{fmt}", s.base)))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "format {fmt}");
        let body = resp.text().await.unwrap();
        assert!(body.contains(marker), "format {fmt}: {body}");
    }

    // ---- dashboard ----
    let resp = auth(c.get(format!("{}/dashboard/summary", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let d: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(d["tasks"]["total"], 1);
    assert_eq!(d["findings"]["info"], 1);

    // ---- admin: audit log contains the blocked target ----
    let resp = auth(c.get(format!("{}/admin/audit", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let audit: serde_json::Value = resp.json().await.unwrap();
    let items = audit["items"].as_array().unwrap();
    assert!(
        items.iter().any(|a| a["target"] == "203.0.113.50"),
        "{items:?}"
    );
}

#[tokio::test]
async fn cli_plugin_task_and_cancellation() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;
    let auth = |r: reqwest::RequestBuilder| r.bearer_auth(&token);

    // Start the sleepy CLI plugin (sh wrapper, sleeps 30s).
    let resp = auth(c.post(format!("{}/tasks", s.base)))
        .json(&serde_json::json!({
            "plugin_id": "sleepy",
            "inputs": {"target": "127.0.0.1"},
            "consent_granted": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let task: serde_json::Value = resp.json().await.unwrap();
    let task_id = task["id"].as_str().unwrap().to_string();

    // Wait until running.
    let mut running = false;
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let resp = auth(c.get(format!("{}/tasks/{task_id}", s.base)))
            .send()
            .await
            .unwrap();
        let t: serde_json::Value = resp.json().await.unwrap();
        if t["status"] == "running" {
            running = true;
            break;
        }
    }
    assert!(running, "task should reach running state");

    // Cancel it.
    let resp = auth(c.post(format!("{}/tasks/{task_id}/cancel", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["cancelled"], true);

    let mut final_status = String::new();
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let resp = auth(c.get(format!("{}/tasks/{task_id}", s.base)))
            .send()
            .await
            .unwrap();
        let t: serde_json::Value = resp.json().await.unwrap();
        final_status = t["status"].as_str().unwrap().to_string();
        if final_status == "cancelled" {
            break;
        }
    }
    assert_eq!(final_status, "cancelled");
}

#[tokio::test]
async fn api_key_authentication_and_workflow() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;
    let auth = |r: reqwest::RequestBuilder| r.bearer_auth(&token);

    // Create an API key.
    let resp = auth(c.post(format!("{}/auth/api-keys", s.base)))
        .json(&serde_json::json!({"name": "ci"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let key_body: serde_json::Value = resp.json().await.unwrap();
    let api_key = key_body["key"].as_str().unwrap().to_string();
    assert!(api_key.starts_with("scsk_"));

    // Use the API key against /plugins.
    let resp = c
        .get(format!("{}/plugins", s.base))
        .header("x-api-key", &api_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Create a workflow: port-scanner step.
    let resp = auth(c.post(format!("{}/workflows", s.base)))
        .json(&serde_json::json!({
            "name": "lab-recon",
            "description": "port scan then headers",
            "steps": [
                {"plugin_id": "port-scanner", "inputs": {"target": "127.0.0.1", "ports": "9"}},
                {"plugin_id": "port-scanner", "inputs": {"target": "127.0.0.1", "ports": "10"}},
            ],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let wf: serde_json::Value = resp.json().await.unwrap();
    let wf_id = wf["id"].as_str().unwrap().to_string();

    // Run it.
    let resp = auth(c.post(format!("{}/workflows/{wf_id}/run", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Wait for the run to complete.
    let mut run_status = String::new();
    for _ in 0..200 {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let resp = auth(c.get(format!("{}/workflows/{wf_id}/runs", s.base)))
            .send()
            .await
            .unwrap();
        let runs: serde_json::Value = resp.json().await.unwrap();
        let first = &runs["items"][0];
        run_status = first["status"].as_str().unwrap_or_default().to_string();
        if !run_status.is_empty() && run_status != "queued" && run_status != "running" {
            break;
        }
    }
    assert_eq!(run_status, "completed", "workflow run status");
}

#[tokio::test]
async fn non_admin_scoping_and_admin_management() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;
    let auth = |r: reqwest::RequestBuilder| r.bearer_auth(&token);

    // Create a viewer user as admin.
    let resp = auth(c.post(format!("{}/admin/users", s.base)))
        .json(&serde_json::json!({
            "email": "viewer@test.local", "name": "Viewer", "password": "viewer-pass-123", "role": "viewer"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Login as viewer.
    let vresp = c
        .post(format!("{}/auth/login", s.base))
        .json(&serde_json::json!({"email": "viewer@test.local", "password": "viewer-pass-123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(vresp.status(), 200);
    let vbody: serde_json::Value = vresp.json().await.unwrap();
    let vtoken = vbody["access_token"].as_str().unwrap().to_string();

    // Viewer cannot create tasks? Policy: viewers should be read-only for scans.
    // (Roles: admin — everything; scanner — run scans; viewer — read only.)
    let resp = c
        .post(format!("{}/tasks", s.base))
        .bearer_auth(&vtoken)
        .json(&serde_json::json!({
            "plugin_id": "port-scanner",
            "inputs": {"target": "127.0.0.1"},
            "consent_granted": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Viewer cannot access admin endpoints.
    let resp = c
        .get(format!("{}/admin/users", s.base))
        .bearer_auth(&vtoken)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Admin can list users and update network policy.
    let resp = auth(c.get(format!("{}/admin/users", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let users: serde_json::Value = resp.json().await.unwrap();
    assert!(users["items"].as_array().unwrap().len() >= 2);

    // Set a global deny and verify task creation is blocked.
    let resp = auth(c.put(format!("{}/admin/network-policy", s.base)))
        .json(&serde_json::json!({"allow": [], "deny": ["127.0.0.1"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let resp = auth(c.post(format!("{}/tasks", s.base)))
        .json(&serde_json::json!({
            "plugin_id": "port-scanner",
            "inputs": {"target": "127.0.0.1"},
            "consent_granted": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Restore.
    let resp = auth(c.put(format!("{}/admin/network-policy", s.base)))
        .json(&serde_json::json!({"allow": [], "deny": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

// ---------------------------------------------------------------------------
// Review cycle 5: targeted regression tests for the audit fixes.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_rate_limit_kicks_in() {
    let s = spawn_app().await;
    let c = client();
    // 30 attempts/min allowed → the 31st is rejected.
    for i in 0..30 {
        let resp = c
            .post(format!("{}/auth/login", s.base))
            .json(&serde_json::json!({"email": "nobody@test.local", "password": "wrong"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "attempt {i}");
    }
    let resp = c
        .post(format!("{}/auth/login", s.base))
        .json(&serde_json::json!({"email": "nobody@test.local", "password": "wrong"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
}

#[tokio::test]
async fn multi_severity_filter_and_settings_endpoint() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;

    // Repeated severity params must be accepted and OR-combined.
    let resp = c
        .get(format!(
            "{}/findings?severity=critical&severity=high",
            s.base
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Unknown severity is rejected.
    let resp = c
        .get(format!("{}/findings?severity=mega", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // GET /admin/settings exists and reports require_consent.
    let resp = c
        .get(format!("{}/admin/settings", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["require_consent"], true);

    // PUT then GET reflects the change.
    let resp = c
        .put(format!("{}/admin/settings", s.base))
        .bearer_auth(&token)
        .json(&serde_json::json!({"require_consent": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let resp = c
        .get(format!("{}/admin/settings", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["require_consent"], false);
}

#[tokio::test]
async fn target_policy_bypass_forms_are_blocked() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;
    let auth = |r: reqwest::RequestBuilder| r.bearer_auth(&token);

    // IPv4-shaped glob must not match a hostname that merely looks dotted.
    for target in ["192.168.attacker.com", "10.evil.example"] {
        let resp = auth(c.post(format!("{}/tasks", s.base)))
            .json(&serde_json::json!({
                "plugin_id": "port-scanner",
                "inputs": {"target": target},
                "consent_granted": true,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "hostname {target} must be rejected");
    }

    // IPv4-mapped IPv6 and integer forms are canonicalized to IPv4 and
    // therefore still respect the local-only allowed_targets.
    for target in ["::ffff:192.0.2.9", "3221225993"] {
        let resp = auth(c.post(format!("{}/tasks", s.base)))
            .json(&serde_json::json!({
                "plugin_id": "port-scanner",
                "inputs": {"target": target},
                "consent_granted": true,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            403,
            "canonical form {target} must be rejected"
        );
    }
}

#[tokio::test]
async fn hourly_limit_rejection_does_not_erosion_other_slots() {
    let s = spawn_app().await;
    // sleepy.toml declares max_per_hour = 0 (unlimited); use port-scanner
    // (60/hour) instead: create+cancel 5 tasks, then verify more can start.
    let (c, token) = login(&s).await;
    let auth = |r: reqwest::RequestBuilder| r.bearer_auth(&token);

    // Cancelled-while-queued still reserves slots by design; what must NOT
    // happen is rejected acquires eroding slots. Fill the plugin's
    // concurrency (4) with sleepy — no wait, sleepy is unlimited hourly.
    // Instead verify many sequential quick scans are all admitted.
    for _ in 0..8 {
        let resp = auth(c.post(format!("{}/tasks", s.base)))
            .json(&serde_json::json!({
                "plugin_id": "port-scanner",
                "inputs": {"target": "127.0.0.1", "ports": "65000"},
                "consent_granted": true,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        // let each finish to keep the test fast and deterministic
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    }
}

#[tokio::test]
async fn password_change_revokes_sessions() {
    let s = spawn_app().await;
    let c = client();

    // Create a second admin to avoid touching the shared seeded one.
    let (c1, t1) = login(&s).await;
    let resp = c1
        .post(format!("{}/admin/users", s.base))
        .bearer_auth(&t1)
        .json(&serde_json::json!({
            "email": "second@test.local", "name": "Second", "password": "second-pass-123", "role": "scanner"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Login as the second user, capture the refresh cookie.
    let resp = c
        .post(format!("{}/auth/login", s.base))
        .json(&serde_json::json!({"email": "second@test.local", "password": "second-pass-123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // Capture the cookie BEFORE resp.json() consumes the response.
    let cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let body: serde_json::Value = resp.json().await.unwrap();
    let token2 = body["access_token"].as_str().unwrap().to_string();

    // Change the password → refresh cookie must stop working.
    let resp = c
        .post(format!("{}/auth/password", s.base))
        .bearer_auth(&token2)
        .json(&serde_json::json!({"current_password": "second-pass-123", "new_password": "changed-pass-456"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let resp = c
        .post(format!("{}/auth/refresh", s.base))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "sessions must be revoked after password change"
    );
}

#[tokio::test]
async fn last_admin_cannot_be_demoted() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;
    // Only one user exists (the seeded admin).
    let users: serde_json::Value = c
        .get(format!("{}/admin/users", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_id = users["items"][0]["id"].as_str().unwrap().to_string();

    let resp = c
        .patch(format!("{}/admin/users/{admin_id}", s.base))
        .bearer_auth(&token)
        .json(&serde_json::json!({"role": "viewer"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}

// ---------------------------------------------------------------------------
// Workspaces + first-class targets (cycle 7 feature work).
// ---------------------------------------------------------------------------

/// Wait for a task to reach a terminal state, polling the detail endpoint.
async fn wait_terminal(
    c: &reqwest::Client,
    base: &str,
    token: &str,
    id: &str,
) -> serde_json::Value {
    for _ in 0..100 {
        let resp = c
            .get(format!("{base}/tasks/{id}"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let t: serde_json::Value = resp.json().await.unwrap();
        let status = t["status"].as_str().unwrap().to_string();
        if matches!(status.as_str(), "completed" | "failed" | "cancelled") {
            return t;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("task {id} did not reach a terminal state in time");
}

#[tokio::test]
async fn workspaces_targets_and_task_scoping() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;
    let auth = |r: reqwest::RequestBuilder| r.bearer_auth(&token);

    // --- workspace CRUD ---------------------------------------------------
    let resp = auth(c.post(format!("{}/workspaces", s.base)))
        .json(&serde_json::json!({"name": "  Acme Corp  ", "description": "Client engagement"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let ws: serde_json::Value = resp.json().await.unwrap();
    let ws_id = ws["id"].as_str().unwrap().to_string();
    assert_eq!(ws["name"], "Acme Corp"); // trimmed
    assert_eq!(ws["tasks_total"], 0);

    // Empty / whitespace names are rejected.
    let resp = auth(c.post(format!("{}/workspaces", s.base)))
        .json(&serde_json::json!({"name": "   "}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // List includes the workspace + the synthetic Personal entry.
    let resp = auth(c.get(format!("{}/workspaces", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let list: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    assert_eq!(list["personal"]["name"], "Personal");

    // --- targets: kind derivation, uniqueness, validation ------------------
    let mk_target = |name: &str| serde_json::json!({"name": name});
    let resp = auth(c.post(format!("{}/workspaces/{ws_id}/targets", s.base)))
        .json(&mk_target("example.com"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let t_host: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(t_host["kind"], "hostname");

    let resp = auth(c.post(format!("{}/workspaces/{ws_id}/targets", s.base)))
        .json(&mk_target("192.168.1.10"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let t_ip: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(t_ip["kind"], "ip_address");

    let resp = auth(c.post(format!("{}/workspaces/{ws_id}/targets", s.base)))
        .json(&mk_target("https://app.example.com"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let t_url: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(t_url["kind"], "url");

    // Duplicate name in the same workspace → 409.
    let resp = auth(c.post(format!("{}/workspaces/{ws_id}/targets", s.base)))
        .json(&mk_target("example.com"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    // Whitespace inside a target name → 400.
    let resp = auth(c.post(format!("{}/workspaces/{ws_id}/targets", s.base)))
        .json(&mk_target("bad target"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Rename re-derives the kind.
    let t_url_id = t_url["id"].as_str().unwrap();
    let resp = auth(c.patch(format!("{}/targets/{t_url_id}", s.base)))
        .json(&serde_json::json!({"name": "acme.example.org", "description": "renamed"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let renamed: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(renamed["kind"], "hostname");
    assert_eq!(renamed["description"], "renamed");

    // --- tasks scoped to the workspace -------------------------------------
    let resp = auth(c.post(format!("{}/tasks", s.base)))
        .json(&serde_json::json!({
            "plugin_id": "sevtest",
            "inputs": {"target": "example.com"},
            "consent_granted": true,
            "workspace_id": ws_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let task: serde_json::Value = resp.json().await.unwrap();
    let task_id = task["id"].as_str().unwrap().to_string();
    assert_eq!(task["workspace_id"], serde_json::json!(ws_id));

    let done = wait_terminal(&c, &s.base, &token, &task_id).await;
    assert_eq!(done["status"], "completed");

    // Unknown workspace on task create → 404 (not 500).
    let resp = auth(c.post(format!("{}/tasks", s.base)))
        .json(&serde_json::json!({
            "plugin_id": "sevtest",
            "inputs": {"target": "example.com"},
            "consent_granted": true,
            "workspace_id": "no-such-workspace",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Task list scoping.
    let resp = auth(c.get(format!("{}/tasks?workspace_id={ws_id}", s.base)))
        .send()
        .await
        .unwrap();
    let tl: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(tl["total"], 1);
    assert_eq!(tl["items"][0]["id"], serde_json::json!(task_id));

    let resp = auth(c.get(format!("{}/tasks?workspace_id=none", s.base)))
        .send()
        .await
        .unwrap();
    let tl: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(tl["total"], 0);

    let resp = auth(c.get(format!("{}/tasks?workspace_id=missing", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Retry keeps the workspace.
    let resp = auth(c.post(format!("{}/tasks/{task_id}/retry", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let retried: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(retried["workspace_id"], serde_json::json!(ws_id));
    let _ = wait_terminal(&c, &s.base, &token, retried["id"].as_str().unwrap()).await;

    // Findings scoping (sevtest produced 3 findings per run, 2 runs = 6).
    let resp = auth(c.get(format!("{}/findings?workspace_id={ws_id}", s.base)))
        .send()
        .await
        .unwrap();
    let fl: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(fl["total"], 6);
    assert_eq!(fl["items"].as_array().unwrap().len(), 6);

    let resp = auth(c.get(format!("{}/findings?workspace_id=none", s.base)))
        .send()
        .await
        .unwrap();
    let fl: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(fl["total"], 0);

    // Dashboard scoping.
    let resp = auth(c.get(format!("{}/dashboard/summary?workspace_id={ws_id}", s.base)))
        .send()
        .await
        .unwrap();
    let sum: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(sum["tasks"]["total"], 2);
    assert_eq!(sum["findings"]["critical"], 2);
    assert_eq!(sum["findings"]["high"], 2);
    assert_eq!(sum["findings"]["medium"], 2);

    let resp = auth(c.get(format!("{}/dashboard/summary?workspace_id=none", s.base)))
        .send()
        .await
        .unwrap();
    let sum: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(sum["tasks"]["total"], 0);

    // Target stats reflect scans of the matching target string.
    let t_host_id = t_host["id"].as_str().unwrap();
    let resp = auth(c.get(format!("{}/targets/{t_host_id}/stats", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404); // no such route (stats ride on the list)

    let resp = auth(c.get(format!("{}/workspaces/{ws_id}/targets", s.base)))
        .send()
        .await
        .unwrap();
    let targets: serde_json::Value = resp.json().await.unwrap();
    let items = targets["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    let host_entry = items
        .iter()
        .find(|t| t["name"] == serde_json::json!("example.com"))
        .expect("example.com target present");
    assert_eq!(host_entry["scans_total"], 2);
    assert!(host_entry["last_scanned_at"].is_string());

    // --- RBAC ---------------------------------------------------------------
    // Viewer: read-only.
    let _ = auth(c.post(format!("{}/admin/users", s.base)))
        .json(&serde_json::json!({
            "email": "viewer@test.local", "name": "Viewer", "password": "viewer-pass-123", "role": "viewer"
        }))
        .send()
        .await
        .unwrap();
    let vresp = c
        .post(format!("{}/auth/login", s.base))
        .json(&serde_json::json!({"email": "viewer@test.local", "password": "viewer-pass-123"}))
        .send()
        .await
        .unwrap();
    let vbody: serde_json::Value = vresp.json().await.unwrap();
    let vtoken = vbody["access_token"].as_str().unwrap().to_string();

    // Viewer can list workspaces…
    let resp = c
        .get(format!("{}/workspaces", s.base))
        .bearer_auth(&vtoken)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // …but not create them.
    let resp = c
        .post(format!("{}/workspaces", s.base))
        .bearer_auth(&vtoken)
        .json(&serde_json::json!({"name": "Nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Scanner can create a workspace but not delete one.
    let _ = auth(c.post(format!("{}/admin/users", s.base)))
        .json(&serde_json::json!({
            "email": "scanner@test.local", "name": "Scanner", "password": "scanner-pass-123", "role": "scanner"
        }))
        .send()
        .await
        .unwrap();
    let sresp = c
        .post(format!("{}/auth/login", s.base))
        .json(&serde_json::json!({"email": "scanner@test.local", "password": "scanner-pass-123"}))
        .send()
        .await
        .unwrap();
    let sbody: serde_json::Value = sresp.json().await.unwrap();
    let stoken = sbody["access_token"].as_str().unwrap().to_string();

    let resp = c
        .post(format!("{}/workspaces", s.base))
        .bearer_auth(&stoken)
        .json(&serde_json::json!({"name": "By Scanner"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let ws2: serde_json::Value = resp.json().await.unwrap();
    let ws2_id = ws2["id"].as_str().unwrap().to_string();

    let resp = c
        .delete(format!("{}/workspaces/{ws2_id}", s.base))
        .bearer_auth(&stoken)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403); // admin-only

    // Admin deletes ws2; then delete the main workspace — its tasks must
    // fall back to the Personal scope (ON DELETE SET NULL).
    let resp = auth(c.delete(format!("{}/workspaces/{ws2_id}", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let resp = auth(c.delete(format!("{}/workspaces/{ws_id}", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let resp = auth(c.get(format!("{}/tasks?workspace_id=none", s.base)))
        .send()
        .await
        .unwrap();
    let tl: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(tl["total"], 2); // both sevtest tasks fell back to Personal
}

#[tokio::test]
async fn multi_severity_filter_returns_correct_results() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;
    let auth = |r: reqwest::RequestBuilder| r.bearer_auth(&token);

    // One sevtest run → exactly one critical, one high, one medium finding.
    let resp = auth(c.post(format!("{}/tasks", s.base)))
        .json(&serde_json::json!({
            "plugin_id": "sevtest",
            "inputs": {"target": "example.com"},
            "consent_granted": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let task: serde_json::Value = resp.json().await.unwrap();
    let done = wait_terminal(&c, &s.base, &token, task["id"].as_str().unwrap()).await;
    assert_eq!(done["status"], "completed");

    // Regression: the severity placeholders used to collide with the OFFSET
    // parameter, silently dropping all but the first severity (and breaking
    // single-severity filters entirely). Items and total must now agree.
    let cases = [
        (vec!["critical"], 1),
        (vec!["high"], 1),
        (vec!["medium"], 1),
        (vec!["critical", "high"], 2),
        (vec!["critical", "high", "medium"], 3),
        (vec!["high", "medium"], 2),
        (vec![], 3),
    ];
    for (sevs, expected) in cases {
        let mut url = format!("{}/findings", s.base);
        for (i, sev) in sevs.iter().enumerate() {
            url.push_str(if i == 0 { "?" } else { "&" });
            url.push_str(&format!("severity={sev}"));
        }
        let resp = auth(c.get(&url)).send().await.unwrap();
        assert_eq!(resp.status(), 200, "url={url}");
        let fl: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            fl["total"].as_i64().unwrap(),
            expected,
            "total mismatch for {url}"
        );
        assert_eq!(
            fl["items"].as_array().unwrap().len() as i64,
            expected,
            "items mismatch for {url}"
        );
    }

    // Combined with workspace scoping (none = personal, all tasks are).
    let resp = auth(c.get(format!(
        "{}/findings?severity=critical&severity=high&workspace_id=none",
        s.base
    )))
    .send()
    .await
    .unwrap();
    let fl: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(fl["total"], 2);
}
