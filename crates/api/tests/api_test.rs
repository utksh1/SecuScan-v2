//! End-to-end API integration tests: full application over real HTTP,
//! temporary SQLite DB, real plugin manifests, live SSE streaming.

use axum::Router;
use secuscan_api::state::AppState;
use secuscan_core::PluginRegistry;
use std::sync::Arc;

struct TestServer {
    pub base: String,
    pub state: std::sync::Arc<AppState>,
    _db_dir: tempfile::TempDir,
    _plugins_dir: tempfile::TempDir,
}

async fn spawn_app() -> TestServer {
    secuscan_exec::init_tls();
    // Max-Parity Sprint 1.1 — exercise the encryption-at-rest path in every
    // E2E test (auth-profile configs are stored as `enc:v1:` ciphertext and
    // decrypted transparently on read).
    let _ = secuscan_core::crypto::init_with_secret("integration-test-enc-key");

    let db_dir = tempfile::tempdir().unwrap();
    let plugins_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        plugins_dir.path().join("port-scanner.toml"),
        include_str!("../../../plugins/port-scanner.toml"),
    )
    .unwrap();
    // Max-Parity Sprint 1.2 — the real OOB logger manifest, used by the
    // loud-failure test (no SECUSCAN_PUBLIC_URL → hard error).
    std::fs::write(
        plugins_dir.path().join("http-request-logger.toml"),
        include_str!("../../../plugins/http-request-logger.toml"),
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
        plugins_dir.path().join("difftest.toml"),
        r#"
[plugin]
id = "difftest"
name = "Diff Test Tool"
version = "1.0.0"
description = "emits a controllable finding set so scan diffs are deterministic"
category = "test"

[engine]
type = "cli"
binary = "sh"
timeout_seconds = 30
output_format = "text"
argv = [
  "sh", "-c",
  "case \"$1\" in run1) printf 'A CRITICAL\nB HIGH\nD LOW\nE CRITICAL\n';; run2) printf 'B CRITICAL\nC MEDIUM\nD LOW\nE LOW\n';; esac",
  "sh", "{mode}",
]

[[fields]]
id = "target"
label = "Target"
type = "string"
required = true

[[fields]]
id = "mode"
label = "Mode"
type = "select"
default = "run1"
options = [
  { value = "run1", label = "Run 1" },
  { value = "run2", label = "Run 2" },
]

[parser]
type = "passthrough"

[[static_rules]]
pattern = "A CRITICAL"
title = "Finding A"
severity = "critical"
category = "Test"

[[static_rules]]
pattern = "B HIGH"
title = "Finding B"
severity = "high"
category = "Test"

[[static_rules]]
pattern = "B CRITICAL"
title = "Finding B"
severity = "critical"
category = "Test"

[[static_rules]]
pattern = "C MEDIUM"
title = "Finding C"
severity = "medium"
category = "Test"

[[static_rules]]
pattern = "D LOW"
title = "Finding D"
severity = "low"
category = "Test"

[[static_rules]]
pattern = "E CRITICAL"
title = "Finding E"
severity = "critical"
category = "Test"

[[static_rules]]
pattern = "E LOW"
title = "Finding E"
severity = "low"
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
        reports_dir: db_dir.path().join("reports"),
        admin_email: "admin@test.local".to_string(),
        admin_password: Some("admin-password-123".to_string()),
        denied_capabilities: vec![],
        allow_register: false,
        cors_origin: None,
        cookie_secure: false,
        max_concurrent_tasks: 4,
        schedule_tick_secs: 30,
        ai_base_url: None,
        ai_api_key: None,
        enc_key: None,
        // Max-Parity Sprint 1.2 — arm OOB so scanner-generated callback URLs
        // point at a reachable (if fictional) host; the receiver-level test
        // below drives the real server directly.
        public_url: Some("http://oob.test.local".to_string()),
    });

    let db = secuscan_db::open(&config.db_url).await.unwrap();
    secuscan_api::seed::seed_admin(&db, &config).await;
    let registry = PluginRegistry::load_dir(&config.plugins_dir);
    assert!(registry.issues().is_empty(), "{:?}", registry.issues());
    let tasks = secuscan_api::manager::TaskManager::start(db.clone(), config.clone());
    let state = Arc::new(AppState {
        rate_limiter: secuscan_api::rate_limit::RateLimiter::from_env(),
        db,
        config: config.clone(),
        registry: Arc::new(tokio::sync::RwLock::new(registry)),
        tasks,
    });

    let app: Router = secuscan_api::build_app(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestServer {
        base: format!("http://{addr}/api/v1"),
        state,
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
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));

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
        ("html", "SecuScan Report"),
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
async fn fp_memory_triage_audit_and_rescan_suppression() {
    // Max-Parity Sprint 1.1 (tasks 1.1-1.3):
    // - triage to false_positive records FP memory with the acting user +
    //   optional reason (audit trail surfaced on GET /findings/:id);
    // - the same finding on a RE-SCAN is auto-suppressed (false_positive);
    // - dedup-group duplicates inherit status changes;
    // - un-marking forgets the memory so the next scan reports fresh.
    let s = spawn_app().await;
    let (c, token) = login(&s).await;
    let auth = |r: reqwest::RequestBuilder| r.bearer_auth(&token);

    async fn run_sevtest(
        s: &TestServer,
        auth: &dyn Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    ) -> String {
        let resp = auth(reqwest::Client::new().post(format!("{}/tasks", s.base)))
            .json(&serde_json::json!({
                "plugin_id": "sevtest",
                "inputs": {"target": "fp-target.test"},
                "consent_granted": true,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        let task: serde_json::Value = resp.json().await.unwrap();
        let task_id = task["id"].as_str().unwrap().to_string();
        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let t: serde_json::Value =
                auth(reqwest::Client::new().get(format!("{}/tasks/{task_id}", s.base)))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
            match t["status"].as_str().unwrap() {
                "completed" => break,
                "failed" => panic!("sevtest task failed: {t:?}"),
                _ => {}
            }
        }
        task_id
    }

    // Run 1 → 3 findings (critical/high/medium).
    let t1 = run_sevtest(&s, &auth).await;
    let fl: serde_json::Value = auth(c.get(format!("{}/findings?task_id={t1}", s.base)))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fl["total"], 3, "{fl:?}");
    let high = fl["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["title"] == "High test finding")
        .cloned()
        .unwrap();
    let high_id = high["id"].as_str().unwrap().to_string();

    // Triage it to false_positive WITH a reason → FP memory recorded.
    let resp = auth(c.patch(format!("{}/findings/{high_id}/triage", s.base)))
        .json(&serde_json::json!({
            "analyst_status": "false_positive",
            "reason": "not exploitable in our context",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let updated: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(updated["analyst_status"], "false_positive");
    assert_eq!(
        updated["fp_memory"]["reason"], "not exploitable in our context",
        "{updated:?}"
    );
    assert_eq!(updated["fp_memory"]["decided_by_email"], "admin@test.local");

    // Audit trail also surfaces on GET /findings/:id.
    let one: serde_json::Value = auth(c.get(format!("{}/findings/{high_id}", s.base)))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(one["fp_memory"]["reason"], "not exploitable in our context");

    // Run 2 → the same finding arrives AUTO-SUPPRESSED.
    let t2 = run_sevtest(&s, &auth).await;
    let fl2: serde_json::Value = auth(c.get(format!("{}/findings?task_id={t2}", s.base)))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let high2 = fl2["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["title"] == "High test finding")
        .cloned()
        .unwrap();
    assert_eq!(
        high2["analyst_status"], "false_positive",
        "re-scan finding should be auto-suppressed: {high2:?}"
    );

    // Group propagation: triage the RUN-2 copy to confirmed → the RUN-1
    // original (same dedup group) inherits it, and the FP memory is
    // forgotten (any non-FP status clears it).
    let resp = auth(c.patch(format!(
        "{}/findings/{}/triage",
        s.base,
        high2["id"].as_str().unwrap()
    )))
    .json(&serde_json::json!({"analyst_status": "confirmed"}))
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    let orig: serde_json::Value = auth(c.get(format!("{}/findings/{high_id}", s.base)))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        orig["analyst_status"], "confirmed",
        "group propagation should update the run-1 original: {orig:?}"
    );
    assert!(
        orig.get("fp_memory").is_none() || orig["fp_memory"].is_null(),
        "FP memory should be forgotten: {orig:?}"
    );

    // Run 3 → the finding reports fresh (new), no memory left.
    let t3 = run_sevtest(&s, &auth).await;
    let fl3: serde_json::Value = auth(c.get(format!("{}/findings?task_id={t3}", s.base)))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let high3 = fl3["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["title"] == "High test finding")
        .cloned()
        .unwrap();
    assert_eq!(
        high3["analyst_status"], "new",
        "after forgetting, re-scan should report fresh: {high3:?}"
    );
}

#[tokio::test]
async fn auth_profiles_encrypted_at_rest_and_readable_via_api() {
    // Max-Parity Sprint 1.1 (task 1.5): auth profile configs are stored as
    // AES-256-GCM ciphertext in SQLite; the API transparently decrypts for
    // owners. Also verifies the executor-facing failure mode for a profile
    // attached to a task that cannot be resolved (unknown method is
    // rejected at creation, so we check a bad cookie list shape instead).
    let s = spawn_app().await;
    let (c, token) = login(&s).await;
    let auth = |r: reqwest::RequestBuilder| r.bearer_auth(&token);

    // Create a cookie auth profile.
    let resp = auth(c.post(format!("{}/auth-profiles", s.base)))
        .json(&serde_json::json!({
            "name": "session cookies",
            "method": "cookie",
            "config": {"cookies": [{"name": "sid", "value": "s3cret-value"}]},
            "notes": "captured session",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let created: serde_json::Value = resp.json().await.unwrap();
    let pid = created["id"].as_str().unwrap().to_string();

    // Raw SQLite row must contain ciphertext, not the secret.
    let row: Option<(String,)> =
        sqlx::query_as("SELECT config_json FROM auth_profiles WHERE id = ?")
            .bind(&pid)
            .fetch_optional(&s.state.db)
            .await
            .unwrap();
    let raw = row.unwrap().0;
    assert!(
        raw.starts_with("enc:v1:"),
        "config_json must be encrypted at rest, got: {raw:?}"
    );
    assert!(!raw.contains("s3cret-value"));

    // API read transparently decrypts for the owner.
    let resp = auth(c.get(format!("{}/auth-profiles/{pid}", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let prof: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(prof["config"]["cookies"][0]["value"], "s3cret-value");

    // Update re-seals and stays decryptable.
    let resp = auth(c.patch(format!("{}/auth-profiles/{pid}", s.base)))
        .json(&serde_json::json!({
            "name": "session cookies v2",
            "method": "cookie",
            "config": {"cookies": [{"name": "sid", "value": "rotated-value"}]},
            "notes": "rotated",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let row: Option<(String,)> =
        sqlx::query_as("SELECT config_json FROM auth_profiles WHERE id = ?")
            .bind(&pid)
            .fetch_optional(&s.state.db)
            .await
            .unwrap();
    assert!(row.unwrap().0.starts_with("enc:v1:"));
    let prof: serde_json::Value = auth(c.get(format!("{}/auth-profiles/{pid}", s.base)))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prof["config"]["cookies"][0]["value"], "rotated-value");
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
    // 30 attempts/min allowed → a subsequent attempt is rejected. Headroom
    // (40) makes the test robust to a fixed-window reset when the suite
    // runs under heavy parallel load.
    let mut saw_429 = false;
    for i in 0..40 {
        let resp = c
            .post(format!("{}/auth/login", s.base))
            .json(&serde_json::json!({"email": "nobody@test.local", "password": "wrong"}))
            .send()
            .await
            .unwrap();
        if resp.status() == 429 {
            saw_429 = true;
            break;
        }
        assert_eq!(resp.status(), 401, "attempt {i}");
    }
    assert!(saw_429, "login limiter fired within 40 attempts");
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

// ---------------------------------------------------------------------------
// Scan diff (cycle 8 feature work).
// ---------------------------------------------------------------------------

/// Start a difftest task with the given mode and wait for completion.
async fn difftest_run(c: &reqwest::Client, base: &str, token: &str, mode: &str) -> String {
    let resp = c
        .post(format!("{base}/tasks"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "plugin_id": "difftest",
            "inputs": {"target": "diff.example.com", "mode": mode},
            "consent_granted": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let task: serde_json::Value = resp.json().await.unwrap();
    let id = task["id"].as_str().unwrap().to_string();
    let done = wait_terminal(c, base, token, &id).await;
    assert_eq!(done["status"], "completed", "difftest run failed: {done}");
    id
}

#[tokio::test]
async fn scan_diff_classifies_new_fixed_regressed_improved_unchanged() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;

    // Run 1: A(critical) B(high) D(low) E(critical)
    let run1 = difftest_run(&c, &s.base, &token, "run1").await;
    // Run 2: B(critical) C(medium) D(low) E(low)
    let run2 = difftest_run(&c, &s.base, &token, "run2").await;

    // Auto baseline must pick run1 (same plugin + target, earlier, completed).
    let resp = c
        .get(format!("{}/tasks/{run2}/diff", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let d: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(d["auto_baseline"], serde_json::json!(true));
    assert_eq!(d["baseline"]["id"], serde_json::json!(run1));
    assert_eq!(
        d["summary"].to_string(),
        serde_json::json!({
            "new": 1, "fixed": 1, "regressed": 1, "improved": 1, "unchanged": 1
        })
        .to_string()
    );

    let status_of = |title: &str| -> String {
        d["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| {
                let f = if i["finding"].is_null() {
                    &i["previous_finding"]
                } else {
                    &i["finding"]
                };
                f["title"] == serde_json::json!(title)
            })
            .unwrap_or_else(|| panic!("no diff item titled {title}: {d}"))["status"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(status_of("Finding A"), "fixed");
    assert_eq!(status_of("Finding B"), "regressed");
    assert_eq!(status_of("Finding C"), "new");
    assert_eq!(status_of("Finding D"), "unchanged");
    assert_eq!(status_of("Finding E"), "improved");

    // Regressed item carries both severities for the UI arrow.
    let b = d["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["finding"]["title"] == serde_json::json!("Finding B"))
        .unwrap();
    assert_eq!(b["previous_severity"], serde_json::json!("high"));
    assert_eq!(b["finding"]["severity"], serde_json::json!("critical"));

    // Fixed item carries only the previous finding.
    let a = d["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["status"] == serde_json::json!("fixed"))
        .unwrap();
    assert!(a["finding"].is_null());
    assert_eq!(
        a["previous_finding"]["title"],
        serde_json::json!("Finding A")
    );

    // Explicit against= works (reverse direction: run1 vs run2).
    let resp = c
        .get(format!("{}/tasks/{run1}/diff?against={run2}", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let d: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(d["auto_baseline"], serde_json::json!(false));
    assert_eq!(d["baseline"]["id"], serde_json::json!(run2));
    // Reversed: A new, B improved, C fixed, D unchanged, E regressed.
    assert_eq!(d["summary"]["new"], 1);
    assert_eq!(d["summary"]["fixed"], 1);
    assert_eq!(d["summary"]["regressed"], 1);
    assert_eq!(d["summary"]["improved"], 1);
    assert_eq!(d["summary"]["unchanged"], 1);

    // Diffing run1 (the earliest) has no baseline -> 404 with guidance.
    let resp = c
        .get(format!("{}/tasks/{run1}/diff", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("no earlier completed run"));

    // A different target never becomes the baseline.
    let resp = c
        .post(format!("{}/tasks", s.base))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "plugin_id": "difftest",
            "inputs": {"target": "other.example.com", "mode": "run1"},
            "consent_granted": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let other: serde_json::Value = resp.json().await.unwrap();
    let _ = wait_terminal(&c, &s.base, &token, other["id"].as_str().unwrap()).await;
    let resp = c
        .get(format!(
            "{}/tasks/{}/diff",
            s.base,
            other["id"].as_str().unwrap()
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404); // diff.example.com runs are not its baseline

    // Non-completed task -> 400 (findings only exist at completion).
    let resp = c
        .post(format!("{}/tasks", s.base))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "plugin_id": "sleepy",
            "inputs": {"target": "127.0.0.1"},
            "consent_granted": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let sleepy: serde_json::Value = resp.json().await.unwrap();
    let sleepy_id = sleepy["id"].as_str().unwrap().to_string();
    let resp = c
        .get(format!("{}/tasks/{sleepy_id}/diff", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    // Cleanup: cancel the sleepy task so the test server can shut down.
    let _ = c
        .post(format!("{}/tasks/{sleepy_id}/cancel", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn scan_diff_respects_user_isolation() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;

    // Scanner user runs difftest twice.
    let _ = c
        .post(format!("{}/admin/users", s.base))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "email": "scanner2@test.local", "name": "Scanner2",
            "password": "scanner2-pass-123", "role": "scanner"
        }))
        .send()
        .await
        .unwrap();
    let resp = c
        .post(format!("{}/auth/login", s.base))
        .json(&serde_json::json!({"email": "scanner2@test.local", "password": "scanner2-pass-123"}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let stoken = body["access_token"].as_str().unwrap().to_string();

    let run1 = difftest_run(&c, &s.base, &stoken, "run1").await;
    let run2 = difftest_run(&c, &s.base, &stoken, "run2").await;

    // Scanner sees their own baseline.
    let resp = c
        .get(format!("{}/tasks/{run2}/diff", s.base))
        .bearer_auth(&stoken)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let d: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(d["baseline"]["id"], serde_json::json!(run1));

    // Admin (global scope) also finds it.
    let resp = c
        .get(format!("{}/tasks/{run2}/diff", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let admin_diff: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(admin_diff["baseline"]["id"], serde_json::json!(run1));

    // Another user cannot use scanner's task as an explicit baseline…
    let _ = c
        .post(format!("{}/admin/users", s.base))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "email": "scanner3@test.local", "name": "Scanner3",
            "password": "scanner3-pass-123", "role": "scanner"
        }))
        .send()
        .await
        .unwrap();
    let resp = c
        .post(format!("{}/auth/login", s.base))
        .json(&serde_json::json!({"email": "scanner3@test.local", "password": "scanner3-pass-123"}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let t3 = body["access_token"].as_str().unwrap().to_string();

    // …and their own difftest run has no baseline (run1/run2 belong to scanner2).
    let run3 = difftest_run(&c, &s.base, &t3, "run1").await;
    let resp = c
        .get(format!("{}/tasks/{run3}/diff", s.base))
        .bearer_auth(&t3)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Direct IDOR check on the diff of a foreign task.
    let resp = c
        .get(format!("{}/tasks/{run2}/diff", s.base))
        .bearer_auth(&t3)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404); // not found, not 403 — existence hidden
}

// ===========================================================================
// Async report jobs (waiting → in_progress → finished, webhooks, downloads)
// ===========================================================================

async fn wait_report_terminal(
    c: &reqwest::Client,
    base: &str,
    token: &str,
    id: &str,
) -> serde_json::Value {
    for _ in 0..150 {
        let resp = c
            .get(format!("{base}/reports/{id}"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let j: serde_json::Value = resp.json().await.unwrap();
        let status = j["status"].as_str().unwrap().to_string();
        if matches!(status.as_str(), "finished" | "failed") {
            return j;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("report job {id} did not reach a terminal state in time");
}

async fn sevtest_task(c: &reqwest::Client, base: &str, token: &str) -> String {
    let resp = c
        .post(format!("{base}/tasks"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "plugin_id": "sevtest",
            "inputs": {"target": "reports.example.com"},
            "consent_granted": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let t: serde_json::Value = resp.json().await.unwrap();
    let id = t["id"].as_str().unwrap().to_string();
    let done = wait_terminal(c, base, token, &id).await;
    assert_eq!(done["status"], "completed", "sevtest failed: {done}");
    id
}

#[tokio::test]
async fn report_job_lifecycle_downloads_every_format() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;
    let task = sevtest_task(&c, &s.base, &token).await;

    for fmt in ["md", "csv", "html", "sarif", "json", "pdf", "docx", "xlsx"] {
        let resp = c
            .post(format!("{}/tasks/{task}/reports", s.base))
            .bearer_auth(&token)
            .json(&serde_json::json!({ "format": fmt }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 202, "create {fmt}: {}", resp.status());
        let job: serde_json::Value = resp.json().await.unwrap();
        let id = job["id"].as_str().unwrap().to_string();
        assert_eq!(job["format"], serde_json::json!(fmt));
        // The secret-free representation never leaks internal fields.
        assert!(job.get("webhook_secret").is_none());

        let done = wait_report_terminal(&c, &s.base, &token, &id).await;
        assert_eq!(done["status"], "finished", "{fmt} job failed: {done}");
        assert!(
            done["file_bytes"].as_i64().unwrap() > 0,
            "{fmt} artifact empty"
        );
        assert!(done["download_path"].as_str().is_some());

        let resp = c
            .get(format!("{}/reports/{id}/download", s.base))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{fmt} download failed");
        let ctype = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let disp = resp
            .headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let bytes = resp.bytes().await.unwrap();
        assert!(!bytes.is_empty());
        match fmt {
            "pdf" => assert_eq!(&bytes[..5], b"%PDF-"),
            "docx" | "xlsx" => assert_eq!(&bytes[..2], b"PK"),
            "json" => assert_eq!(&bytes[..1], b"{"),
            "csv" => assert!(bytes.starts_with(b"severity,")),
            _ => {}
        }
        match fmt {
            "pdf" => assert!(ctype.starts_with("application/pdf")),
            "docx" => assert!(ctype.contains("wordprocessingml")),
            "xlsx" => assert!(ctype.contains("spreadsheetml")),
            _ => {}
        }
        assert!(disp.contains(&format!(".{fmt}\"")), "filename {disp}");
    }

    // Listing is filtered by task and ordered (newest first by created_at).
    let resp = c
        .get(format!("{}/reports?task_id={task}", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let list: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(list["total"], serde_json::json!(8));
    assert_eq!(list["items"].as_array().unwrap().len(), 8);
    assert!(list["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|j| j["task_id"] == serde_json::json!(task)));

    // Deleting a job removes the artifact (download 404 afterwards).
    let some_id = list["items"][0]["id"].as_str().unwrap().to_string();
    let resp = c
        .delete(format!("{}/reports/{some_id}", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let resp = c
        .get(format!("{}/reports/{some_id}/download", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// Captures (headers, raw body) of a webhook POST for assertions.
type Received = std::sync::Arc<std::sync::Mutex<Option<(axum::http::HeaderMap, Vec<u8>)>>>;

async fn webhook_receiver(
    axum::extract::State(rx): axum::extract::State<Received>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::http::StatusCode {
    *rx.lock().unwrap() = Some((headers, body.to_vec()));
    axum::http::StatusCode::OK
}

#[tokio::test]
async fn report_job_webhook_delivery_is_signed() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;
    let task = sevtest_task(&c, &s.base, &token).await;

    // Stand up a local receiver that captures headers + raw body.
    let received: Received = std::sync::Arc::new(std::sync::Mutex::new(None));
    let rx = received.clone();
    let app: axum::Router = axum::Router::new()
        .route("/hook", axum::routing::post(webhook_receiver))
        .with_state(rx);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let resp = c
        .post(format!("{}/tasks/{task}/reports", s.base))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "format": "json",
            "webhook_url": format!("http://{addr}/hook"),
            "webhook_secret": "whsec_test_123",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let job: serde_json::Value = resp.json().await.unwrap();
    let id = job["id"].as_str().unwrap().to_string();

    let done = wait_report_terminal(&c, &s.base, &token, &id).await;
    assert_eq!(done["status"], "finished");

    // Wait for the callback (delivery starts right after the job finishes).
    let mut captured = None;
    for _ in 0..100 {
        if let Some(got) = received.lock().unwrap().take() {
            captured = Some(got);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let (headers, body) = captured.expect("webhook never delivered");

    assert_eq!(
        headers
            .get("x-secuscan-event")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default(),
        "report.finished"
    );
    assert_eq!(
        headers
            .get("x-secuscan-delivery")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default(),
        id
    );

    // Independent HMAC verification (not calling the server's own code).
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(b"whsec_test_123").unwrap();
    mac.update(&body);
    let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    let got = headers
        .get("x-secuscan-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert_eq!(got, expected, "signature mismatch");

    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["event"], serde_json::json!("report.finished"));
    assert_eq!(payload["report"]["id"], serde_json::json!(id));
    assert_eq!(payload["report"]["status"], serde_json::json!("finished"));
    assert!(payload["report"]["download_path"].as_str().is_some());
    // The secret must never appear in the callback payload.
    let body_str = String::from_utf8_lossy(&body);
    assert!(!body_str.contains("whsec_test_123"));

    // The callback can reach the receiver before the worker commits
    // webhook_attempts; poll the database-backed API for eventual persistence.
    let mut recorded = false;
    for _ in 0..100 {
        let response = c
            .get(format!("{}/reports/{id}", s.base))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let job: serde_json::Value = response.json().await.unwrap();
        if job["webhook_attempts"] == serde_json::json!(1) {
            recorded = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        recorded,
        "signed webhook must record exactly one delivery attempt"
    );
}

#[tokio::test]
async fn report_job_webhook_failures_do_not_fail_the_job() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;
    let task = sevtest_task(&c, &s.base, &token).await;

    // Port 1 on loopback: connection refused, nothing listens there.
    let resp = c
        .post(format!("{}/tasks/{task}/reports", s.base))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "format": "md",
            "webhook_url": "http://127.0.0.1:1/hook",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let job: serde_json::Value = resp.json().await.unwrap();
    let id = job["id"].as_str().unwrap().to_string();

    let done = wait_report_terminal(&c, &s.base, &token, &id).await;
    assert_eq!(
        done["status"], "finished",
        "delivery failure must not fail the job"
    );

    // Retries: 3 attempts with backoff (1s, 4s) — poll until recorded.
    let mut attempts = 0i64;
    for _ in 0..200 {
        let resp = c
            .get(format!("{}/reports/{id}", s.base))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        let j: serde_json::Value = resp.json().await.unwrap();
        attempts = j["webhook_attempts"].as_i64().unwrap_or(0);
        if attempts >= 3 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(attempts, 3, "expected 3 recorded delivery attempts");
}

#[tokio::test]
async fn report_job_isolation_and_validation() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;
    let auth = |r: reqwest::RequestBuilder| r.bearer_auth(&token);

    let task = sevtest_task(&c, &s.base, &token).await;

    // A second scanner user.
    let resp = auth(c.post(format!("{}/admin/users", s.base)))
        .json(&serde_json::json!({
            "email": "scanner2@test.local", "name": "Scanner Two",
            "password": "scanner2-pass-123", "role": "scanner"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let resp = c
        .post(format!("{}/auth/login", s.base))
        .json(&serde_json::json!({
            "email": "scanner2@test.local", "password": "scanner2-pass-123"
        }))
        .send()
        .await
        .unwrap();
    let t2body: serde_json::Value = resp.json().await.unwrap();
    let t2 = t2body["access_token"].as_str().unwrap().to_string();

    // Admin creates a job.
    let resp = auth(
        c.post(format!("{}/tasks/{task}/reports", s.base))
            .json(&serde_json::json!({ "format": "pdf" })),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 202);
    let job: serde_json::Value = resp.json().await.unwrap();
    let id = job["id"].as_str().unwrap().to_string();

    // Foreign user: existence hidden for job detail, download, delete.
    for (method, path) in [
        ("GET", format!("/reports/{id}")),
        ("GET", format!("/reports/{id}/download")),
        ("DELETE", format!("/reports/{id}")),
    ] {
        let resp = c
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("{}{}", s.base, path),
            )
            .bearer_auth(&t2)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404, "{method} foreign job must 404");
    }

    // Foreign user sees an empty list, cannot create a job on a foreign task.
    let resp = c
        .get(format!("{}/reports", s.base))
        .bearer_auth(&t2)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let list: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(list["total"], serde_json::json!(0));

    let resp = c
        .post(format!("{}/tasks/{task}/reports", s.base))
        .bearer_auth(&t2)
        .json(&serde_json::json!({ "format": "pdf" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404); // foreign task, not 403

    // Viewer role is read-only.
    let resp = auth(c.post(format!("{}/admin/users", s.base)))
        .json(&serde_json::json!({
            "email": "viewer2@test.local", "name": "Viewer Two",
            "password": "viewer2-pass-123", "role": "viewer"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let resp = c
        .post(format!("{}/auth/login", s.base))
        .json(&serde_json::json!({
            "email": "viewer2@test.local", "password": "viewer2-pass-123"
        }))
        .send()
        .await
        .unwrap();
    let vt: serde_json::Value = resp.json().await.unwrap();
    let vt = vt["access_token"].as_str().unwrap().to_string();
    let resp = c
        .post(format!("{}/tasks/{task}/reports", s.base))
        .bearer_auth(&vt)
        .json(&serde_json::json!({ "format": "pdf" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Validation errors.
    let cases = [
        serde_json::json!({ "format": "exe" }),
        serde_json::json!({ "format": "md", "severity": "ultra" }),
        serde_json::json!({ "format": "md", "webhook_url": "ftp://example.com/hook" }),
        serde_json::json!({ "format": "md", "webhook_url": "not a url" }),
    ];
    for body in cases {
        let resp = auth(
            c.post(format!("{}/tasks/{task}/reports", s.base))
                .json(&body),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(resp.status(), 400, "body {body} should be rejected");
    }

    // Unknown task.
    let resp = auth(
        c.post(format!(
            "{}/tasks/00000000-0000-0000-0000-000000000000/reports",
            s.base
        ))
        .json(&serde_json::json!({ "format": "md" })),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 404);

    // Deleting the task cascades its jobs (and their files).
    let done = wait_report_terminal(&c, &s.base, &token, &id).await;
    assert_eq!(done["status"], "finished");
    let resp = auth(c.delete(format!("{}/tasks/{task}", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let resp = auth(c.get(format!("{}/reports/{id}", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn report_job_severity_filter_and_sync_parity() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;
    let task = sevtest_task(&c, &s.base, &token).await; // critical+high+medium

    let resp = c
        .post(format!("{}/tasks/{task}/reports", s.base))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "format": "csv", "severity": "high" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let job: serde_json::Value = resp.json().await.unwrap();
    let id = job["id"].as_str().unwrap().to_string();
    assert_eq!(job["severity_filter"], serde_json::json!("high"));

    let done = wait_report_terminal(&c, &s.base, &token, &id).await;
    assert_eq!(done["status"], "finished");

    let resp = c
        .get(format!("{}/reports/{id}/download", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let csv = String::from_utf8(resp.bytes().await.unwrap().to_vec()).unwrap();
    let rows = csv.lines().filter(|l| !l.is_empty()).count();
    assert_eq!(rows, 3, "header + critical + high, got: {csv}");
    assert!(csv.contains("Critical test finding"));
    assert!(csv.contains("High test finding"));
    assert!(!csv.contains("Medium test finding"));

    // The synchronous endpoint honors the same filter (back-compat parity).
    let resp = c
        .get(format!("{}/tasks/{task}/report/csv?severity=high", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let csv = String::from_utf8(resp.bytes().await.unwrap().to_vec()).unwrap();
    assert!(csv.contains("Critical test finding"));
    assert!(!csv.contains("Medium test finding"));

    // And an unknown severity on the sync route is a 400, not a silent pass.
    let resp = c
        .get(format!("{}/tasks/{task}/report/csv?severity=nope", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // The historical `markdown` alias still works on both surfaces and is
    // canonicalized to `md` for storage (the DB CHECK only knows `md`).
    let resp = c
        .get(format!("{}/tasks/{task}/report/markdown", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(String::from_utf8(resp.bytes().await.unwrap().to_vec())
        .unwrap()
        .starts_with("# SecuScan Report"));

    let resp = c
        .post(format!("{}/tasks/{task}/reports", s.base))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "format": "markdown" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let job: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(job["format"], serde_json::json!("md"));
    let id = job["id"].as_str().unwrap().to_string();
    let done = wait_report_terminal(&c, &s.base, &token, &id).await;
    assert_eq!(done["status"], "finished");
}

// ---------------------------------------------------------------------------
// Recurring scan schedules
// ---------------------------------------------------------------------------

/// Backdate a schedule so the next `run_due` pass sees it as due (tests
/// drive the scheduler deterministically instead of waiting for intervals).
async fn backdate_schedule(s: &TestServer, id: &str) {
    sqlx::query("UPDATE schedules SET next_run_at = '2000-01-01T00:00:00.000Z' WHERE id = ?1")
        .bind(id)
        .execute(&s.state.db)
        .await
        .unwrap();
}

async fn wait_task_terminal(s: &TestServer, id: &str) -> secuscan_db::models::TaskRow {
    for _ in 0..100 {
        if let Ok(t) = secuscan_db::repo::tasks::get(&s.state.db, id).await {
            if t.status().is_terminal() {
                return t;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("task {id} did not reach a terminal state in time");
}

#[tokio::test]
async fn schedule_crud_and_validation() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;
    let auth = |r: reqwest::RequestBuilder| r.bearer_auth(&token);

    // A viewer (read-only) and a second scanner for isolation checks.
    let resp = auth(c.post(format!("{}/admin/users", s.base)))
        .json(&serde_json::json!({
            "email": "viewer@test.local", "name": "Viewer", "password": "viewer-pass-123", "role": "viewer"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let resp = auth(c.post(format!("{}/admin/users", s.base)))
        .json(&serde_json::json!({
            "email": "scanner2@test.local", "name": "Scanner Two", "password": "scanner2-pass-123", "role": "scanner"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let vresp = c
        .post(format!("{}/auth/login", s.base))
        .json(&serde_json::json!({"email": "scanner2@test.local", "password": "scanner2-pass-123"}))
        .send()
        .await
        .unwrap();
    let s2token = vresp.json::<serde_json::Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Validation matrix.
    let cases = [
        (
            serde_json::json!({"name": "", "plugin_id": "port-scanner", "inputs": {"target": "127.0.0.1"}, "interval_seconds": 3600, "consent_granted": true}),
            400,
        ),
        (
            serde_json::json!({"name": "x", "plugin_id": "no-such-plugin", "inputs": {"target": "127.0.0.1"}, "interval_seconds": 3600, "consent_granted": true}),
            404,
        ),
        (
            serde_json::json!({"name": "x", "plugin_id": "port-scanner", "inputs": {"target": "127.0.0.1"}, "interval_seconds": 60, "consent_granted": true}),
            400,
        ),
        (
            serde_json::json!({"name": "x", "plugin_id": "port-scanner", "inputs": {"target": "127.0.0.1"}, "interval_seconds": 999_999_999, "consent_granted": true}),
            400,
        ),
        (
            serde_json::json!({"name": "x", "plugin_id": "port-scanner", "inputs": {}, "interval_seconds": 3600, "consent_granted": true}),
            400,
        ), // missing required target
    ];
    for (body, want) in cases {
        let resp = auth(c.post(format!("{}/schedules", s.base)))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), want, "body {body}");
    }

    // A second scanner can create their own schedule (owner = scanner2);
    // it lands in the Personal scope and is invisible to other users.
    let resp = c
        .post(format!("{}/schedules", s.base))
        .bearer_auth(&s2token)
        .json(&serde_json::json!({"name": "v", "plugin_id": "port-scanner", "inputs": {"target": "127.0.0.1"}, "interval_seconds": 3600, "consent_granted": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Viewer is read-only: schedule creation is forbidden.
    let vresp = c
        .post(format!("{}/auth/login", s.base))
        .json(&serde_json::json!({"email": "viewer@test.local", "password": "viewer-pass-123"}))
        .send()
        .await
        .unwrap();
    let vtoken = vresp.json::<serde_json::Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let resp = c
        .post(format!("{}/schedules", s.base))
        .bearer_auth(&vtoken)
        .json(&serde_json::json!({"name": "v", "plugin_id": "port-scanner", "inputs": {"target": "127.0.0.1"}, "interval_seconds": 3600, "consent_granted": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Admin creates one in a workspace.
    let ws_resp = auth(c.post(format!("{}/workspaces", s.base)))
        .json(&serde_json::json!({"name": "Acme", "description": "test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(ws_resp.status(), 201);
    let ws_id = ws_resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = auth(c.post(format!("{}/schedules", s.base)))
        .json(&serde_json::json!({
            "name": "Daily port sweep",
            "plugin_id": "port-scanner",
            "inputs": {"target": "127.0.0.1", "ports": "80"},
            "interval_seconds": 86_400,
            "consent_granted": true,
            "workspace_id": ws_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let sched: serde_json::Value = resp.json().await.unwrap();
    let sid = sched["id"].as_str().unwrap().to_string();
    assert_eq!(sched["plugin_id"], "port-scanner");
    assert_eq!(sched["target"], "127.0.0.1");
    assert_eq!(sched["interval_seconds"], 86_400);
    assert_eq!(sched["enabled"], true);
    assert_eq!(sched["workspace_id"], ws_id);
    assert!(sched["next_run_at"].as_str().unwrap() > "2026");
    assert!(sched["last_task_id"].is_null());

    // Listing: admin sees both, scanner2 only their own.
    let resp = auth(c.get(format!("{}/schedules", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let list: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(list["total"], 2);
    let resp = c
        .get(format!("{}/schedules", s.base))
        .bearer_auth(&s2token)
        .send()
        .await
        .unwrap();
    let list2: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(list2["total"], 1);

    // Workspace scoping on the list.
    let resp = auth(c.get(format!("{}/schedules?workspace_id={ws_id}", s.base)))
        .send()
        .await
        .unwrap();
    let scoped: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(scoped["total"], 1);
    let resp = auth(c.get(format!("{}/schedules?workspace_id=none", s.base)))
        .send()
        .await
        .unwrap();
    let personal: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(personal["total"], 1); // scanner2's, which has no workspace

    // Stranger gets 404 (no existence leak), viewer can read nothing of others.
    let resp = c
        .get(format!("{}/schedules/{sid}", s.base))
        .bearer_auth(&s2token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let resp = c
        .patch(format!("{}/schedules/{sid}", s.base))
        .bearer_auth(&s2token)
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Owner patch: interval change re-anchors next_run_at to ~now + the
    // NEW interval (the old 24h anchor is discarded, even if that means
    // the next run moves earlier).
    let patch_now = secuscan_db::now();
    let resp = auth(c.patch(format!("{}/schedules/{sid}", s.base)))
        .json(&serde_json::json!({"interval_seconds": 3_600}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let patched: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(patched["interval_seconds"], 3_600);
    let after = patched["next_run_at"].as_str().unwrap().to_string();
    let upper = secuscan_core::models::add_seconds_iso(&patch_now, 3_600 + 120);
    assert!(
        after.as_str() > patch_now.as_str() && after.as_str() < upper.as_str(),
        "interval change must re-anchor to ~now+3600: got {after} (patch at {patch_now})"
    );

    // Disable + re-enable also re-anchors.
    let resp = auth(c.patch(format!("{}/schedules/{sid}", s.base)))
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let disabled: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(disabled["enabled"], false);
    let resp = auth(c.patch(format!("{}/schedules/{sid}", s.base)))
        .json(&serde_json::json!({"enabled": true}))
        .send()
        .await
        .unwrap();
    let re_enabled: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(re_enabled["enabled"], true);
    // Re-anchoring is "now() + interval". When the disable→re-enable round-trip
    // completes within the same wall-clock second as the prior patch, the new
    // anchor is equal to (not strictly greater than) `after`. The semantic
    // guarantee is "re-anchored to a fresh future instant" — >= captures that
    // and removes a flaky timing race under parallel test execution.
    assert!(
        re_enabled["next_run_at"].as_str().unwrap() >= after.as_str(),
        "re-enable must re-anchor"
    );

    // Input change re-validates: missing required field is a clean 400.
    let resp = auth(c.patch(format!("{}/schedules/{sid}", s.base)))
        .json(&serde_json::json!({"inputs": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Workspace change to an unknown id is a 404 before anything persists.
    let resp = auth(c.patch(format!("{}/schedules/{sid}", s.base)))
        .json(&serde_json::json!({"workspace_id": "no-such-ws"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Explicit null clears the workspace (Personal).
    let resp = auth(c.patch(format!("{}/schedules/{sid}", s.base)))
        .json(&serde_json::json!({"workspace_id": null}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cleared: serde_json::Value = resp.json().await.unwrap();
    assert!(cleared["workspace_id"].is_null());

    // Delete: stranger 404, owner 204, then 404.
    let resp = c
        .delete(format!("{}/schedules/{sid}", s.base))
        .bearer_auth(&s2token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let resp = auth(c.delete(format!("{}/schedules/{sid}", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let resp = auth(c.get(format!("{}/schedules/{sid}", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn scheduler_fires_overlaps_and_recovers() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;
    let auth = |r: reqwest::RequestBuilder| r.bearer_auth(&token);

    // A long-running plugin so the overlap window is deterministic.
    let resp = auth(c.post(format!("{}/schedules", s.base)))
        .json(&serde_json::json!({
            "name": "Sleepy loop",
            "plugin_id": "sleepy",
            "inputs": {"target": "127.0.0.1"},
            "interval_seconds": 3_600,
            "consent_granted": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let sched: serde_json::Value = resp.json().await.unwrap();
    let sid = sched["id"].as_str().unwrap().to_string();

    // Not due yet: run_due is a no-op.
    let outcomes = secuscan_api::scheduler::run_due(&s.state).await;
    assert!(outcomes.is_empty(), "{outcomes:?}");

    // Backdate -> fires, creates a task linked to the schedule.
    backdate_schedule(&s, &sid).await;
    let outcomes = secuscan_api::scheduler::run_due(&s.state).await;
    assert_eq!(outcomes.len(), 1, "{outcomes:?}");
    let task_id = match &outcomes[0] {
        secuscan_api::scheduler::DueOutcome::Launched(_, t) => t.clone(),
        other => panic!("expected Launched, got {other:?}"),
    };

    let resp = auth(c.get(format!("{}/tasks/{task_id}", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let task: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(task["schedule_id"], sid);
    assert_eq!(task["plugin_id"], "sleepy");
    assert_eq!(task["target"], "127.0.0.1");

    // Schedule bookkeeping updated, anchor advanced, no error.
    let resp = auth(c.get(format!("{}/schedules/{sid}", s.base)))
        .send()
        .await
        .unwrap();
    let after: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(after["last_task_id"], task_id);
    assert!(after["last_run_at"].as_str().is_some());
    assert!(after["last_error"].is_null());
    assert!(after["next_run_at"].as_str().unwrap() > "2026");

    // Run history endpoint lists the task.
    let resp = auth(c.get(format!("{}/schedules/{sid}/runs", s.base)))
        .send()
        .await
        .unwrap();
    let runs: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(runs["total"], 1);
    assert_eq!(runs["items"][0]["id"], task_id);

    // Overlap guard: backdate again while the sleepy task is still running.
    backdate_schedule(&s, &sid).await;
    let outcomes = secuscan_api::scheduler::run_due(&s.state).await;
    assert_eq!(
        outcomes,
        vec![secuscan_api::scheduler::DueOutcome::OverlapSkipped(
            sid.clone()
        )],
        "{outcomes:?}"
    );
    // Still exactly one task for this schedule.
    let tasks = secuscan_db::repo::tasks::list_for_schedule(&s.state.db, &sid, 50)
        .await
        .unwrap();
    assert_eq!(tasks.len(), 1);

    // Failure path: disable the plugin, backdate, run_due -> Rejected with
    // a recorded error and no task; the schedule keeps retrying later.
    secuscan_db::repo::misc::set_plugin_enabled(&s.state.db, "sleepy", false)
        .await
        .unwrap();
    // Cancel the running task so the overlap guard does not mask the
    // rejection, then wait for it to settle.
    let _ = s.state.tasks.cancel(&task_id).await;
    let _ = wait_task_terminal(&s, &task_id).await;
    backdate_schedule(&s, &sid).await;
    let outcomes = secuscan_api::scheduler::run_due(&s.state).await;
    match &outcomes[0] {
        secuscan_api::scheduler::DueOutcome::Rejected(_, msg) => {
            assert!(msg.contains("disabled"), "unexpected message: {msg}");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    let resp = auth(c.get(format!("{}/schedules/{sid}", s.base)))
        .send()
        .await
        .unwrap();
    let rejected: serde_json::Value = resp.json().await.unwrap();
    let err = rejected["last_error"].as_str().unwrap().to_string();
    assert!(err.contains("disabled"), "{err}");
    // Rejection still advanced the anchor (no busy loop).
    assert!(rejected["next_run_at"].as_str().unwrap() > "2026");
    let tasks = secuscan_db::repo::tasks::list_for_schedule(&s.state.db, &sid, 50)
        .await
        .unwrap();
    assert_eq!(tasks.len(), 1, "no new task on rejection");

    // Recovery: re-enable + backdate -> fires again.
    secuscan_db::repo::misc::set_plugin_enabled(&s.state.db, "sleepy", true)
        .await
        .unwrap();
    backdate_schedule(&s, &sid).await;
    let outcomes = secuscan_api::scheduler::run_due(&s.state).await;
    assert!(matches!(
        &outcomes[0],
        secuscan_api::scheduler::DueOutcome::Launched(_, _)
    ));
    let tasks = secuscan_db::repo::tasks::list_for_schedule(&s.state.db, &sid, 50)
        .await
        .unwrap();
    assert_eq!(tasks.len(), 2);
    // Clean up the second sleepy task.
    let _ = s.state.tasks.cancel(&tasks[0].id).await;

    // Deleting the schedule keeps the task history (schedule_id nulls out).
    let resp = auth(c.delete(format!("{}/schedules/{sid}", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let tasks = secuscan_db::repo::tasks::list_for_schedule(&s.state.db, &sid, 50)
        .await
        .unwrap();
    assert!(
        tasks.is_empty(),
        "history detached from the deleted schedule"
    );
    let task_row = secuscan_db::repo::tasks::get(&s.state.db, &task_id)
        .await
        .unwrap();
    assert!(task_row.schedule_id.is_none());
}

#[tokio::test]
async fn schedule_run_now_endpoint() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;
    let auth = |r: reqwest::RequestBuilder| r.bearer_auth(&token);

    // A viewer for the RBAC check.
    let resp = auth(c.post(format!("{}/admin/users", s.base)))
        .json(&serde_json::json!({
            "email": "viewer@test.local", "name": "Viewer", "password": "viewer-pass-123", "role": "viewer"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let vresp = c
        .post(format!("{}/auth/login", s.base))
        .json(&serde_json::json!({"email": "viewer@test.local", "password": "viewer-pass-123"}))
        .send()
        .await
        .unwrap();
    let vtoken = vresp.json::<serde_json::Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = auth(c.post(format!("{}/schedules", s.base)))
        .json(&serde_json::json!({
            "name": "Manual kick",
            "plugin_id": "port-scanner",
            "inputs": {"target": "127.0.0.1"},
            "interval_seconds": 86_400,
            "consent_granted": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let sched: serde_json::Value = resp.json().await.unwrap();
    let sid = sched["id"].as_str().unwrap().to_string();
    let anchor_before = sched["next_run_at"].as_str().unwrap().to_string();

    // Viewer cannot run; stranger would 404.
    let resp = c
        .post(format!("{}/schedules/{sid}/run", s.base))
        .bearer_auth(&vtoken)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Owner run-now: 201 with a task; the recurring anchor is untouched.
    let resp = auth(c.post(format!("{}/schedules/{sid}/run", s.base)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let task_id = body["task_id"].as_str().unwrap().to_string();
    assert_eq!(body["next_run_at"], anchor_before);

    let task = wait_task_terminal(&s, &task_id).await;
    assert_eq!(task.status().label(), "completed");
    assert_eq!(task.schedule_id.as_deref(), Some(sid.as_str()));

    // The manual run is stamped on the schedule but the anchor moved on.
    let resp = auth(c.get(format!("{}/schedules/{sid}", s.base)))
        .send()
        .await
        .unwrap();
    let after: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(after["last_task_id"], task_id);
    assert_eq!(after["next_run_at"], anchor_before);

    // Run history shows it.
    let resp = auth(c.get(format!("{}/schedules/{sid}/runs", s.base)))
        .send()
        .await
        .unwrap();
    let runs: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(runs["total"], 1);
    assert_eq!(runs["items"][0]["id"], task_id);
}

#[tokio::test]
async fn mcp_scan_approvals_are_out_of_band_scoped_one_use_and_audited() {
    let s = spawn_app().await;
    let (c, admin_jwt) = login(&s).await;

    let scanner = secuscan_db::repo::users::create(
        &s.state.db,
        "mcp-scanner@test.local",
        "MCP scanner",
        "unused-test-hash",
        "scanner",
    )
    .await
    .unwrap();
    let key = secuscan_db::repo::api_keys::create(&s.state.db, &scanner.id, "dedicated MCP agent", None)
        .await
        .unwrap()
        .raw;

    let scan = serde_json::json!({
        "plugin_id": "port-scanner",
        "inputs": { "target": "127.0.0.1", "ports": "1" },
        "consent_granted": true,
    });
    let start_url = format!("{}/mcp/scans", s.base);
    let approve_url = format!("{}/mcp/scan-approvals", s.base);

    // A scanner cannot issue its own approval. Neither can an anonymous agent.
    let denied = c
        .post(&approve_url)
        .header("x-api-key", &key)
        .json(&serde_json::json!({
            "issued_to_user_id": scanner.id,
            "scan": scan,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);

    // No caller-supplied consent, or no one-time approval, means no MCP scan.
    let denied = c
        .post(&start_url)
        .header("x-api-key", &key)
        .json(
            &serde_json::json!({"approval_token":"mcpap_invalid","scan":{
                "plugin_id":"port-scanner",
                "inputs":{"target":"127.0.0.1","ports":"1"},
                "consent_granted":false
            }}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    let denied = c
        .post(&start_url)
        .header("x-api-key", &key)
        .json(&serde_json::json!({"scan":scan}))
        .send()
        .await
        .unwrap();
    assert!(denied.status().is_client_error());

    // Reject targets outside the plugin's authorized lab network *before*
    // issuing any approval token.
    let denied = c
        .post(&approve_url)
        .bearer_auth(&admin_jwt)
        .json(&serde_json::json!({
            "issued_to_user_id": scanner.id,
            "scan": {
                "plugin_id":"port-scanner",
                "inputs":{"target":"203.0.113.50","ports":"1"},
                "consent_granted":true
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);

    let response = c
        .post(&approve_url)
        .bearer_auth(&admin_jwt)
        .json(&serde_json::json!({
            "issued_to_user_id": scanner.id,
            "scan": scan
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    let approved: serde_json::Value = response.json().await.unwrap();
    let opaque_token = approved["approval_token"].as_str().unwrap();
    let approval_id = approved["approval_id"].as_str().unwrap();
    assert!(opaque_token.starts_with("mcpap_"));

    // Never persist the plaintext approval token.
    let (stored_hash,): (String,) =
        sqlx::query_as("SELECT token_hash FROM mcp_scan_approvals WHERE id = ?")
            .bind(approval_id)
            .fetch_one(&s.state.db)
            .await
            .unwrap();
    assert_eq!(stored_hash, secuscan_db::sha256_hex(opaque_token));
    assert_ne!(stored_hash, opaque_token);

    let good = serde_json::json!({
        "approval_token": opaque_token,
        "scan": scan
    });

    // Approval binds both scanner identity and every input. Rejection does
    // not consume it, allowing the exact intended request to proceed.
    let wrong_actor = c
        .post(&start_url)
        .bearer_auth(&admin_jwt)
        .json(&good)
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_actor.status(), 403);
    let changed_mode = c
        .post(&start_url)
        .header("x-api-key", &key)
        .json(&serde_json::json!({
            "approval_token": opaque_token,
            "scan": {
                "plugin_id":"port-scanner",
                "inputs":{"target":"127.0.0.1","ports":"2"},
                "consent_granted":true
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(changed_mode.status(), 403);
    let changed_target = c
        .post(&start_url)
        .header("x-api-key", &key)
        .json(&serde_json::json!({
            "approval_token": opaque_token,
            "scan": {
                "plugin_id":"port-scanner",
                "inputs":{"target":"127.0.0.2","ports":"1"},
                "consent_granted":true
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(changed_target.status(), 403);

    // Plugin version, engine and safety metadata are bound to the approval.
    let manifest_path = s._plugins_dir.path().join("port-scanner.toml");
    let original_manifest = std::fs::read_to_string(&manifest_path).unwrap();
    let changed_manifest =
        original_manifest.replacen("version = \"1.1.0\"", "version = \"9.9.9\"", 1);
    assert_ne!(original_manifest, changed_manifest);
    std::fs::write(&manifest_path, changed_manifest).unwrap();
    *s.state.registry.write().await = PluginRegistry::load_dir(s._plugins_dir.path());
    let version_mismatch = c
        .post(&start_url)
        .header("x-api-key", &key)
        .json(&good)
        .send()
        .await
        .unwrap();
    assert_eq!(version_mismatch.status(), 403);
    std::fs::write(&manifest_path, original_manifest).unwrap();
    *s.state.registry.write().await = PluginRegistry::load_dir(s._plugins_dir.path());

    let created = c
        .post(&start_url)
        .header("x-api-key", &key)
        .json(&good)
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let task: serde_json::Value = created.json().await.unwrap();
    assert_eq!(task["options"]["origin"], "mcp");
    assert_eq!(task["options"]["mcp_approval_id"], approval_id);

    let (consumed_at, task_id): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT consumed_at, task_id FROM mcp_scan_approvals WHERE id = ?")
            .bind(approval_id)
            .fetch_one(&s.state.db)
            .await
            .unwrap();
    assert!(consumed_at.is_some());
    assert_eq!(task_id.as_deref(), task["id"].as_str());

    // Exactly-once/replay protection, including attempted retry of a scan.
    let replay = c
        .post(&start_url)
        .header("x-api-key", &key)
        .json(&good)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 403);

    // Expired unused approvals never execute.
    let response = c
        .post(&approve_url)
        .bearer_auth(&admin_jwt)
        .json(&serde_json::json!({
            "issued_to_user_id": scanner.id,
            "scan": scan,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    let second: serde_json::Value = response.json().await.unwrap();
    sqlx::query("UPDATE mcp_scan_approvals SET expires_at_epoch = 1 WHERE id = ?")
        .bind(second["approval_id"].as_str().unwrap())
        .execute(&s.state.db)
        .await
        .unwrap();
    let expired = c
        .post(&start_url)
        .header("x-api-key", &key)
        .json(&serde_json::json!({
            "approval_token": second["approval_token"],
            "scan": scan
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(expired.status(), 403);
}

#[tokio::test]
async fn scoped_mcp_keys_are_denied_direct_rest_mutations_and_revoked() {
    use reqwest::Method;

    let s = spawn_app().await;
    let (client, admin_jwt) = login(&s).await;
    let scanner = secuscan_db::repo::users::create(
        &s.state.db,
        "restricted-mcp-scanner@test.local",
        "Restricted MCP Scanner",
        "disabled-password-hash",
        "scanner",
    )
    .await
    .unwrap();
    let other = secuscan_db::repo::users::create(
        &s.state.db,
        "different-mcp-scanner@test.local",
        "Different MCP Scanner",
        "disabled-password-hash",
        "scanner",
    )
    .await
    .unwrap();

    let legacy = secuscan_db::repo::api_keys::create(&s.state.db, &scanner.id, "legacy scanner", None)
        .await
        .unwrap();
    assert_eq!(legacy.row.scope, "full");

    let issue_url = format!("{}/admin/mcp-keys", s.base);
    let payload = serde_json::json!({
        "issued_to_user_id": scanner.id,
        "name": "sandbox MCP agent"
    });
    // Full-access keys cannot issue restricted keys: issuance requires an
    // administrator's interactive JWT.
    let denied = client
        .post(&issue_url)
        .header("x-api-key", &legacy.raw)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);

    let issued = client
        .post(&issue_url)
        .bearer_auth(&admin_jwt)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(issued.status(), 201);
    let key: serde_json::Value = issued.json().await.unwrap();
    assert_eq!(key["scope"], "mcp_scan");
    let restricted = key["key"].as_str().unwrap().to_string();
    assert!(restricted.starts_with("scmcp_"));

    // Admin inventory returns scoped metadata but never the cleartext key.
    let list = client
        .get(&issue_url)
        .bearer_auth(&admin_jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 200);
    let body: serde_json::Value = list.json().await.unwrap();
    assert!(!body.to_string().contains(&restricted));
    assert!(body["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| { v["id"] == key["id"] && v["scope"] == "mcp_scan" }));

    // A scoped key remains useful for the inspection endpoints needed by
    // MCP. It cannot mint a new full key or modify a resource.
    let read = client
        .get(format!("{}/plugins", s.base))
        .header("x-api-key", &restricted)
        .send()
        .await
        .unwrap();
    assert_eq!(read.status(), 200);

    let mutations = [
        (Method::POST, "/tasks"),
        (Method::POST, "/tasks/fake/retry"),
        (Method::DELETE, "/tasks/fake"),
        (Method::POST, "/workflows"),
        (Method::POST, "/workflows/fake/run"),
        (Method::POST, "/schedules"),
        (Method::POST, "/robots/fake/run"),
        (Method::POST, "/sniper/run"),
        (Method::POST, "/workspaces"),
        (Method::POST, "/auth/api-keys"),
        (Method::POST, "/mcp/scan-approvals"),
        (Method::POST, "/admin/mcp-keys"),
        (Method::POST, "/vpn-profiles/fake/test"),
        (Method::PATCH, "/findings/fake"),
        (Method::PUT, "/plugins/port-scanner/enabled"),
        (Method::GET, "/admin/users"),
    ];
    for (method, path) in mutations {
        let response = client
            .request(method.clone(), format!("{}{}", s.base, path))
            .header("x-api-key", &restricted)
            .json(&serde_json::json!({
                "plugin_id":"port-scanner",
                "inputs":{"target":"127.0.0.1","ports":"1"},
                "consent_granted":true,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403, "{method} {path}");
    }

    // A second Authorization header must not override the restricted key.
    let mixed = client
        .post(format!("{}/tasks", s.base))
        .bearer_auth(&admin_jwt)
        .header("x-api-key", &restricted)
        .json(&serde_json::json!({
            "plugin_id":"port-scanner",
            "inputs":{"target":"127.0.0.1","ports":"1"},
            "consent_granted":true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(mixed.status(), 401);

    // Reopening the persisted SQLite database and constructing a fresh API
    // router must preserve scope enforcement (not an in-memory MCP flag).
    let reopened_db = secuscan_db::open(&s.state.config.db_url).await.unwrap();
    let mut restarted_state = (*s.state).clone();
    restarted_state.db = reopened_db;
    let restarted_app = secuscan_api::build_app(Arc::new(restarted_state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let restart_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, restarted_app).await.unwrap();
    });
    let restarted_base = format!("http://{restart_addr}/api/v1");
    let restart_denied = client
        .post(format!("{restarted_base}/tasks"))
        .header("x-api-key", &restricted)
        .json(&serde_json::json!({
            "plugin_id":"port-scanner",
            "inputs":{"target":"127.0.0.1","ports":"1"},
            "consent_granted":true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(restart_denied.status(), 403);
    let restart_read = client
        .get(format!("{restarted_base}/plugins"))
        .header("x-api-key", &restricted)
        .send()
        .await
        .unwrap();
    assert_eq!(restart_read.status(), 200);

    // A valid out-of-band admin approval still authorizes exactly one scan.
    let scan = serde_json::json!({
        "plugin_id":"port-scanner",
        "inputs":{"target":"127.0.0.1","ports":"1"},
        "consent_granted":true
    });
    let approval_url = format!("{}/mcp/scan-approvals", s.base);
    let approval = client
        .post(&approval_url)
        .bearer_auth(&admin_jwt)
        .json(&serde_json::json!({
            "issued_to_user_id": scanner.id,
            "scan": scan,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(approval.status(), 201);
    let issued_approval: serde_json::Value = approval.json().await.unwrap();

    let other_key_response = client
        .post(&issue_url)
        .bearer_auth(&admin_jwt)
        .json(&serde_json::json!({
            "issued_to_user_id": other.id,
            "name":"other scanner"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(other_key_response.status(), 201);
    let other_key: serde_json::Value = other_key_response.json().await.unwrap();
    let approved_body = serde_json::json!({
        "approval_token": issued_approval["approval_token"],
        "scan": scan,
    });
    let wrong_identity = client
        .post(format!("{restarted_base}/mcp/scans"))
        .header("x-api-key", other_key["key"].as_str().unwrap())
        .json(&approved_body)
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_identity.status(), 403);

    let approved = client
        .post(format!("{restarted_base}/mcp/scans"))
        .header("x-api-key", &restricted)
        .json(&approved_body)
        .send()
        .await
        .unwrap();
    assert_eq!(approved.status(), 201);
    let task: serde_json::Value = approved.json().await.unwrap();
    assert_eq!(task["options"]["origin"], "mcp");
    let replay = client
        .post(format!("{restarted_base}/mcp/scans"))
        .header("x-api-key", &restricted)
        .json(&approved_body)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 403);

    // Existing unscoped keys still work through the ordinary task API.
    let legacy_start = client
        .post(format!("{}/tasks", s.base))
        .header("x-api-key", &legacy.raw)
        .json(&scan)
        .send()
        .await
        .unwrap();
    assert_eq!(legacy_start.status(), 201);

    // Revocation is effective immediately against the shared persisted DB.
    let revoked = client
        .delete(format!(
            "{}/admin/mcp-keys/{}",
            s.base,
            key["id"].as_str().unwrap()
        ))
        .bearer_auth(&admin_jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 204);
    let denied_after_revoke = client
        .get(format!("{restarted_base}/plugins"))
        .header("x-api-key", &restricted)
        .send()
        .await
        .unwrap();
    assert_eq!(denied_after_revoke.status(), 401);
}

#[tokio::test]
async fn private_workspace_membership_blocks_cross_workspace_idors_and_streams() {
    let s = spawn_app().await;
    let (c, admin) = login(&s).await;
    let hash = secuscan_api::auth::hash_password("workspace-test-password").unwrap();
    let owner = secuscan_db::repo::users::create(
        &s.state.db,
        "ws-owner@test.local",
        "WS owner",
        &hash,
        "scanner",
    )
    .await
    .unwrap();
    let editor = secuscan_db::repo::users::create(
        &s.state.db,
        "ws-editor@test.local",
        "WS editor",
        &hash,
        "scanner",
    )
    .await
    .unwrap();
    let viewer = secuscan_db::repo::users::create(
        &s.state.db,
        "ws-viewer@test.local",
        "WS viewer",
        &hash,
        "viewer",
    )
    .await
    .unwrap();
    let outsider = secuscan_db::repo::users::create(
        &s.state.db,
        "ws-outsider@test.local",
        "WS outsider",
        &hash,
        "scanner",
    )
    .await
    .unwrap();

    let mut tokens = std::collections::HashMap::new();
    for email in [
        "ws-owner@test.local",
        "ws-editor@test.local",
        "ws-viewer@test.local",
        "ws-outsider@test.local",
    ] {
        let resp = c
            .post(format!("{}/auth/login", s.base))
            .json(&serde_json::json!({
                "email": email, "password": "workspace-test-password",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        tokens.insert(email, body["access_token"].as_str().unwrap().to_string());
    }
    let owner_token = &tokens["ws-owner@test.local"];
    let editor_token = &tokens["ws-editor@test.local"];
    let viewer_token = &tokens["ws-viewer@test.local"];
    let outsider_token = &tokens["ws-outsider@test.local"];

    let created = c
        .post(format!("{}/workspaces", s.base))
        .bearer_auth(owner_token)
        .json(&serde_json::json!({"name":"private-client"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let workspace: serde_json::Value = created.json().await.unwrap();
    assert_eq!(workspace["access_mode"], "private");
    let ws = workspace["id"].as_str().unwrap();
    let members = c
        .get(format!("{}/workspaces/{ws}/members", s.base))
        .bearer_auth(owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(members.status(), 200);
    let listing: serde_json::Value = members.json().await.unwrap();
    assert!(listing["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| { row["user_id"] == owner.id && row["role"] == "owner" }));

    let target = c
        .post(format!("{}/workspaces/{ws}/targets", s.base))
        .bearer_auth(owner_token)
        .json(&serde_json::json!({"name":"127.0.0.1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(target.status(), 201);
    let target_id: serde_json::Value = target.json().await.unwrap();
    let task = c
        .post(format!("{}/tasks", s.base))
        .bearer_auth(owner_token)
        .json(&serde_json::json!({
            "plugin_id":"sevtest",
            "inputs":{"target":"127.0.0.1"},
            "consent_granted":true,
            "workspace_id":ws
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(task.status(), 201);
    let created_task: serde_json::Value = task.json().await.unwrap();
    let task_id = created_task["id"].as_str().unwrap();
    let terminal = wait_terminal(&c, &s.base, owner_token, task_id).await;
    assert_eq!(terminal["status"], "completed");
    let finds = c
        .get(format!("{}/tasks/{task_id}/findings", s.base))
        .bearer_auth(owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(finds.status(), 200);
    let finds: serde_json::Value = finds.json().await.unwrap();
    let finding_id = finds["items"][0]["id"].as_str().unwrap();

    // Non-members see the same 404 as unknown IDs, including ID-based
    // target mutation, task evidence, exported reports and SSE.
    for path in [
        format!("/workspaces/{ws}"),
        format!("/workspaces/{ws}/targets"),
        format!("/workspaces/{ws}/members"),
        format!("/tasks/{task_id}"),
        format!("/findings/{finding_id}"),
        format!("/tasks/{task_id}/report/md"),
        format!("/tasks/{task_id}/stream"),
        format!("/findings/{finding_id}/comments"),
        format!("/dashboard/summary?workspace_id={ws}"),
    ] {
        let denied = c
            .get(format!("{}{}", s.base, path))
            .bearer_auth(outsider_token)
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), 404, "GET {path}");
    }
    let denied_mutation = c
        .patch(format!(
            "{}/targets/{}",
            s.base,
            target_id["id"].as_str().unwrap()
        ))
        .bearer_auth(outsider_token)
        .json(&serde_json::json!({"description":"attempted"}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied_mutation.status(), 404);
    let denied_scan = c
        .post(format!("{}/tasks", s.base))
        .bearer_auth(outsider_token)
        .json(&serde_json::json!({
            "plugin_id":"sevtest", "inputs":{"target":"127.0.0.1"},
            "consent_granted":true, "workspace_id":ws
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(denied_scan.status(), 404);
    let list = c
        .get(format!("{}/workspaces", s.base))
        .bearer_auth(outsider_token)
        .send()
        .await
        .unwrap();
    let list: serde_json::Value = list.json().await.unwrap();
    assert!(!list["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["id"] == ws));
    let tasks = c
        .get(format!("{}/tasks", s.base))
        .bearer_auth(outsider_token)
        .send()
        .await
        .unwrap();
    let tasks: serde_json::Value = tasks.json().await.unwrap();
    assert_eq!(tasks["total"], 0);
    let findings = c
        .get(format!("{}/findings", s.base))
        .bearer_auth(outsider_token)
        .send()
        .await
        .unwrap();
    let findings: serde_json::Value = findings.json().await.unwrap();
    assert_eq!(findings["total"], 0);

    for (member, role) in [(&editor, "editor"), (&viewer, "viewer")] {
        let resp = c
            .post(format!("{}/workspaces/{ws}/members", s.base))
            .bearer_auth(owner_token)
            .json(&serde_json::json!({"user_id":member.id, "role":role}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
    }
    // Viewers can browse evidence and export it, but cannot mutate it.
    for path in [
        format!("/workspaces/{ws}"),
        format!("/tasks/{task_id}"),
        format!("/findings/{finding_id}"),
        format!("/tasks/{task_id}/report/md"),
        format!("/tasks/{task_id}/stream"),
    ] {
        let allowed = c
            .get(format!("{}{}", s.base, path))
            .bearer_auth(viewer_token)
            .send()
            .await
            .unwrap();
        assert_eq!(allowed.status(), 200, "GET {path}");
    }
    let denied_edit = c
        .patch(format!(
            "{}/targets/{}",
            s.base,
            target_id["id"].as_str().unwrap()
        ))
        .bearer_auth(viewer_token)
        .json(&serde_json::json!({"description":"viewer write"}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied_edit.status(), 403);
    let denied_role_change = c
        .post(format!("{}/workspaces/{ws}/members", s.base))
        .bearer_auth(editor_token)
        .json(&serde_json::json!({"user_id":outsider.id, "role":"editor"}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied_role_change.status(), 404);

    let editor_scan = c
        .post(format!("{}/tasks", s.base))
        .bearer_auth(editor_token)
        .json(&serde_json::json!({
            "plugin_id":"sevtest", "inputs":{"target":"127.0.0.1"},
            "consent_granted":true, "workspace_id":ws
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(editor_scan.status(), 201);

    // Revoke editor: formerly authorized evidence and new launches both
    // become inaccessible without disclosing the private workspace ID.
    let revoked = c
        .delete(format!("{}/workspaces/{ws}/members/{}", s.base, editor.id))
        .bearer_auth(owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 204);
    let denied = c
        .get(format!("{}/tasks/{task_id}", s.base))
        .bearer_auth(editor_token)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 404);
    let denied = c
        .get(format!("{}/tasks/{task_id}/stream", s.base))
        .bearer_auth(editor_token)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 404);
    let denied = c
        .post(format!("{}/tasks", s.base))
        .bearer_auth(editor_token)
        .json(&serde_json::json!({
            "plugin_id":"sevtest", "inputs":{"target":"127.0.0.1"},
            "consent_granted":true, "workspace_id":ws
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 404);

    // Explicit admin-created shared workspace preserves original behavior.
    let shared = c
        .post(format!("{}/workspaces", s.base))
        .bearer_auth(&admin)
        .json(&serde_json::json!({"name":"legacy-shared", "access_mode":"shared"}))
        .send()
        .await
        .unwrap();
    assert_eq!(shared.status(), 201);
    let shared: serde_json::Value = shared.json().await.unwrap();
    let shared_id = shared["id"].as_str().unwrap();
    let visible = c
        .get(format!("{}/workspaces/{shared_id}", s.base))
        .bearer_auth(outsider_token)
        .send()
        .await
        .unwrap();
    assert_eq!(visible.status(), 200);
    let shared_target = c
        .post(format!("{}/workspaces/{shared_id}/targets", s.base))
        .bearer_auth(outsider_token)
        .json(&serde_json::json!({"name":"shared.local"}))
        .send()
        .await
        .unwrap();
    assert_eq!(shared_target.status(), 201);
}

// --- Max-Parity Sprint 1.2: OOB pipeline end-to-end ---------------------------------
// Handler → payload serving (CORS) → bare-callback hit → marker-correlated
// beacon → auto-opened validated finding → no duplicate on repeat beacons.
#[tokio::test]
async fn oob_payload_serving_correlates_and_auto_opens_findings() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;

    // 1. Create a handler with cookie capture.
    let resp = c
        .post(format!("{}/oob-handlers", s.base))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "e2e-oob",
            "kind": "http_logger",
            "config": { "capture_cookies": true },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let handler: serde_json::Value = resp.json().await.unwrap();
    let secret = handler["secret"].as_str().unwrap().to_string();
    let handler_id = handler["id"].as_str().unwrap().to_string();

    // 2. GET with Accept: application/javascript serves the capture script.
    let resp = c
        .get(format!("{}/oob/{}", s.base, secret))
        .header("accept", "application/javascript")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap()),
        Some("*"),
        "CORS wildcard on payload"
    );
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("application/javascript"),
        "payload content-type"
    );
    let js = resp.text().await.unwrap();
    assert!(js.contains("document.cookie"), "cookies capture present");
    assert!(js.contains("sendBeacon"), "beacon transport present");
    assert!(js.contains("location.pathname"), "beacons are relative");

    // 3. Bare callback records a hit (does NOT serve the script).
    let resp = c.get(format!("{}/oob/{}", s.base, secret)).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "", "bare callback has empty body");
    let row: serde_json::Value = c
        .get(format!("{}/oob-handlers/{}", s.base, handler_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(row["hit_count"].as_i64(), Some(1), "bare callback counted");

    // 4. Create a task (every task gets a marker), beacon with the marker.
    let resp = c
        .post(format!("{}/tasks", s.base))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "plugin_id": "port-scanner",
            "inputs": { "target": "127.0.0.1:1" },
            "consent_granted": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let task: serde_json::Value = resp.json().await.unwrap();
    let task_id = task["id"].as_str().unwrap().to_string();

    let marker: Option<String> = sqlx::query_scalar("SELECT oob_marker FROM tasks WHERE id = ?")
        .bind(&task_id)
        .fetch_one(&s.state.db)
        .await
        .unwrap();
    let marker = marker.expect("every task gets an OOB marker");
    assert!(marker.starts_with("ptt"));

    let beacon = |q: &str| {
        let url = format!("{}/oob/{}?m={}{}", s.base, secret, marker, q);
        c.get(url).send()
    };
    let resp = beacon("&t=cookies&d=sessionid%3Dleaked-value").await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap()),
        Some("*"),
        "CORS wildcard on hit response"
    );
    beacon("&t=ping").await.unwrap();
    let _ = c
        .post(format!("{}/oob/{}?m={}&t=keys", s.base, secret, marker))
        .body("captured\nkeys")
        .send()
        .await;

    // 5. Hits recorded + correlated.
    let hits: serde_json::Value = c
        .get(format!("{}/oob-handlers/{}/hits", s.base, handler_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = hits["items"].as_array().unwrap();
    assert_eq!(items.len(), 4, "bare + 2 beacons + POST recorded");
    let correlated: Vec<_> = items
        .iter()
        .filter(|h| h["task_id"].as_str() == Some(task_id.as_str()))
        .collect();
    assert_eq!(correlated.len(), 3, "marker beacons correlate to the task");
    assert!(
        correlated.iter().any(|h| h["payload"]["stream"] == "cookies"
            && h["payload"]["data"].as_str().unwrap_or("").contains("sessionid")),
        "cookie beacon carries stream + data"
    );

    // 6. Auto-finding opened, exactly once.
    let findings: serde_json::Value = c
        .get(format!("{}/findings?task_id={}", s.base, task_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = findings["items"].as_array().unwrap();
    let oob_findings: Vec<_> = items
        .iter()
        .filter(|f| f["title"] == "Out-of-band interaction confirmed (blind SSRF/XXE/injection)")
        .collect();
    assert_eq!(oob_findings.len(), 1, "exactly one auto-finding");
    let f = oob_findings[0];
    assert_eq!(f["kind"], "validated_issue");
    assert_eq!(f["confidence"], "certain");
    assert!(f["proof"].as_str().unwrap().contains("sessionid"), "proof carries beacon data");

    // 7. Repeat beacon does NOT duplicate the finding.
    beacon("&t=html&d=again").await.unwrap();
    let findings: serde_json::Value = c
        .get(format!("{}/findings?task_id={}", s.base, task_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let count = findings["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["title"] == "Out-of-band interaction confirmed (blind SSRF/XXE/injection)")
        .count();
    assert_eq!(count, 1, "repeat beacons dedup to one finding");

    // 8. Hit cap enforced (500).
    for i in 0..499 {
        let _ = beacon(&format!("&t=cap&d={i}")).await;
    }
    let row: serde_json::Value = c
        .get(format!("{}/oob-handlers/{}", s.base, handler_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(row["hit_count"].as_i64(), Some(500), "cap reached at 500");
    let resp = beacon("&t=over").await.unwrap();
    assert_eq!(resp.status(), 429, "hit over cap rejected");
}

// --- Max-Parity Sprint 1.2: OOB tools fail loudly without a public URL --------------
#[tokio::test]
async fn oob_scanner_fails_loudly_when_public_url_missing() {
    let s = spawn_app().await;
    // Run the scanner directly through execute_task with an unarmed OobCtx:
    // OobCtx::default() has public_url: None → the scanner must fail loudly
    // instead of emitting a dead secuscan.local URL.
    let registry = secuscan_core::PluginRegistry::load_dir(&s.state.config.plugins_dir);
    let manifest = registry
        .get("http-request-logger")
        .expect("http-request-logger plugin present");
    let mut inputs = std::collections::BTreeMap::new();
    inputs.insert("target".to_string(), serde_json::json!("oob-loud-failure"));
    let sink = secuscan_exec::EventSink::new(uuid::Uuid::new_v4(), tokio::sync::mpsc::channel(8).0);
    let outcome = secuscan_exec::execute_task(
        manifest,
        &inputs,
        &sink,
        tokio_util::sync::CancellationToken::new(),
        None,
        Some(secuscan_exec::native::OobCtx::default()),
    )
    .await;
    assert_eq!(outcome.status, secuscan_core::models::TaskStatus::Failed);
    assert!(
        outcome.error.unwrap_or_default().contains("SECUSCAN_PUBLIC_URL"),
        "error names the missing env var"
    );
}

// --- Max-Parity Sprint 1.3: API-key expiry ------------------------------------------
#[tokio::test]
async fn api_keys_expire_and_then_reject() {
    let s = spawn_app().await;
    let (c, token) = login(&s).await;

    // Create a key with a 7-day lifetime.
    let resp = c
        .post(format!("{}/auth/api-keys", s.base))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "expiring", "expires_in_days": 7 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let raw = body["key"].as_str().unwrap().to_string();
    assert!(body["expires_at"].as_str().is_some(), "expires_at returned");
    assert!(
        body["expires_at"].as_str().unwrap() > body["created_at"].as_str().unwrap(),
        "expiry is in the future"
    );

    // Validation: out-of-range lifetimes rejected.
    let resp = c
        .post(format!("{}/auth/api-keys", s.base))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "bad", "expires_in_days": 0 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // The fresh key authenticates.
    let resp = c
        .get(format!("{}/auth/me", s.base))
        .header("x-api-key", &raw)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "fresh key works");

    // Simulate expiry by backdating the column directly.
    sqlx::query("UPDATE api_keys SET expires_at = '2020-01-01T00:00:00.000Z'")
        .execute(&s.state.db)
        .await
        .unwrap();
    let resp = c
        .get(format!("{}/auth/me", s.base))
        .header("x-api-key", &raw)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "expired key rejected");

    // The listing reflects the expired state after the verify attempt.
    let keys: serde_json::Value = c
        .get(format!("{}/auth/api-keys", s.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let expired = keys["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["name"] == "expiring")
        .unwrap();
    assert!(
        expired["revoked_at"].as_str().is_some(),
        "expired key stamped revoked on verify attempt"
    );
}
