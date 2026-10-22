use secuscan_core::models::{AnalystStatus, Finding, FindingKind, Severity, TaskStatus};
use secuscan_db::repo;
use secuscan_db::{open, sha256_hex};

async fn test_db() -> (tempfile::TempDir, sqlx::SqlitePool) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let pool = open(&url).await.expect("db open + migrate");
    (dir, pool)
}

#[tokio::test]
async fn user_lifecycle() {
    let (_d, pool) = test_db().await;
    let u = repo::users::create(&pool, "Admin@Example.com", "Admin", "hash", "admin")
        .await
        .unwrap();
    assert_eq!(u.email, "admin@example.com"); // normalized
    // duplicate email
    assert!(repo::users::create(&pool, "admin@example.com", "X", "h", "viewer")
        .await
        .is_err());
    assert!(repo::users::find_by_email(&pool, "ADMIN@example.com")
        .await
        .unwrap()
        .is_some());
    assert!(repo::users::update_role(&pool, &u.id, "scanner").await.is_ok());
    assert!(repo::users::update_role(&pool, &u.id, "superuser").await.is_err());
    assert_eq!(repo::users::count(&pool).await.unwrap(), 1);
}

#[tokio::test]
async fn refresh_tokens_expire() {
    let (_d, pool) = test_db().await;
    let u = repo::users::create(&pool, "a@b.c", "A", "h", "viewer").await.unwrap();
    let past = "2020-01-01T00:00:00.000Z";
    let future = "2099-01-01T00:00:00.000Z";
    repo::users::insert_refresh_token(&pool, "t1", &u.id, &sha256_hex("tok1"), past)
        .await
        .unwrap();
    repo::users::insert_refresh_token(&pool, "t2", &u.id, &sha256_hex("tok2"), future)
        .await
        .unwrap();
    assert!(repo::users::find_refresh_token(&pool, &sha256_hex("tok1"))
        .await
        .unwrap()
        .is_none()); // expired
    assert!(repo::users::find_refresh_token(&pool, &sha256_hex("tok2"))
        .await
        .unwrap()
        .is_some());
    let removed = repo::users::delete_expired_refresh_tokens(&pool).await.unwrap();
    assert_eq!(removed, 1);
}

#[tokio::test]
async fn api_key_roundtrip() {
    let (_d, pool) = test_db().await;
    let u = repo::users::create(&pool, "a@b.c", "A", "h", "scanner").await.unwrap();
    let created = repo::api_keys::create(&pool, &u.id, "ci-key").await.unwrap();
    assert!(created.raw.starts_with("scsk_"));
    assert_ne!(created.row.key_hash, created.raw); // hashed
    let verified = repo::api_keys::verify(&pool, &created.raw)
        .await
        .unwrap()
        .expect("key verifies");
    assert_eq!(verified.user_id, u.id);
    assert!(verified.last_used_at.is_some());
    assert!(repo::api_keys::verify(&pool, "scsk_wrong").await.unwrap().is_none());
    assert!(repo::api_keys::revoke(&pool, &created.row.id, &u.id).await.unwrap());
    assert!(repo::api_keys::verify(&pool, &created.raw).await.unwrap().is_none()); // revoked
}

#[tokio::test]
async fn task_and_findings_flow() {
    let (_d, pool) = test_db().await;
    let u = repo::users::create(&pool, "a@b.c", "A", "h", "scanner").await.unwrap();
    let t = repo::tasks::create(
        &pool,
        repo::tasks::NewTask {
            user_id: &u.id,
            plugin_id: "port-scanner",
            plugin_name: "TCP Port Scanner",
            target: Some("127.0.0.1"),
            inputs_json: r#"{"target":"127.0.0.1"}"#,
            options_json: "{}",
            workflow_run_id: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(t.status(), TaskStatus::Queued);

    repo::tasks::mark_running(&pool, &t.id).await.unwrap();

    let findings = vec![
        {
            let mut f = Finding::new("Open port 80", "Network Service", Severity::High, FindingKind::Observation);
            f.description = "d".into();
            f
        },
        {
            let mut f = Finding::new("Open port 22", "Network Service", Severity::Info, FindingKind::Observation);
            f.description = "d2".into();
            f
        },
    ];
    let ids = repo::findings::insert_many(&pool, &t.id, "port-scanner", &findings)
        .await
        .unwrap();
    assert_eq!(ids.len(), 2);

    let stats = r#"{"findings":2}"#;
    repo::tasks::finish(
        &pool,
        &t.id,
        TaskStatus::Completed,
        Some(0),
        None,
        stats,
        "raw output here",
        false,
    )
    .await
    .unwrap();

    let got = repo::tasks::get(&pool, &t.id).await.unwrap();
    assert_eq!(got.status(), TaskStatus::Completed);
    assert_eq!(got.exit_code, Some(0));
    assert_eq!(got.output.as_deref(), Some("raw output here"));

    // list omits output
    let listed = repo::tasks::list(
        &pool,
        &repo::tasks::TaskListFilters {
            user_id: Some(u.id.clone()),
            limit: 10,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].output.is_none());

    // findings sorted by severity: high before info
    let fl = repo::findings::list(
        &pool,
        &repo::findings::FindingFilters {
            task_id: Some(t.id.clone()),
            limit: 10,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(fl.len(), 2);
    assert_eq!(fl[0].severity(), Severity::High);
    assert_eq!(fl[1].severity(), Severity::Info);

    // triage
    let updated = repo::findings::update_analyst_status(&pool, &fl[0].id, AnalystStatus::Confirmed)
        .await
        .unwrap();
    assert_eq!(updated.analyst_status(), AnalystStatus::Confirmed);

    // events
    repo::misc::insert_events(
        &pool,
        &[repo::misc::NewTaskEvent {
            task_id: &t.id,
            ts: "2026-01-01T00:00:00.000Z",
            level: "info",
            payload_json: r#"{"message":"started"}"#,
        }],
    )
    .await
    .unwrap();
    let evs = repo::misc::list_events(&pool, &t.id, 0, 100).await.unwrap();
    assert_eq!(evs.len(), 1);
    let evs2 = repo::misc::list_events(&pool, &t.id, evs[0].id, 100).await.unwrap();
    assert!(evs2.is_empty()); // cursor works

    // delete cascades
    assert!(repo::tasks::delete(&pool, &t.id).await.unwrap());
    assert_eq!(repo::misc::count_events(&pool, &t.id).await.unwrap(), 0);
    let fl2 = repo::findings::list(
        &pool,
        &repo::findings::FindingFilters {
            task_id: Some(t.id.clone()),
            limit: 10,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(fl2.is_empty());
}

#[tokio::test]
async fn settings_and_policy() {
    let (_d, pool) = test_db().await;
    assert!(repo::misc::get_require_consent(&pool).await.unwrap()); // default true
    repo::misc::set_require_consent(&pool, false).await.unwrap();
    assert!(!repo::misc::get_require_consent(&pool).await.unwrap());

    let pol = secuscan_core::policy::NetworkPolicy {
        allow: vec!["127.0.0.1".into()],
        deny: vec!["10.66.*.*".into()],
    };
    repo::misc::set_network_policy(&pool, &pol).await.unwrap();
    let got = repo::misc::get_network_policy(&pool).await.unwrap();
    assert_eq!(got, pol);

    repo::misc::set_plugin_enabled(&pool, "nmap", false).await.unwrap();
    let m = repo::misc::enabled_map(&pool).await.unwrap();
    assert_eq!(m.get("nmap"), Some(&false));
    repo::misc::set_plugin_enabled(&pool, "nmap", true).await.unwrap();
    let m = repo::misc::enabled_map(&pool).await.unwrap();
    assert_eq!(m.get("nmap"), Some(&true));

    let entry = secuscan_core::policy::PolicyAuditEntry::denied(
        "8.8.8.8",
        "nmap",
        "user@example.com",
        "outside allowlist",
        secuscan_core::policy::DenyLayer::GlobalAllow,
        "127.0.0.1",
    );
    repo::misc::insert_policy_audit(&pool, &entry).await.unwrap();
    let audit = repo::misc::list_policy_audit(&pool, 10).await.unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].target, "8.8.8.8");
}

#[tokio::test]
async fn workflow_runs() {
    let (_d, pool) = test_db().await;
    let u = repo::users::create(&pool, "a@b.c", "A", "h", "admin").await.unwrap();
    let steps = r#"[{"plugin_id":"port-scanner","inputs":{"target":"127.0.0.1"}}]"#;
    let w = repo::workflows::create(&pool, "recon-chain", "chain", steps, &u.id)
        .await
        .unwrap();
    let run = repo::workflows::create_run(&pool, &w.id).await.unwrap();
    repo::workflows::append_run_task(&pool, &run.id, "task-1")
        .await
        .unwrap();
    repo::workflows::append_run_task(&pool, &run.id, "task-2")
        .await
        .unwrap();
    repo::workflows::finish_run(&pool, &run.id, TaskStatus::Completed, None)
        .await
        .unwrap();
    let runs = repo::workflows::list_runs(&pool, &w.id).await.unwrap();
    assert_eq!(runs.len(), 1);
    let ids: Vec<String> = serde_json::from_str(&runs[0].task_ids_json).unwrap();
    assert_eq!(ids, vec!["task-1", "task-2"]);
    assert_eq!(runs[0].status, "completed");

    assert!(repo::workflows::update(&pool, &w.id, "renamed", "d", steps)
        .await
        .is_ok());
    assert_eq!(repo::workflows::count_workflows(&pool).await.unwrap(), 1);
    assert!(repo::workflows::delete(&pool, &w.id).await.unwrap());
    assert!(repo::workflows::list_runs(&pool, &w.id).await.unwrap().is_empty()); // cascade
}

#[tokio::test]
async fn dashboard_counters() {
    let (_d, pool) = test_db().await;
    let u = repo::users::create(&pool, "a@b.c", "A", "h", "admin").await.unwrap();
    let t = repo::tasks::create(
        &pool,
        repo::tasks::NewTask {
            user_id: &u.id,
            plugin_id: "p",
            plugin_name: "P",
            target: Some("127.0.0.1"),
            inputs_json: "{}",
            options_json: "{}",
            workflow_run_id: None,
        },
    )
    .await
    .unwrap();
    let mut f = Finding::new("x", "c", Severity::Critical, FindingKind::Observation);
    f.description = "d".into();
    repo::findings::insert_many(&pool, &t.id, "p", &[f]).await.unwrap();
    let s = repo::misc::dashboard_summary(&pool).await.unwrap();
    assert_eq!(s.tasks_total, 1);
    assert_eq!(s.tasks_queued, 1);
    assert_eq!(s.findings_critical, 1);
    assert_eq!(s.findings_new, 1);
    assert_eq!(s.users_total, 1);
}
