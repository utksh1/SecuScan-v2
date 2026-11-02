//! Migration smoke test — boots a fresh DB and runs all migrations,
//! then calls every repo function the v2.6.0 routes touch. Catches
//! schema drift before the full integration suite runs.

use secuscan_db::repo;

#[tokio::test]
async fn migrations_apply_and_basic_repo_calls_work() {
    let tmp = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}/test.db", tmp.path().display());
    let db = secuscan_db::open(&url).await.expect("db opens + migrates");

    // Create a user so FK constraints pass.
    let user = repo::users::create(&db, "alice@example.com", "Alice", "hash", "admin")
        .await
        .expect("user create");
    let user_id = user.id.clone();

    // Create a workspace.
    let ws = repo::workspaces::create_workspace(
        &db,
        repo::workspaces::NewWorkspace {
            name: "WS1",
            description: "",
            created_by: &user_id,
        },
    )
    .await
    .expect("workspace create");

    // v2.6.0 — robots
    let robot = repo::robots::create(&db, "R1", "test", "[]", "[]", "user", &user_id)
        .await
        .expect("robot create");
    assert_eq!(robot.name, "R1");
    let robots = repo::robots::list(&db).await.expect("robot list");
    assert!(!robots.is_empty());

    let run = repo::robots::create_run(&db, &robot.id, Some(&ws.id), "[\"example.com\"]", &user_id)
        .await
        .expect("robot run create");
    assert_eq!(run.status, "running");
    repo::robots::set_run_state(&db, &run.id, "{\"seed\":{\"status\":\"completed\"}}")
        .await
        .expect("set run state");
    repo::robots::finish_run(&db, &run.id, "completed", None)
        .await
        .expect("finish run");

    // v2.6.0 — attack surface
    let asset = repo::attack_surface::upsert_asset(
        &db,
        Some(&ws.id),
        Some("example.com"),
        Some("1.2.3.4"),
        None,
        r#"{"technologies":["nginx"],"ports":[{"port":443,"proto":"tcp"}]}"#,
    )
    .await
    .expect("upsert asset");
    assert_eq!(asset.hostname.as_deref(), Some("example.com"));
    let assets = repo::attack_surface::list(&db, Some(&ws.id), None, 100)
        .await
        .expect("asset list");
    assert_eq!(assets.len(), 1);
    let n = repo::attack_surface::count(&db, Some(&ws.id))
        .await
        .expect("asset count");
    assert_eq!(n, 1);

    // v2.6.0 — auth profiles
    let ap = repo::auth_profiles::create(
        &db,
        Some(&ws.id),
        "cookie1",
        "cookie",
        r#"{"cookies":[{"name":"s","value":"xyz"}]}"#,
        "",
        &user_id,
    )
    .await
    .expect("auth profile create");
    assert_eq!(ap.method, "cookie");
    let aps = repo::auth_profiles::list(&db, Some(&ws.id))
        .await
        .expect("ap list");
    assert_eq!(aps.len(), 1);

    // v2.6.0 — collab
    let m = repo::collab::add_member(&db, &ws.id, &user_id, "owner", &user_id)
        .await
        .expect("add member");
    assert_eq!(m.role, "owner");
    let members = repo::collab::list_members(&db, &ws.id)
        .await
        .expect("member list");
    assert_eq!(members.len(), 1);

    // v2.6.0 — branding
    let b = repo::branding::get(&db).await.expect("branding get");
    assert_eq!(b.org_name, "SecuScan");
    let b = repo::branding::update(
        &db,
        "Acme Corp",
        None,
        "FF8800",
        "0088FF",
        "Acme internal",
        Some(&user_id),
    )
    .await
    .expect("branding update");
    assert_eq!(b.org_name, "Acme Corp");
    assert_eq!(b.primary_color, "FF8800");
}
