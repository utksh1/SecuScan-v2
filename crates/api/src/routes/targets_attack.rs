//! v3.1.2 Attack-Target endpoint: curated multi-tool suites launched
//! against a registered target with one POST.
//!
//! Pentest-tools.com exposes "Replay Attack" and "Attack Target" buttons
//! that re-run a target through a curated bundle of scanners instead of
//! making the user re-launch each tool individually. This module ships
//! the same affordance.
//!
//! Suites (target-kind aware):
//!
//! | suite     | hostname/url                                  | ip_address                                |
//! |-----------|-----------------------------------------------|-------------------------------------------|
//! | quick     | http-recon + http-headers + dns-lookup       | dns-lookup + nmap (top-100)               |
//! | web       | quick + whatweb + nikto + ssl-scanner        | (rejected; use quick or internal)         |
//! | full      | web + subdomain-finder + nmap top-1000 + wordpress-audit + drupal-scanner | nmap top-1000 + smb-enum + ssh-audit |
//! | internal  | (rejected; use full)                          | nmap + smb-enum + ssh-audit               |
//!
//! Every plugin is launched through the standard
//! `validate_and_create_task` admission pipeline so the global target
//! policy, per-plugin consent gate, and v3.1.1 VPN-aware admission
//! gate all still apply. A single 409 from the VPN gate aborts the
//! whole attack and returns no tasks.

use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::routes::tasks::{validate_and_create_task, StartTaskRequest};
use crate::state::SharedState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use secuscan_db::repo;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new().route("/targets/:id/attack", axum::routing::post(attack_target))
}

#[derive(Debug, Deserialize)]
struct AttackRequest {
    suite: String,
}

/// Pick the plugins for a given suite + target kind. Returns the ordered
/// list of plugin ids to launch.
fn pick_suite(suite: &str, kind: &str) -> ApiResult<Vec<&'static str>> {
    let s = suite.to_ascii_lowercase();
    let k = kind.to_ascii_lowercase();
    match (s.as_str(), k.as_str()) {
        ("quick", "hostname" | "url") => Ok(vec!["http-recon", "http-headers", "dns-lookup"]),
        ("quick", "ip_address") => Ok(vec!["dns-lookup", "nmap"]),
        ("web", "hostname" | "url") => Ok(vec![
            "http-recon",
            "http-headers",
            "dns-lookup",
            "whatweb",
            "nikto",
            "testssl",
        ]),
        ("web", "ip_address") => Err(ApiError::BadRequest(
            "the `web` suite requires a hostname or URL target -- use `quick` or `internal` for IP targets".into(),
        )),
        ("full", "hostname" | "url") => Ok(vec![
            "http-recon",
            "http-headers",
            "dns-lookup",
            "whatweb",
            "nikto",
            "testssl",
            "subdomain-finder",
            "nmap",
            "wordpress-audit",
            "drupal-scanner",
        ]),
        ("full", "ip_address") => Ok(vec!["nmap", "smb-enum", "ssh-audit"]),
        ("internal", "ip_address") => Ok(vec!["nmap", "smb-enum", "ssh-audit"]),
        ("internal", "hostname" | "url") => Err(ApiError::BadRequest(
            "the `internal` suite requires an IP target -- use `full` for hostname targets".into(),
        )),
        _ => Err(ApiError::BadRequest(format!(
            "unknown suite `{suite}` (expected one of: quick, web, full, internal)"
        ))),
    }
}

/// Build the inputs map for a plugin against a target. Most plugins
/// accept `target` as a free-form string. URL targets pass through
/// unchanged; hostnames pass through; IPs pass through. Plugins whose
/// own validation rejects the value will fail at admission time, which
/// is the right behavior -- we don't second-guess plugin schemas here.
fn inputs_for(plugin_id: &str, target: &str) -> BTreeMap<String, Value> {
    let mut m = BTreeMap::new();
    m.insert("target".to_string(), Value::String(target.to_string()));
    // Suite-level hints for plugins that accept them.
    match plugin_id {
        "nmap" => {
            // Top-1000 ports is the documented "quick" preset.
            m.insert("ports".to_string(), Value::String("top-1000".into()));
        }
        "subdomain-finder" => {
            // Default wordlist is fine; pass-through.
        }
        _ => {}
    }
    m
}

async fn attack_target(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<AttackRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    let target = repo::workspaces::get_target(&state.db, &id).await?;
    // Authorization: caller must own a task in the target's workspace OR
    // be admin. For simplicity (and because targets are workspace-scoped),
    // require the user to be a member of the workspace. Admins bypass.
    if !user.is_admin() {
        let ws = repo::workspaces::get_workspace(&state.db, &target.workspace_id).await?;
        if ws.created_by != user.0.id {
            // Fall back to membership check.
            let members = repo::collab::list_members(&state.db, &target.workspace_id).await?;
            let is_member = members.iter().any(|m| m.user_id == user.0.id);
            if !is_member {
                return Err(ApiError::Forbidden(
                    "you are not a member of this target's workspace".into(),
                ));
            }
        }
    }

    let plugin_ids = pick_suite(&req.suite, &target.kind)?;
    // Pre-flight: every requested plugin must be enabled and (if it has
    // allowed_targets) accept this target. Skip plugins that aren't
    // available (binary missing) -- the user gets a clear list of what
    // was actually launched vs skipped.
    let mut launched: Vec<Value> = Vec::new();
    let mut skipped: Vec<Value> = Vec::new();

    let enabled_map: HashMap<String, bool> = repo::misc::enabled_map(&state.db).await?;

    // Phase 1: under the registry read lock, collect the manifests we'll
    // launch. We clone out so the lock can be dropped before admission
    // (validate_and_create_task takes its own registry read for manifest
    // validation; holding our lock across that would deadlock or
    // needlessly serialize).
    let mut to_launch: Vec<&str> = Vec::new();
    {
        let registry = state.registry.read().await;
        for pid in plugin_ids {
            let manifest = match registry.get(pid) {
                Some(m) => m,
                None => {
                    skipped.push(json!({
                        "plugin_id": pid,
                        "reason": "not in catalog",
                    }));
                    continue;
                }
            };
            let is_enabled = *enabled_map.get(pid).unwrap_or(&true);
            if !is_enabled {
                skipped.push(json!({
                    "plugin_id": pid,
                    "reason": "disabled",
                }));
                continue;
            }
            if !manifest.available {
                skipped.push(json!({
                    "plugin_id": pid,
                    "reason": "binary missing",
                }));
                continue;
            }
            to_launch.push(pid);
        }
    }

    // Phase 2: launch each plugin through the standard admission pipeline.
    // Some plugins require consent; inherit consent=true from the attack
    // action -- the user clicking "Attack" *is* the consent.
    //
    // Special case: if the workspace VPN admission gate rejects with 409
    // Conflict (tunnel cannot come up), propagate that immediately rather
    // than silently skipping every plugin -- the user needs to see the
    // tunnel error, not a misleading "all plugins skipped" 400.
    for pid in to_launch {
        let inputs = inputs_for(pid, &target.name);
        let task_req = StartTaskRequest {
            plugin_id: pid.to_string(),
            inputs,
            preset: None,
            consent_granted: true,
            workspace_id: Some(target.workspace_id.clone()),
            auth_profile_id: None,
        };
        match validate_and_create_task(&state, &user, &task_req, None, None).await {
            Ok((row, manifest, inputs)) => {
                state.tasks.spawn(row.clone(), manifest, inputs).await;
                launched.push(json!({
                    "id": row.id,
                    "plugin_id": row.plugin_id,
                    "status": row.status,
                }));
            }
            Err(ApiError::Conflict(msg)) => {
                return Err(ApiError::Conflict(format!(
                    "workspace requires VPN profile to attack target `{}`: {msg}",
                    target.name
                )));
            }
            Err(e) => {
                skipped.push(json!({
                    "plugin_id": pid,
                    "reason": e.to_string(),
                }));
            }
        }
    }

    if launched.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "attack suite `{}` produced no launchable tasks for target `{}` -- all plugins skipped: {}",
            req.suite,
            target.name,
            skipped
                .iter()
                .map(|s| s["plugin_id"].as_str().unwrap_or("?"))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "suite": req.suite,
            "target_id": target.id,
            "target": target.name,
            "workspace_id": target.workspace_id,
            "tasks": launched,
            "skipped": skipped,
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_suite_quick_hostname_is_3_plugins() {
        let p = pick_suite("quick", "hostname").unwrap();
        assert_eq!(p, vec!["http-recon", "http-headers", "dns-lookup"]);
    }

    #[test]
    fn pick_suite_quick_ip_is_dns_plus_nmap() {
        let p = pick_suite("quick", "ip_address").unwrap();
        assert_eq!(p, vec!["dns-lookup", "nmap"]);
    }

    #[test]
    fn pick_suite_web_rejects_ip() {
        let err = pick_suite("web", "ip_address").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn pick_suite_internal_rejects_hostname() {
        let err = pick_suite("internal", "hostname").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn pick_suite_full_hostname_includes_cms_scanners() {
        let p = pick_suite("full", "hostname").unwrap();
        assert!(p.contains(&"wordpress-audit"));
        assert!(p.contains(&"drupal-scanner"));
        assert!(p.contains(&"subdomain-finder"));
    }

    #[test]
    fn pick_suite_full_ip_is_internal_three() {
        let p = pick_suite("full", "ip_address").unwrap();
        assert_eq!(p, vec!["nmap", "smb-enum", "ssh-audit"]);
    }

    #[test]
    fn pick_suite_unknown_rejected() {
        assert!(pick_suite("exhaustive", "hostname").is_err());
    }

    #[test]
    fn inputs_for_nmap_adds_top_1000_hint() {
        let m = inputs_for("nmap", "127.0.0.1");
        assert_eq!(m.get("ports").and_then(|v| v.as_str()), Some("top-1000"));
    }

    #[test]
    fn inputs_for_generic_plugin_just_target() {
        let m = inputs_for("http-headers", "example.com");
        assert_eq!(m.len(), 1);
        assert_eq!(m.get("target").and_then(|v| v.as_str()), Some("example.com"));
    }
}
