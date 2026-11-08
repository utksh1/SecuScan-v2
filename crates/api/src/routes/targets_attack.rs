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
//! | web       | quick + website-scanner + param-finder + js-analyzer + nuclei + whatweb + nikto + testssl + http-probe + crawler | (rejected; use quick or internal) |
//! | full      | web + xss-scanner + api-scanner + subdomain-finder + nmap top-1000 + wordpress-audit + drupal-scanner + subdomain-takeover + http-smuggling + http-probe + crawler | nmap + fast-port-scan + smb-enum + ssh-audit + service-defaults |
//! | internal  | (rejected; use full)                          | nmap + smb-enum + ssh-audit + service-defaults |
//!
//! Every plugin is launched through the standard
//! `validate_and_create_task` admission pipeline so the global target
//! policy, per-plugin consent gate, and v3.1.1 VPN-aware admission
//! gate all still apply. A single 409 from the VPN gate aborts the
//! whole attack and returns no tasks.
//!
//! v4.2.2 preset wiring: every suite now also picks a scan profile per
//! plugin following a depth preference list — `web` runs each plugin's
//! Quick/Light profile, `full` runs each plugin's Deep/Full profile,
//! `quick` the lightest, `internal` deep-then-standard. Plugins without
//! presets launch with their plain defaults. The preset is merged by
//! the standard admission pipeline (caller inputs still win), recorded
//! on the task (`options.preset`), and echoed in the attack response.

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
            "website-scanner",
            "param-finder",
            "js-analyzer",
            "nuclei",
            "whatweb",
            "nikto",
            "testssl",
            // v4.1.0: http-probe gives fast tech-stack fingerprint +
            // title/status; katana crawls the surface to discover
            // endpoints Sniper can pivot on.
            "http-probe",
            "crawler",
        ]),
        ("web", "ip_address") => Err(ApiError::BadRequest(
            "the `web` suite requires a hostname or URL target -- use `quick` or `internal` for IP targets".into(),
        )),
        ("full", "hostname" | "url") => Ok(vec![
            "http-recon",
            "http-headers",
            "dns-lookup",
            "website-scanner",
            "param-finder",
            "js-analyzer",
            "nuclei",
            "xss-scanner",
            "api-scanner",
            "whatweb",
            "nikto",
            "testssl",
            "subdomain-finder",
            "nmap",
            "wordpress-audit",
            "drupal-scanner",
            // v4.1.0 power engines -- pentest-tools.com has no
            // equivalent for any of these. (command-injection and
            // secrets-scanner are kept as standalone plugins because
            // they require a URL-with-parameter or filesystem-path
            // input the generic suite cannot supply.)
            "subdomain-takeover",
            "http-smuggling",
            "http-probe",
            "crawler",
        ]),
        ("full", "ip_address") => Ok(vec![
            "nmap",
            "fast-port-scan",
            "smb-enum",
            "ssh-audit",
            "service-defaults",
        ]),
        ("internal", "ip_address") => Ok(vec!["nmap", "smb-enum", "ssh-audit", "service-defaults"]),
        ("internal", "hostname" | "url") => Err(ApiError::BadRequest(
            "the `internal` suite requires an IP target -- use `full` for hostname targets".into(),
        )),
        _ => Err(ApiError::BadRequest(format!(
            "unknown suite `{suite}` (expected one of: quick, web, full, internal)"
        ))),
    }
}

/// v4.2.2: ordered profile-name preferences per suite. The first name
/// the plugin actually defines wins; plugins without any of these (or
/// without presets at all) launch with their plain defaults.
///
/// The lists encode the user-facing contract:
/// - `web` = Quick profiles (fastest safe preset each plugin offers)
/// - `full` = Deep profiles (deepest thorough preset that is not
///   explicitly hazardous — e.g. whatweb resolves to `aggressive`,
///   never `heavy`)
fn suite_preset_preferences(suite: &str) -> &'static [&'static str] {
    match suite {
        // Lightest tier: fast triage profiles.
        "quick" | "web" => &[
            "quick",
            "light",
            "fast",
            "passive",
            "shallow",
            "kev",
            "polite",
            "verified",
            "conservative",
            "standard",
        ],
        // Deepest thorough tier. `deep` first so plugins that offer it
        // never fall through to the slower extremes (`full-sweep`'s
        // 65,535-port nmap run, whatweb `heavy`'s greedy matching).
        "full" => &[
            "deep",
            "full",
            "exhaustive",
            "aggressive",
            "all-reflections",
            "heavy",
            "standard",
        ],
        // Internal-network deep dive.
        "internal" => &["deep", "standard", "quick"],
        _ => &[],
    }
}

/// Pick the profile a suite should run for a plugin, given the
/// plugin's declared presets. `None` when no preferred name matches
/// (the plugin then launches with its plain defaults).
fn pick_preset(presets: &BTreeMap<String, BTreeMap<String, Value>>, suite: &str) -> Option<String> {
    suite_preset_preferences(suite)
        .iter()
        .copied()
        .find(|name| presets.contains_key(*name))
        .map(|s| s.to_string())
}

/// Build the inputs map for a plugin against a target. Most plugins
/// accept `target` as a free-form string. URL targets pass through
/// unchanged; hostnames pass through; IPs pass through. Plugins whose
/// own validation rejects the value will fail at admission time, which
/// is the right behavior -- we don't second-guess plugin schemas here.
///
/// v4.2.2: the nmap top-1000 hint only fires when NO preset was picked
/// -- when a preset drives nmap, its own top_ports/service_detection
/// values apply (and explicit caller inputs would win over both).
fn inputs_for(plugin_id: &str, target: &str, preset: Option<&str>) -> BTreeMap<String, Value> {
    let mut m = BTreeMap::new();
    m.insert("target".to_string(), Value::String(target.to_string()));
    // Suite-level hints for plugins that accept them.
    if preset.is_none() && plugin_id == "nmap" {
        // v4.2.0: the equivalent of the "deep" profile -- top 1000
        // ports + service detection. (The old `ports: "top-1000"`
        // string failed the ports field pattern, so nmap was
        // silently skipped by the full suite.)
        m.insert("top_ports".to_string(), json!(1000));
        m.insert("service_detection".to_string(), json!(true));
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
    crate::access::require_workspace(
        &state,
        &user,
        &target.workspace_id,
        crate::access::WorkspacePermission::Write,
    )
    .await?;

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
    //
    // v4.2.2: we also resolve the suite's scan profile per plugin here
    // (web=Quick/Light, full=Deep/Full, ...) while the manifest is in
    // hand; plugins without a matching preset launch with plain defaults.
    let mut to_launch: Vec<(&str, Option<String>)> = Vec::new();
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
            let preset = pick_preset(&manifest.presets, &req.suite);
            to_launch.push((pid, preset));
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
    for (pid, preset) in to_launch {
        let inputs = inputs_for(pid, &target.name, preset.as_deref());
        let task_req = StartTaskRequest {
            plugin_id: pid.to_string(),
            inputs,
            preset: preset.clone(),
            consent_granted: true,
            workspace_id: Some(target.workspace_id.clone()),
            auth_profile_id: None,
        report_callback: None,
            max_scan_time_minutes: None,
};
        match validate_and_create_task(&state, &user, &task_req, None, None).await {
            Ok((row, manifest, inputs)) => {
                state.tasks.spawn(row.clone(), manifest, inputs).await;
                // Echo the suite-selected profile so the UI (and verify)
                // can show "this task ran the Deep profile" without a
                // follow-up GET. Null for plugins without presets.
                launched.push(json!({
                    "id": row.id,
                    "plugin_id": row.plugin_id,
                    "status": row.status,
                    "preset": preset,
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
    fn pick_suite_web_and_full_include_nuclei() {
        // v4.0.0: the 12k-template nuclei engine is a first-class suite
        // member; full also gets the dalfox XSS engine.
        let web = pick_suite("web", "url").unwrap();
        assert!(web.contains(&"nuclei"));
        assert!(!web.contains(&"xss-scanner"));
        let full = pick_suite("full", "hostname").unwrap();
        assert!(full.contains(&"nuclei"));
        assert!(full.contains(&"xss-scanner"));
    }

    #[test]
    fn pick_suite_web_includes_v410_recon_engines() {
        // v4.1.0: web suite gains http-probe + crawler.
        let web = pick_suite("web", "hostname").unwrap();
        assert!(
            web.contains(&"http-probe"),
            "web suite must include http-probe (v4.1.0)"
        );
        assert!(
            web.contains(&"crawler"),
            "web suite must include crawler (v4.1.0)"
        );
    }

    #[test]
    fn pick_suite_full_includes_v410_attack_engines() {
        // v4.1.0: full suite gains the attack engines pentest-tools.com
        // has no equivalent for. (command-injection and secrets-scanner
        // are kept as standalone plugins because they require inputs
        // the generic suite cannot supply.)
        let full = pick_suite("full", "url").unwrap();
        assert!(
            full.contains(&"subdomain-takeover"),
            "full suite must include subdomain-takeover"
        );
        assert!(
            full.contains(&"http-smuggling"),
            "full suite must include http-smuggling"
        );
        assert!(full.contains(&"http-probe"));
        assert!(full.contains(&"crawler"));
    }

    #[test]
    fn pick_suite_full_ip_includes_fast_port_scan() {
        // v4.1.0: IP full suite gains fast-port-scan (naabu) alongside nmap.
        let p = pick_suite("full", "ip_address").unwrap();
        assert_eq!(
            p,
            vec![
                "nmap",
                "fast-port-scan",
                "smb-enum",
                "ssh-audit",
                "service-defaults"
            ]
        );
    }

    #[test]
    fn pick_suite_unknown_rejected() {
        assert!(pick_suite("exhaustive", "hostname").is_err());
    }

    #[test]
    fn inputs_for_nmap_adds_top_1000_hint_when_no_preset() {
        // v4.2.0: the suite supplies top_ports=1000 + service detection
        // (valid field ids -- the previous ports="top-1000" string never
        // passed the ports field pattern). v4.2.2: only as a fallback --
        // when a preset drives nmap, the preset's own values apply.
        let m = inputs_for("nmap", "127.0.0.1", None);
        assert_eq!(m.get("top_ports").and_then(|v| v.as_i64()), Some(1000));
        assert_eq!(
            m.get("service_detection").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn inputs_for_nmap_skips_hint_when_preset_drives() {
        // v4.2.2: with the light/deep preset selected, the explicit
        // top-1000 hint must NOT be injected (it would otherwise override
        // the preset's own top_ports via the caller-wins merge rule).
        let m = inputs_for("nmap", "127.0.0.1", Some("light"));
        assert!(!m.contains_key("top_ports"));
        assert!(!m.contains_key("service_detection"));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn inputs_for_generic_plugin_just_target() {
        let m = inputs_for("http-headers", "example.com", None);
        assert_eq!(m.len(), 1);
        assert_eq!(
            m.get("target").and_then(|v| v.as_str()),
            Some("example.com")
        );
    }

    // ---- v4.2.2: suite -> scan-profile selection --------------------------------

    /// Build a presets map (values don't matter for selection).
    fn presets(names: &[&str]) -> BTreeMap<String, BTreeMap<String, Value>> {
        names
            .iter()
            .map(|n| (n.to_string(), BTreeMap::new()))
            .collect()
    }

    #[test]
    fn web_suite_picks_quick_profiles() {
        // The user-facing contract: web suite = Quick profiles.
        let http_headers = presets(&["quick", "full"]); // quick/full only
        assert_eq!(pick_preset(&http_headers, "web").as_deref(), Some("quick"));
        let nuclei = presets(&[
            "kev",
            "light",
            "cve",
            "exposures",
            "misconfig",
            "panels",
            "deep",
        ]);
        assert_eq!(pick_preset(&nuclei, "web").as_deref(), Some("light"));
        let whatweb = presets(&["passive", "polite", "aggressive", "heavy"]);
        assert_eq!(pick_preset(&whatweb, "web").as_deref(), Some("passive"));
        let xss = presets(&["verified", "all-reflections"]);
        assert_eq!(pick_preset(&xss, "web").as_deref(), Some("verified"));
    }

    #[test]
    fn full_suite_picks_deep_profiles() {
        // The user-facing contract: full suite = Deep profiles.
        let nmap = presets(&[
            "light",
            "deep",
            "full-sweep",
            "top-5000",
            "stealth",
            "vuln-scripts",
        ]);
        assert_eq!(pick_preset(&nmap, "full").as_deref(), Some("deep"));
        // ...and never the 65,535-port full-sweep (deep outranks it).
        assert_ne!(pick_preset(&nmap, "full").as_deref(), Some("full-sweep"));
        let website_scanner = presets(&["light", "deep"]);
        assert_eq!(
            pick_preset(&website_scanner, "full").as_deref(),
            Some("deep")
        );
        // http-headers has no `deep`; its deepest is `full`.
        let http_headers = presets(&["quick", "full"]);
        assert_eq!(pick_preset(&http_headers, "full").as_deref(), Some("full"));
        // subfinder's deepest is `exhaustive`.
        let subfinder = presets(&["light", "standard", "exhaustive"]);
        assert_eq!(
            pick_preset(&subfinder, "full").as_deref(),
            Some("exhaustive")
        );
        // xss-scanner's deepest is `all-reflections`.
        let xss = presets(&["verified", "all-reflections"]);
        assert_eq!(
            pick_preset(&xss, "full").as_deref(),
            Some("all-reflections")
        );
        // nikto only has quick/standard -> standard fallback.
        let nikto = presets(&["quick", "standard"]);
        assert_eq!(pick_preset(&nikto, "full").as_deref(), Some("standard"));
    }

    #[test]
    fn full_suite_avoids_hazardous_extremes() {
        // whatweb `heavy` (aggression 4) is the greedy-match extreme;
        // `aggressive` (3) must win in the full suite.
        let whatweb = presets(&["passive", "polite", "aggressive", "heavy"]);
        assert_eq!(pick_preset(&whatweb, "full").as_deref(), Some("aggressive"));
        // fast-port-scan has light/deep/full; `deep` (top-1000) must win
        // over `full` (all 65,535 ports) inside a suite -- full sweeps are
        // a standalone choice.
        let naabu = presets(&["light", "deep", "full"]);
        assert_eq!(pick_preset(&naabu, "full").as_deref(), Some("deep"));
    }

    #[test]
    fn quick_and_internal_suite_preferences() {
        let nmap = presets(&[
            "light",
            "deep",
            "full-sweep",
            "top-5000",
            "stealth",
            "vuln-scripts",
        ]);
        assert_eq!(pick_preset(&nmap, "quick").as_deref(), Some("light"));
        let smb = presets(&["quick", "standard", "deep"]);
        assert_eq!(pick_preset(&smb, "internal").as_deref(), Some("deep"));
        // quick resolves to the lightest tier as well.
        assert_eq!(pick_preset(&smb, "quick").as_deref(), Some("quick"));
    }

    #[test]
    fn plugins_without_matching_presets_get_none() {
        // http-recon / dns-lookup have no presets at all.
        assert_eq!(pick_preset(&presets(&[]), "full"), None);
        // A plugin whose presets are all outside the preference lists
        // (e.g. only `custom-x`) also gets None.
        assert_eq!(pick_preset(&presets(&["custom-x"]), "full"), None);
        // Unknown suite -> no preference list -> None.
        assert_eq!(pick_preset(&presets(&["deep"]), "bogus"), None);
    }
}
