//! Sniper Auto-Exploiter — finding → exploit-chain orchestrator.
//!
//! Given a finding, Sniper picks a chain of exploit steps tailored to the
//! finding's category, executes them as real scan tasks, and aggregates the
//! results into a proof. A chain is a list of (plugin_id, inputs-override)
//! steps run sequentially against the finding's target; the chain "proves"
//! the finding when any step produces a `validated_issue` finding.
//!
//! Chains are deliberately conservative: every exploit plugin already enforces
//! its own consent gate, and Sniper refuses to run against targets outside
//! the platform's global network policy (the same policy the task admission
//! pipeline enforces — Sniper reuses `validate_and_create_task` so a denied
//! target is denied here too).

use crate::routes::tasks::{validate_and_create_task, StartTaskRequest};
use crate::state::SharedState;
use secuscan_core::models::TaskStatus;
use secuscan_db::models::FindingRow;
use secuscan_db::repo;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Instant;

/// A single exploit step: which plugin to run and what inputs.
#[derive(Debug, Clone)]
pub struct SniperStep {
    pub label: &'static str,
    pub plugin_id: &'static str,
    /// Extra inputs merged over {target: <finding target>}.
    pub inputs: BTreeMap<String, Value>,
}

/// A chain for one finding category.
#[derive(Debug, Clone)]
pub struct SniperChain {
    pub category_match: &'static str,
    pub steps: Vec<SniperStep>,
}

fn step(label: &'static str, plugin_id: &'static str, kvs: &[(&str, Value)]) -> SniperStep {
    let mut inputs = BTreeMap::new();
    for (k, v) in kvs {
        inputs.insert(k.to_string(), v.clone());
    }
    SniperStep { label, plugin_id, inputs }
}

/// Build the chain catalog. Matched case-insensitively against the finding's
/// category (substring match, first hit wins).
pub fn chains() -> Vec<SniperChain> {
    vec![
        // --- SQL injection: full exploitation via SQLMap ---
        SniperChain {
            category_match: "SQL",
            steps: vec![
                step("Confirm injection point", "sqli-exploiter", &[
                    ("level", json!(3)),
                    ("risk", json!(2)),
                    ("techniques", json!("BEUST")),
                    ("current_user", json!(true)),
                    ("current_db", json!(true)),
                ]),
                step("Enumerate databases", "sqli-exploiter", &[
                    ("databases", json!(true)),
                    ("tables", json!(true)),
                ]),
                step("Extract credential hashes", "sqli-exploiter", &[
                    ("users", json!(true)),
                    ("passwords", json!(true)),
                ]),
            ],
        },
        // --- XSS: prove via OOB callback handler ---
        // NOTE (Sprint 1.1 task 1.6): the step carries its own `target` — the
        // HANDLER NAME. xss-exploiter's `target` field is a handler label
        // constrained to ^[a-zA-Z0-9][a-zA-Z0-9._-]*$, and the finding URL
        // (http://…) overwriting it used to break task admission, so the
        // XSS chain could never run. `@run:` expands to a run-scoped suffix
        // so each Sniper run gets a unique handler label.
        SniperChain {
            category_match: "XSS",
            steps: vec![
                step("Create XSS callback handler", "xss-exploiter", &[
                    ("target", json!("@run:sniper-xss")),
                    ("capture_cookies", json!(true)),
                    ("capture_html", json!(true)),
                    ("delivery_mode", json!("script_tag")),
                ]),
            ],
        },
        // --- Weak/default credentials ---
        SniperChain {
            category_match: "Credential",
            steps: vec![
                step("Default-credential audit", "password-audit", &[]),
            ],
        },
        SniperChain {
            category_match: "Auth",
            steps: vec![
                step("Default-credential audit", "password-audit", &[]),
            ],
        },
        SniperChain {
            category_match: "API",
            steps: vec![
                step("API scanner follow-up", "api-scanner", &[]),
            ],
        },
        SniperChain {
            category_match: "CORS",
            steps: vec![
                step("CORS policy re-check", "cors-check", &[]),
            ],
        },
        SniperChain {
            category_match: "CRLF",
            steps: vec![
                step("Website DAST refresh", "website-scanner", &[]),
            ],
        },
        SniperChain {
            category_match: "LFI",
            steps: vec![
                step("Website DAST refresh", "website-scanner", &[]),
            ],
        },
        SniperChain {
            category_match: "JWT",
            steps: vec![
                step("Website DAST refresh", "website-scanner", &[]),
            ],
        },
        SniperChain {
            category_match: "Web",
            steps: vec![
                step("Website DAST refresh", "website-scanner", &[]),
                step("Security header audit", "http-headers", &[]),
            ],
        },
        // --- WordPress: deep CMS-specific chain ---
        SniperChain {
            category_match: "WordPress",
            steps: vec![
                step("WordPress deep scan", "wordpress-audit", &[]),
            ],
        },
        // --- Drupal: CVE-focused chain ---
        SniperChain {
            category_match: "Drupal",
            steps: vec![
                step("Drupal CVE scan", "drupal-scanner", &[]),
            ],
        },
        // --- TLS: full config audit ---
        SniperChain {
            category_match: "TLS",
            steps: vec![
                step("Full TLS configuration audit", "testssl", &[]),
            ],
        },
        // --- Network services: NSE script sweep ---
        SniperChain {
            category_match: "Port",
            steps: vec![
                step("Service-version + script sweep", "nmap", &[
                    ("scan_type", json!("T")),
                ]),
            ],
        },
        // --- Vulnerability (nuclei template hits): deep re-verification.
        // The source finding already carries the template's severity +
        // proof; the chain re-runs nuclei focused on high/critical
        // matches, then refreshes the native DAST pass and header audit
        // for context around the vulnerable endpoint.
        SniperChain {
            category_match: "Vulnerability",
            steps: vec![
                step("Template re-verification (high/critical)", "nuclei", &[
                    ("severity", json!("high,critical")),
                ]),
                step("Website DAST refresh", "website-scanner", &[]),
                step("Security header audit", "http-headers", &[]),
            ],
        },
        // --- v4.1.0: Subdomain Takeover -- subzy re-verification.
        // The source finding already carries the takeover URL + service;
        // subzy re-runs focused on the same hostname to confirm the
        // dangling CNAME is still claimable. Then http-recon probes the
        // edge to fingerprint the actual NXDOMAIN/404 marker the SaaS
        // provider emits when the resource has been freed.
        SniperChain {
            category_match: "Subdomain Takeover",
            steps: vec![
                step("subzy re-verification", "subdomain-takeover", &[]),
                step("Edge fingerprint (http-recon)", "http-recon", &[]),
            ],
        },
        // --- v4.1.0: HTTP Request Smuggling -- smuggler re-verification.
        // The source finding carries the verified class (CL.TE / TE.CL /
        // TE.TE); smuggler re-runs in verbose mode against the same
        // endpoint to capture the exact desync payload, then a DAST pass
        // refreshes context around the affected endpoint.
        SniperChain {
            category_match: "Smuggling",
            steps: vec![
                step("smuggler re-verification (verbose)", "http-smuggling", &[]),
                step("Website DAST refresh", "website-scanner", &[]),
            ],
        },
        // --- v4.1.0: Command Injection -- commix verbose re-verification.
        // The source finding carries the verified parameter + technique;
        // commix re-runs in verbose mode to capture the exact payload
        // that achieved execution, then a DAST pass refreshes context.
        SniperChain {
            category_match: "Command Injection",
            steps: vec![
                step("commix verbose re-verification", "command-injection", &[
                    ("level", json!(2)),
                ]),
                step("Website DAST refresh", "website-scanner", &[]),
            ],
        },
        // --- v4.1.0: Secret Exposure -- gitleaks re-scan + JS analyser
        // follow-up. The source finding already carries the matched
        // secret + rule + path; gitleaks re-runs to confirm the secret
        // still resolves, and js-analyzer sweeps the affected host for
        // other JS-embedded secret patterns.
        SniperChain {
            category_match: "Secret",
            steps: vec![
                step("gitleaks re-verification", "secrets-scanner", &[]),
                step("JS secret-pattern sweep", "js-analyzer", &[]),
            ],
        },
        // --- Web (catch-all): headers + recon + fuzz ---
        SniperChain {
            category_match: "HTTP",
            steps: vec![
                step("HTTP recon refresh", "http-recon", &[]),
                step("Security header audit", "http-headers", &[]),
            ],
        },
    ]
}

/// Compute a step's final inputs (Max-Parity Sprint 1.1, task 1.6):
/// - step-defined values always win — the finding's target (URL, else the
///   task target) is injected only when the step doesn't provide its own;
/// - `@run:`-prefixed string values expand to `{rest}-{run_prefix}` so each
///   run gets unique, pattern-valid identifiers (handler names).
fn resolve_step_inputs(
    step_def: &SniperStep,
    finding_url: Option<&str>,
    task_target: Option<&str>,
    run_id: &str,
) -> Result<BTreeMap<String, Value>, String> {
    let mut inputs = step_def.inputs.clone();
    if !inputs.contains_key("target") {
        let target = finding_url
            .map(str::to_string)
            .or_else(|| task_target.map(str::to_string));
        match target {
            Some(t) => {
                inputs.insert("target".into(), json!(t));
            }
            None => return Err("finding has no target".into()),
        }
    }
    expand_run_sentinels(&mut inputs, run_id);
    Ok(inputs)
}

/// Expand `@run:`-prefixed string sentinels into run-scoped values.
fn expand_run_sentinels(inputs: &mut BTreeMap<String, Value>, run_id: &str) {
    let suffix: String = run_id
        .chars()
        .take(8)
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    for v in inputs.values_mut() {
        if let Some(rest) = v.as_str().and_then(|s| s.strip_prefix("@run:")) {
            *v = json!(format!("{rest}-{suffix}"));
        }
    }
}

/// Pick the chain for a finding category. Returns None when nothing matches.
pub fn pick_chain(category: &str) -> Option<SniperChain> {
    let cat = category.to_ascii_lowercase();
    chains().into_iter().find(|c| cat.contains(c.category_match.to_ascii_lowercase().as_str()))
}

/// Run the chain for a finding. Returns (outcome, proof_markdown).
pub async fn run_chain(
    state: &SharedState,
    user: &crate::auth::extractor::CurrentUser,
    finding: &FindingRow,
    run_id: &str,
    workspace_id: Option<&str>,
) -> Result<(String, String), String> {
    let chain = pick_chain(&finding.category)
        .ok_or_else(|| format!("no sniper chain for category `{}`", finding.category))?;

    let mut steps_state: Vec<Value> = Vec::new();
    let mut proofs: Vec<String> = Vec::new();
    let mut proven = false;
    // Task target fallback, resolved once (used when the finding has no URL).
    let task_target = finding_target(state, &finding.task_id).await;

    for (i, step_def) in chain.steps.iter().enumerate() {
        // Record step start.
        steps_state.push(json!({
            "step": i + 1,
            "label": step_def.label,
            "plugin_id": step_def.plugin_id,
            "status": "running",
            "task_id": Value::Null,
            "findings_count": 0,
        }));
        persist_state(state, run_id, &steps_state).await?;

        let inputs = match resolve_step_inputs(
            step_def,
            finding.url.as_deref(),
            task_target.as_deref(),
            run_id,
        ) {
            Ok(i) => i,
            Err(e) => {
                // One step being unrunnable (e.g. no target anywhere)
                // shouldn't abort the whole chain.
                steps_state.last_mut().unwrap()["status"] = json!("failed");
                steps_state.last_mut().unwrap()["error"] =
                    json!(format!("step {}: {e}", i + 1));
                persist_state(state, run_id, &steps_state).await?;
                continue;
            }
        };

        let req = StartTaskRequest {
            plugin_id: step_def.plugin_id.to_string(),
            inputs,
            preset: None,
            consent_granted: true,
            workspace_id: workspace_id.map(str::to_string),
            auth_profile_id: None,
        };
        let (task, manifest, normalized) = match validate_and_create_task(state, user, &req, None, None).await {
            Ok(t) => t,
            Err(e) => {
                // Mark step failed but continue the chain — one step failing
                // (e.g. missing binary) should not abort the whole run.
                steps_state.last_mut().unwrap()["status"] = json!("failed");
                steps_state.last_mut().unwrap()["error"] = json!(e.to_string());
                persist_state(state, run_id, &steps_state).await?;
                continue;
            }
        };
        let _ = repo::sniper::attach_task(&state.db, run_id, &task.id).await;
        steps_state.last_mut().unwrap()["task_id"] = json!(task.id);
        persist_state(state, run_id, &steps_state).await?;

        state.tasks.spawn(task.clone(), manifest, normalized).await;

        // Wait for terminal state.
        let deadline = Instant::now() + std::time::Duration::from_secs(3_600);
        let final_status = loop {
            let t = repo::tasks::get(&state.db, &task.id).await.map_err(|e| e.to_string())?;
            if t.status().is_terminal() {
                break t.status();
            }
            if Instant::now() >= deadline {
                state.tasks.cancel(&task.id).await;
                break TaskStatus::Failed;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        };

        // Collect step findings.
        let step_findings = repo::findings::list_all_for_task(&state.db, &task.id)
            .await
            .unwrap_or_default();
        let validated: Vec<&secuscan_db::models::FindingRow> = step_findings.iter()
            .filter(|f| f.kind == "validated_issue" || f.severity == "critical" || f.severity == "high")
            .collect();

        steps_state.last_mut().unwrap()["status"] = json!(final_status.label());
        steps_state.last_mut().unwrap()["findings_count"] = json!(step_findings.len());
        persist_state(state, run_id, &steps_state).await?;

        if !validated.is_empty() {
            proven = true;
            for f in &validated {
                proofs.push(format!(
                    "**[{}] {}** — {}\n\n```\n{}\n```",
                    f.severity, f.title, f.category, f.proof
                ));
            }
        }
    }

    let outcome = if proven { "proven" } else if !proofs.is_empty() { "inconclusive" } else { "not_proven" };
    let proof_md = if proofs.is_empty() {
        format!(
            "Sniper chain for category `{}` completed without producing validated findings. \
             The original finding stands as reported; manual exploitation is required to prove impact.",
            finding.category
        )
    } else {
        format!(
            "Sniper proven impact for finding `{}` ({}):\n\n{}",
            finding.title, finding.category, proofs.join("\n\n")
        )
    };
    Ok((outcome.to_string(), proof_md))
}

async fn persist_state(state: &SharedState, run_id: &str, steps_state: &[Value]) -> Result<(), String> {
    let state_json = serde_json::to_string(steps_state).unwrap_or_else(|_| "[]".into());
    repo::sniper::set_run_state(&state.db, run_id, &state_json)
        .await
        .map_err(|e| e.to_string())
}

async fn finding_target(state: &SharedState, task_id: &str) -> Option<String> {
    repo::tasks::get(&state.db, task_id).await.ok().and_then(|t| t.target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_chain_sql_matches_sqli() {
        let c = pick_chain("SQL Injection").unwrap();
        assert_eq!(c.category_match, "SQL");
        assert!(c.steps.len() >= 2);
    }

    #[test]
    fn pick_chain_xss_matches_xss() {
        let c = pick_chain("XSS Reflection").unwrap();
        assert_eq!(c.category_match, "XSS");
    }

    #[test]
    fn xss_chain_step_keeps_handler_name_not_finding_url() {
        // Sprint 1.1 task 1.6: the XSS chain step defines its own `target`
        // (the handler-name sentinel). run_chain must not overwrite it with
        // the finding URL, which fails the handler-name pattern.
        let c = pick_chain("XSS Reflection").unwrap();
        let step = &c.steps[0];
        assert_eq!(step.plugin_id, "xss-exploiter");
        assert_eq!(step.inputs.get("target"), Some(&json!("@run:sniper-xss")));
    }

    #[test]
    fn resolve_step_inputs_preserves_step_defined_target() {
        // Step with its own target: the finding URL must NOT win.
        let step = step("handler", "xss-exploiter", &[("target", json!("@run:sniper-xss"))]);
        let inputs = resolve_step_inputs(&step, Some("http://vuln.app/search?q=<x>"), Some("vuln.app"), "run-1234")
            .unwrap();
        assert!(inputs["target"].as_str().unwrap().starts_with("sniper-xss-"), "{:?}", inputs["target"]);
        assert!(!inputs["target"].as_str().unwrap().contains("://"));
    }

    #[test]
    fn resolve_step_inputs_injects_finding_url_when_step_has_no_target() {
        let step = step("recheck", "http-headers", &[]);
        let inputs = resolve_step_inputs(&step, Some("http://example.com/a"), None, "run-1").unwrap();
        assert_eq!(inputs["target"], json!("http://example.com/a"));
    }

    #[test]
    fn resolve_step_inputs_falls_back_to_task_target() {
        let step = step("recheck", "website-scanner", &[]);
        let inputs = resolve_step_inputs(&step, None, Some("example.com"), "run-1").unwrap();
        assert_eq!(inputs["target"], json!("example.com"));
    }

    #[test]
    fn resolve_step_inputs_errors_without_any_target() {
        let step = step("recheck", "website-scanner", &[]);
        assert!(resolve_step_inputs(&step, None, None, "run-1").is_err());
    }

    #[test]
    fn run_sentinels_expand_to_pattern_valid_handler_names() {
        let mut inputs = BTreeMap::new();
        inputs.insert("target".to_string(), json!("@run:sniper-xss"));
        inputs.insert("delivery_mode".to_string(), json!("script_tag"));
        expand_run_sentinels(&mut inputs, "a1b2c3d4-ef56-7890");
        let t = inputs["target"].as_str().unwrap();
        assert!(t.starts_with("sniper-xss-a1b2c3d4"), "{t}");
        // Must satisfy xss-exploiter's handler pattern ^[a-zA-Z0-9][a-zA-Z0-9._-]*$.
        assert!(t.chars().next().unwrap().is_ascii_alphanumeric());
        assert!(t.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_'));
        // Non-sentinel values pass through untouched.
        assert_eq!(inputs["delivery_mode"], json!("script_tag"));
    }

    #[test]
    fn pick_chain_falls_back_to_http() {
        let c = pick_chain("HTTP Security Headers").unwrap();
        assert_eq!(c.category_match, "HTTP");
    }

    #[test]
    fn pick_chain_web_and_api() {
        assert_eq!(pick_chain("Web").unwrap().category_match, "Web");
        assert_eq!(pick_chain("API specification").unwrap().category_match, "API");
        assert_eq!(pick_chain("Authentication").unwrap().category_match, "Auth");
        assert_eq!(pick_chain("CORS misconfiguration").unwrap().category_match, "CORS");
    }

    #[test]
    fn pick_chain_unknown_returns_none_when_no_match() {
        // "Zzz" matches nothing, and the catch-all is "HTTP", so None.
        assert!(pick_chain("Zzz Unknown Category").is_none());
    }

    #[test]
    fn pick_chain_vulnerability_runs_nuclei_dast_headers() {
        // v4.0.0: nuclei template hits (unmapped tags -> "Vulnerability")
        // get a deep re-verification chain.
        let c = pick_chain("Vulnerability").unwrap();
        assert_eq!(c.category_match, "Vulnerability");
        let ids: Vec<&str> = c.steps.iter().map(|s| s.plugin_id).collect();
        assert_eq!(ids, vec!["nuclei", "website-scanner", "http-headers"]);
        // The nuclei step focuses on high/critical severities.
        assert_eq!(c.steps[0].inputs.get("severity"), Some(&json!("high,critical")));
    }

    #[test]
    fn pick_chain_subdomain_takeover_runs_subzy_then_recon() {
        // v4.1.0: subdomain-takeover findings get subzy re-verification +
        // http-recon edge fingerprint.
        let c = pick_chain("Subdomain Takeover").unwrap();
        assert_eq!(c.category_match, "Subdomain Takeover");
        let ids: Vec<&str> = c.steps.iter().map(|s| s.plugin_id).collect();
        assert_eq!(ids, vec!["subdomain-takeover", "http-recon"]);
    }

    #[test]
    fn pick_chain_smuggling_runs_smuggler_then_dast() {
        // v4.1.0: request-smuggling findings get smuggler re-verification +
        // DAST refresh.
        let c = pick_chain("Request Smuggling").unwrap();
        assert_eq!(c.category_match, "Smuggling");
        let ids: Vec<&str> = c.steps.iter().map(|s| s.plugin_id).collect();
        assert_eq!(ids, vec!["http-smuggling", "website-scanner"]);
    }

    #[test]
    fn pick_chain_command_injection_runs_commix_then_dast() {
        // v4.1.0: command-injection findings get commix verbose re-verification +
        // DAST refresh. The commix step escalates level to 2.
        let c = pick_chain("Command Injection").unwrap();
        assert_eq!(c.category_match, "Command Injection");
        let ids: Vec<&str> = c.steps.iter().map(|s| s.plugin_id).collect();
        assert_eq!(ids, vec!["command-injection", "website-scanner"]);
        assert_eq!(c.steps[0].inputs.get("level"), Some(&json!(2)));
    }

    #[test]
    fn pick_chain_secret_exposure_runs_gitleaks_then_js_analyzer() {
        // v4.1.0: secret-exposure findings get gitleaks re-verification +
        // js-analyzer sweep.
        let c = pick_chain("Secret Exposure").unwrap();
        assert_eq!(c.category_match, "Secret");
        let ids: Vec<&str> = c.steps.iter().map(|s| s.plugin_id).collect();
        assert_eq!(ids, vec!["secrets-scanner", "js-analyzer"]);
    }

    #[test]
    fn all_chains_have_steps() {
        for c in chains() {
            assert!(!c.steps.is_empty(), "chain {} has no steps", c.category_match);
            for s in &c.steps {
                assert!(!s.plugin_id.is_empty());
            }
        }
    }
}
