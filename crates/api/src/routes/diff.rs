//! Scan diff: compare a completed task's findings against a baseline run
//! (the previous completed run of the same plugin + target by default) and
//! classify every finding as new / fixed / regressed / improved / unchanged.
//!
//! Fingerprint identity is (plugin_id, category, title): the same issue
//! found by the same plugin must produce the same title across runs —
//! which the declarative parser templates guarantee for deterministic
//! tools. Severity is compared separately so a severity change on the same
//! issue is reported as regressed/improved rather than fixed+new.

use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::routes::findings::finding_to_json;
use crate::routes::tasks::load_task_for_user;
use crate::state::SharedState;
use axum::extract::{Path, RawQuery, State};
use axum::Json;
use secuscan_db::models::{FindingRow, TaskRow};
use secuscan_db::repo;
use serde_json::{json, Value};
use std::collections::HashMap;

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new().route("/tasks/:id/diff", axum::routing::get(diff))
}

/// Identity of a finding across runs. The unit separator makes collisions
/// from concatenated field values impossible.
fn fingerprint(f: &FindingRow) -> String {
    format!("{}\u{1f}{}\u{1f}{}", f.plugin_id, f.category, f.title)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiffStatus {
    New,
    Fixed,
    Regressed,
    Improved,
    Unchanged,
}

impl DiffStatus {
    fn label(self) -> &'static str {
        match self {
            DiffStatus::New => "new",
            DiffStatus::Fixed => "fixed",
            DiffStatus::Regressed => "regressed",
            DiffStatus::Improved => "improved",
            DiffStatus::Unchanged => "unchanged",
        }
    }

    /// Display order: what needs attention first.
    fn rank(self) -> u8 {
        match self {
            DiffStatus::New => 0,
            DiffStatus::Regressed => 1,
            DiffStatus::Fixed => 2,
            DiffStatus::Improved => 3,
            DiffStatus::Unchanged => 4,
        }
    }
}

struct DiffItem {
    status: DiffStatus,
    /// Finding as seen in the current task (None for `fixed`).
    current: Option<FindingRow>,
    /// Finding as seen in the baseline task (None for `new`).
    previous: Option<FindingRow>,
}

fn compute_diff(current: &[FindingRow], previous: &[FindingRow]) -> Vec<DiffItem> {
    let prev_map: HashMap<String, &FindingRow> =
        previous.iter().map(|f| (fingerprint(f), f)).collect();
    let cur_map: HashMap<String, &FindingRow> =
        current.iter().map(|f| (fingerprint(f), f)).collect();

    let mut items = Vec::with_capacity(current.len() + prev_map.len());

    for f in current {
        let fp = fingerprint(f);
        let prev = prev_map.get(&fp);
        let status = match prev {
            None => DiffStatus::New,
            Some(p) => {
                let cur = f.severity() as i32;
                let old = p.severity() as i32;
                if cur > old {
                    DiffStatus::Regressed
                } else if cur < old {
                    DiffStatus::Improved
                } else {
                    DiffStatus::Unchanged
                }
            }
        };
        items.push(DiffItem {
            status,
            current: Some(f.clone()),
            previous: prev.cloned().cloned(),
        });
    }

    for f in previous {
        if !cur_map.contains_key(&fingerprint(f)) {
            items.push(DiffItem {
                status: DiffStatus::Fixed,
                current: None,
                previous: Some(f.clone()),
            });
        }
    }

    // Attention order first, then by the relevant finding's severity.
    items.sort_by(|a, b| {
        let ra = a.status.rank();
        let rb = b.status.rank();
        if ra != rb {
            return ra.cmp(&rb);
        }
        let sev_a = a
            .current
            .as_ref()
            .or(a.previous.as_ref())
            .map(|f| f.severity() as i32)
            .unwrap_or(0);
        let sev_b = b
            .current
            .as_ref()
            .or(b.previous.as_ref())
            .map(|f| f.severity() as i32)
            .unwrap_or(0);
        sev_b.cmp(&sev_a).then_with(|| {
            let t_a = a
                .current
                .as_ref()
                .or(a.previous.as_ref())
                .map(|f| f.title.clone())
                .unwrap_or_default();
            let t_b = b
                .current
                .as_ref()
                .or(b.previous.as_ref())
                .map(|f| f.title.clone())
                .unwrap_or_default();
            t_a.cmp(&t_b)
        })
    });
    items
}

fn diff_item_to_json(item: &DiffItem) -> Value {
    let mut v = json!({ "status": item.status.label() });
    if let Some(f) = &item.current {
        v["finding"] = finding_to_json(f);
    }
    if let Some(f) = &item.previous {
        v["previous_finding"] = finding_to_json(f);
        if item.current.is_some() {
            v["previous_severity"] = json!(f.severity);
        }
    }
    v
}

fn baseline_json(t: &TaskRow) -> Value {
    json!({
        "id": t.id,
        "created_at": t.created_at,
        "finished_at": t.finished_at,
        "plugin_id": t.plugin_id,
        "plugin_name": t.plugin_name,
        "target": t.target,
        "status": t.status,
    })
}

#[derive(Default)]
struct DiffQuery {
    against: Option<String>,
}

impl DiffQuery {
    fn parse(raw: Option<&str>) -> Self {
        let mut q = DiffQuery::default();
        if let Some(raw) = raw {
            for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
                if k == "against" {
                    q.against = Some(v.to_string());
                }
            }
        }
        q
    }
}

async fn diff(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<Value>> {
    let q = DiffQuery::parse(raw.as_deref());
    let task = load_task_for_user(&state, &user, &id).await?;

    // Findings are persisted at completion; diffing a non-completed task
    // would report everything as "fixed".
    if task.status() != secuscan_core::models::TaskStatus::Completed {
        return Err(ApiError::BadRequest(
            "diff requires a completed task (findings are only recorded at completion)".into(),
        ));
    }

    // Baseline: explicit (`?against=`) or auto-picked.
    let baseline = match q.against.as_deref() {
        Some(other_id) => {
            let b = load_task_for_user(&state, &user, other_id).await?;
            if b.status() != secuscan_core::models::TaskStatus::Completed {
                return Err(ApiError::BadRequest(
                    "the baseline task (`against`) must also be completed".into(),
                ));
            }
            b
        }
        None => {
            let scope = if user.is_admin() {
                None
            } else {
                Some(user.0.id.as_str())
            };
            repo::tasks::find_previous_run(
                &state.db,
                scope,
                &task.plugin_id,
                task.target.as_deref(),
                &task.created_at,
                &task.id,
                task.workspace_id.as_deref(),
            )
            .await?
            .ok_or_else(|| {
                ApiError::NotFound(format!(
                    "no earlier completed run of `{}` against `{}` to diff against; \
                     pass ?against=<task_id> to compare with a specific run",
                    task.plugin_id,
                    task.target.as_deref().unwrap_or("(no target)")
                ))
            })?
        }
    };
    // The baseline can become inaccessible if membership was revoked
    // between candidate selection and loading the evidence. Re-check now.
    let baseline = load_task_for_user(&state, &user, &baseline.id).await?;

    let current_findings = repo::findings::list_all_for_task(&state.db, &task.id).await?;
    let previous_findings = repo::findings::list_all_for_task(&state.db, &baseline.id).await?;
    let items = compute_diff(&current_findings, &previous_findings);

    let mut summary = HashMap::new();
    for it in &items {
        *summary.entry(it.status.label()).or_insert(0i64) += 1;
    }

    Ok(Json(json!({
        "task": {
            "id": task.id,
            "plugin_id": task.plugin_id,
            "plugin_name": task.plugin_name,
            "target": task.target,
            "status": task.status,
            "created_at": task.created_at,
        },
        "baseline": baseline_json(&baseline),
        "auto_baseline": q.against.is_none(),
        "summary": {
            "new": summary.get("new").copied().unwrap_or(0),
            "fixed": summary.get("fixed").copied().unwrap_or(0),
            "regressed": summary.get("regressed").copied().unwrap_or(0),
            "improved": summary.get("improved").copied().unwrap_or(0),
            "unchanged": summary.get("unchanged").copied().unwrap_or(0),
        },
        "items": items.iter().map(diff_item_to_json).collect::<Vec<_>>(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secuscan_core::models::{FindingKind, Severity};

    fn row(id: &str, plugin: &str, category: &str, title: &str, severity: Severity) -> FindingRow {
        FindingRow {
            id: id.to_string(),
            task_id: "t".into(),
            plugin_id: plugin.into(),
            severity: severity.label().into(),
            kind: FindingKind::Observation.label().into(),
            analyst_status: "new".into(),
            category: category.into(),
            title: title.into(),
            description: String::new(),
            remediation: String::new(),
            proof: String::new(),
            url: None,
            metadata_json: "{}".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            group_id: None,
            cve: None,
            cvss_v3: None,
            cvss_vector: None,
            epss_score: None,
            epss_percentile: None,
            cisa_kev: 0,
            cwe: None,
            owasp: None,
            confidence: None,
        }
    }

    #[test]
    fn diff_classifies_all_five_statuses() {
        let prev = vec![
            row("1", "p", "Cat", "Gone", Severity::Critical), // fixed
            row("2", "p", "Cat", "Worse", Severity::High),    // regressed (high -> critical)
            row("3", "p", "Cat", "Same", Severity::Medium),   // unchanged
            row("4", "p", "Cat", "Better", Severity::Critical), // improved (critical -> low)
        ];
        let cur = vec![
            row("5", "p", "Cat", "Worse", Severity::Critical),
            row("6", "p", "Cat", "Brand new", Severity::Low),
            row("7", "p", "Cat", "Same", Severity::Medium),
            row("8", "p", "Cat", "Better", Severity::Low),
        ];
        let items = compute_diff(&cur, &prev);
        let by_title = |t: &str| {
            items
                .iter()
                .find(|i| {
                    i.current
                        .as_ref()
                        .or(i.previous.as_ref())
                        .map(|f| f.title == t)
                        .unwrap_or(false)
                })
                .unwrap()
                .status
        };
        assert_eq!(by_title("Gone"), DiffStatus::Fixed);
        assert_eq!(by_title("Worse"), DiffStatus::Regressed);
        assert_eq!(by_title("Same"), DiffStatus::Unchanged);
        assert_eq!(by_title("Better"), DiffStatus::Improved);
        assert_eq!(by_title("Brand new"), DiffStatus::New);
        // Attention order: new first, unchanged last.
        assert_eq!(items.first().unwrap().status, DiffStatus::New);
        assert_eq!(items.last().unwrap().status, DiffStatus::Unchanged);
    }

    #[test]
    fn diff_empty_sides() {
        // Everything fixed…
        let items = compute_diff(&[], &[row("1", "p", "C", "T", Severity::Info)]);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].status, DiffStatus::Fixed);
        // …and everything new.
        let items = compute_diff(&[row("1", "p", "C", "T", Severity::Info)], &[]);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].status, DiffStatus::New);
    }

    #[test]
    fn diff_separates_same_title_across_categories_and_plugins() {
        let prev = vec![row("1", "p1", "CatA", "T", Severity::High)];
        let cur = vec![row("2", "p1", "CatB", "T", Severity::High)];
        let items = compute_diff(&cur, &prev);
        // Different category => different fingerprint => new + fixed, not unchanged.
        assert_eq!(items.len(), 2);
    }
}
