//! Per-plugin execution limits: bounded concurrency and a sliding-window
//! hourly cap, both driven by the manifest `[safety]` block.

use secuscan_core::manifest::{EngineSpec, PluginManifest};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::OwnedSemaphorePermit;

/// Decision returned by [`PluginLimiter::acquire`].
#[derive(Debug)]
pub enum LimitVerdict {
    /// A permit was acquired; hold it for the duration of the task.
    Acquired(OwnedSemaphorePermit),
    /// The task must be refused before it starts.
    Rejected { reason: String },
}

#[derive(Default)]
pub struct PluginLimiter {
    semaphores: Mutex<HashMap<String, std::sync::Arc<tokio::sync::Semaphore>>>,
    hourly: Mutex<HashMap<String, std::collections::VecDeque<Instant>>>,
}

/// Window length for `max_per_hour`.
const WINDOW: Duration = Duration::from_secs(3600);

impl PluginLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to start one task of this plugin. Awaits a concurrency slot when
    /// the plugin is at its limit; rejects outright when the hourly cap is
    /// exhausted. The hourly slot is reserved *before* waiting for a
    /// concurrency slot, so a queued task cannot bypass the cap.
    pub async fn acquire(self: &std::sync::Arc<Self>, plugin: &PluginManifest) -> LimitVerdict {
        let max_concurrent = plugin.safety.max_concurrent.max(1);
        let max_per_hour = plugin.safety.max_per_hour;

        // 1) hourly sliding window (reserve a slot).
        {
            let mut hourly = self.hourly.lock().expect("limiter lock");
            let q = hourly.entry(plugin.plugin.id.clone()).or_default();
            let now = Instant::now();
            while let Some(front) = q.front() {
                if now.duration_since(*front) >= WINDOW {
                    q.pop_front();
                } else {
                    break;
                }
            }
            if max_per_hour > 0 && q.len() >= max_per_hour {
                return LimitVerdict::Rejected {
                    reason: format!(
                        "plugin `{}` has reached its hourly limit of {max_per_hour} task(s) — \
                         try again later",
                        plugin.plugin.id
                    ),
                };
            }
            q.push_back(now);
        }

        // 2) concurrency slot.
        let sem = {
            let mut sems = self.semaphores.lock().expect("limiter lock");
            sems.entry(plugin.plugin.id.clone())
                .or_insert_with(|| {
                    std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent))
                })
                .clone()
        };
        match sem.acquire_owned().await {
            Ok(permit) => LimitVerdict::Acquired(permit),
            Err(_) => LimitVerdict::Rejected {
                reason: "plugin limiter closed".to_string(),
            },
        }
    }

    /// Number of tasks started (reserved) for a plugin in the current window.
    pub fn started_in_window(&self, plugin_id: &str) -> usize {
        let mut hourly = self.hourly.lock().expect("limiter lock");
        let Some(q) = hourly.get_mut(plugin_id) else {
            return 0;
        };
        let now = Instant::now();
        while let Some(front) = q.front() {
            if now.duration_since(*front) >= WINDOW {
                q.pop_front();
            } else {
                break;
            }
        }
        q.len()
    }

    /// Release an hourly reservation when a task never actually started
    /// (e.g. cancelled while queued). Best-effort.
    pub fn release_hourly(&self, plugin_id: &str) {
        let mut hourly = self.hourly.lock().expect("limiter lock");
        if let Some(q) = hourly.get_mut(plugin_id) {
            // remove the most recent reservation
            q.pop_back();
        }
    }

    /// Default timeout for a plugin's engine (helper for callers).
    pub fn engine_timeout(plugin: &PluginManifest) -> Duration {
        Duration::from_secs(match &plugin.engine {
            EngineSpec::Cli { timeout_seconds, .. } | EngineSpec::Native { timeout_seconds, .. } => {
                *timeout_seconds
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secuscan_core::manifest::{
        DepsSpec, EngineSpec, FieldSpec, FieldType, ParserSpec, PluginManifest, PluginMeta,
        SafetyLevel, SafetySpec,
    };
    use std::collections::BTreeMap;

    fn plugin(id: &str, max_concurrent: usize, max_per_hour: usize) -> PluginManifest {
        PluginManifest {
            plugin: PluginMeta {
                id: id.into(),
                name: id.into(),
                version: "1".into(),
                description: "d".into(),
                long_description: None,
                category: "test".into(),
                author: None,
                license: None,
                icon: None,
                difficulty: None,
                tags: vec![],
            },
            engine: EngineSpec::Native {
                native: "port_scanner".into(),
                timeout_seconds: 30,
            },
            fields: vec![FieldSpec {
                id: "target".into(),
                label: "Target".into(),
                ftype: FieldType::String,
                required: true,
                default: None,
                placeholder: None,
                help: None,
                pattern: None,
                message: None,
                options: vec![],
                min: None,
                max: None,
                allow_dash: false,
            }],
            presets: BTreeMap::new(),
            parser: ParserSpec::Passthrough,
            static_rules: vec![],
            safety: SafetySpec {
                level: SafetyLevel::Safe,
                requires_consent: true,
                consent_message: None,
                allowed_targets: vec![],
                max_concurrent,
                max_per_hour,
                capabilities: vec![],
            },
            dependencies: DepsSpec::default(),
            available: true,
            missing_binaries: vec![],
            source: Default::default(),
        }
    }

    #[tokio::test]
    async fn concurrency_blocks_at_limit() {
        let limiter = std::sync::Arc::new(PluginLimiter::new());
        let p = plugin("t", 1, 0);
        let a = limiter.acquire(&p).await;
        assert!(matches!(a, LimitVerdict::Acquired(_)));
        // Second acquire must wait — verify via timeout.
        let l2 = limiter.clone();
        let p2 = plugin("t", 1, 0);
        let attempt = tokio::time::timeout(Duration::from_millis(100), l2.acquire(&p2)).await;
        assert!(attempt.is_err(), "second acquire should be pending");
        // After releasing (dropping) the permit it goes through.
        drop(a);
        let b = tokio::time::timeout(Duration::from_secs(2), limiter.acquire(&p)).await;
        assert!(matches!(b, Ok(LimitVerdict::Acquired(_))));
    }

    #[tokio::test]
    async fn hourly_cap_rejects() {
        let limiter = std::sync::Arc::new(PluginLimiter::new());
        let p = plugin("h", 4, 2);
        assert!(matches!(limiter.acquire(&p).await, LimitVerdict::Acquired(_)));
        assert!(matches!(limiter.acquire(&p).await, LimitVerdict::Acquired(_)));
        match limiter.acquire(&p).await {
            LimitVerdict::Rejected { reason } => assert!(reason.contains("hourly limit")),
            other => panic!("expected rejection, got {other:?}",),
        }
        assert_eq!(limiter.started_in_window("h"), 2);
        limiter.release_hourly("h");
        assert_eq!(limiter.started_in_window("h"), 1);
        assert!(matches!(limiter.acquire(&p).await, LimitVerdict::Acquired(_)));
    }

    #[tokio::test]
    async fn zero_means_unlimited() {
        let limiter = std::sync::Arc::new(PluginLimiter::new());
        let p = plugin("u", 64, 0);
        for _ in 0..10 {
            assert!(matches!(limiter.acquire(&p).await, LimitVerdict::Acquired(_)));
        }
    }
}
