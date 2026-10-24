//! Load the real `plugins/` tree the way the server does at boot.
//! Catches a broken TOML, a duplicate id, or a silently dropped plugin
//! before CI ever reaches the slower E2E job.

use secuscan_core::PluginRegistry;
use std::path::PathBuf;

fn plugins_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins")
}

/// Plugins the product surface (Attack-Target, Sniper, verify.mjs) names
/// by id. A rename here must update those call sites in the same PR.
const REQUIRED_IDS: &[&str] = &[
    "port-scanner",
    "http-headers",
    "http-recon",
    "website-scanner",
    "api-scanner",
    "param-finder",
    "js-analyzer",
    "feroxbuster",
    "people-hunter",
    "xss-exploiter",
    "xss-scanner",
    "nuclei",
    "smb-enum",
    "ssh-audit",
    "service-defaults",
    "subdomain-takeover",
    "http-probe",
    "crawler",
    "fast-port-scan",
    "http-smuggling",
    "command-injection",
    "secrets-scanner",
];

#[test]
fn shipped_catalog_loads_clean() {
    let dir = plugins_dir();
    assert!(dir.is_dir(), "plugins dir missing at {}", dir.display());

    let reg = PluginRegistry::load_dir(&dir);
    assert!(
        reg.issues().is_empty(),
        "plugin load issues: {:?}",
        reg.issues()
            .iter()
            .map(|i| format!("{}: {}", i.file, i.error))
            .collect::<Vec<_>>()
    );
    assert!(
        reg.len() >= 50,
        "catalog must ship >=50 plugins (got {})",
        reg.len()
    );

    for id in REQUIRED_IDS {
        assert!(
            reg.get(id).is_some(),
            "required plugin `{id}` missing from catalog"
        );
    }
}

#[test]
fn every_manifest_has_safety_and_unique_id() {
    let reg = PluginRegistry::load_dir(&plugins_dir());
    let mut seen = std::collections::BTreeSet::new();
    for p in reg.all() {
        assert!(
            seen.insert(p.plugin.id.clone()),
            "duplicate plugin id {}",
            p.plugin.id
        );
        assert!(
            !p.plugin.id.is_empty()
                && p.plugin
                    .id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "plugin id `{}` is not kebab-case",
            p.plugin.id
        );
        assert!(
            p.safety.max_concurrent >= 1,
            "{} max_concurrent must be >= 1",
            p.plugin.id
        );
        match p.safety.level {
            secuscan_core::SafetyLevel::Safe
            | secuscan_core::SafetyLevel::Intrusive
            | secuscan_core::SafetyLevel::Exploit => {}
        }
        if matches!(p.safety.level, secuscan_core::SafetyLevel::Exploit) {
            assert!(
                p.safety.requires_consent,
                "exploit plugin {} must require consent",
                p.plugin.id
            );
        }
    }
}

#[test]
fn native_plugins_declare_a_native_engine() {
    let reg = PluginRegistry::load_dir(&plugins_dir());
    let natives = [
        "port-scanner",
        "http-headers",
        "http-recon",
        "website-scanner",
        "api-scanner",
        "param-finder",
        "js-analyzer",
        "people-hunter",
        "xss-exploiter",
    ];
    for id in natives {
        let p = reg.get(id).unwrap_or_else(|| panic!("missing {id}"));
        match &p.engine {
            secuscan_core::EngineSpec::Native { native, .. } => {
                assert!(!native.is_empty(), "{id} native id empty");
            }
            other => panic!("{id} should be a native engine, got {other:?}"),
        }
    }
}
