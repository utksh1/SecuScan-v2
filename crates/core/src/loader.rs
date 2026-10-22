//! Plugin registry: loads and validates every `plugins/*.toml` manifest at
//! startup, checks binary availability, and answers id lookups.

use crate::error::{CoreError, CoreResult};
use crate::manifest::PluginManifest;
use crate::validate::validate_manifest;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A problem detected while loading one manifest file. Invalid manifests are
/// skipped (not fatal) but every issue is surfaced to the operator and API.
#[derive(Debug, Clone)]
pub struct LoadIssue {
    pub file: String,
    pub plugin_id: Option<String>,
    pub error: String,
}

/// The loaded, validated plugin catalogue.
#[derive(Debug, Clone, Default)]
pub struct PluginRegistry {
    plugins: Vec<PluginManifest>,
    by_id: HashMap<String, usize>,
    issues: Vec<LoadIssue>,
}

impl PluginRegistry {
    /// Load every `*.toml` file under `dir`. Non-existent dir yields an empty
    /// registry with an issue (so misconfiguration is visible, not silent).
    pub fn load_dir(dir: &Path) -> Self {
        let mut registry = PluginRegistry::default();
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                registry.issues.push(LoadIssue {
                    file: dir.display().to_string(),
                    plugin_id: None,
                    error: format!("cannot read plugins directory: {e}"),
                });
                return registry;
            }
        };

        let mut files: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().is_some_and(|e| e == "toml"))
            .collect();
        files.sort(); // deterministic load order

        for path in files {
            match Self::load_one(&path) {
                Ok(mut manifest) => {
                    let id = manifest.plugin.id.clone();
                    let errs = validate_manifest(&manifest);
                    if !errs.is_empty() {
                        registry.issues.push(LoadIssue {
                            file: path.display().to_string(),
                            plugin_id: Some(id),
                            error: errs.join("; "),
                        });
                        continue;
                    }
                    // binary availability
                    let missing = missing_binaries(&manifest);
                    manifest.available = missing.is_empty();
                    manifest.missing_binaries = missing;
                    manifest.source = path.clone();
                    if registry.by_id.contains_key(&id) {
                        registry.issues.push(LoadIssue {
                            file: path.display().to_string(),
                            plugin_id: Some(id),
                            error: "duplicate plugin id (first occurrence wins)".into(),
                        });
                        continue;
                    }
                    registry.by_id.insert(id, registry.plugins.len());
                    registry.plugins.push(manifest);
                }
                Err(e) => registry.issues.push(LoadIssue {
                    file: path.display().to_string(),
                    plugin_id: None,
                    error: e.to_string(),
                }),
            }
        }
        registry
    }

    fn load_one(path: &Path) -> CoreResult<PluginManifest> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| CoreError::Load(format!("cannot read {}: {e}", path.display())))?;
        let manifest: PluginManifest =
            toml::from_str(&raw).map_err(|e| CoreError::Load(format!("TOML parse error: {e}")))?;
        Ok(manifest)
    }

    pub fn get(&self, id: &str) -> Option<&PluginManifest> {
        self.by_id.get(id).map(|i| &self.plugins[*i])
    }

    pub fn all(&self) -> &[PluginManifest] {
        &self.plugins
    }

    pub fn issues(&self) -> &[LoadIssue] {
        &self.issues
    }

    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Re-check binary availability in place (called by the admin refresh
    /// endpoint after tools are installed).
    pub fn refresh_availability(&mut self) {
        for p in &mut self.plugins {
            let missing = missing_binaries(p);
            p.available = missing.is_empty();
            p.missing_binaries = missing;
        }
    }
}

fn missing_binaries(m: &PluginManifest) -> Vec<String> {
    let mut names: Vec<String> = m.dependencies.binaries.clone();
    if let crate::manifest::EngineSpec::Cli { binary, .. } = &m.engine {
        names.push(binary.clone());
    }
    names.retain(|b| !b.is_empty());
    names.sort();
    names.dedup();
    names.into_iter().filter(|b| !binary_available(b)).collect()
}

/// Check whether an executable is resolvable on PATH (POSIX semantics).
pub fn binary_available(name: &str) -> bool {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains('\0') {
        // Absolute/relative paths are not supported for plugin binaries by
        // design; anything path-like is refused.
        return false;
    }
    let Ok(path_var) = std::env::var("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return true;
        }
    }
    false
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(p) {
        Ok(md) => md.is_file() && md.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    // Best-effort on non-POSIX: also accept `.exe` siblings.
    p.is_file() || p.with_extension("exe").is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
[plugin]
id = "demo"
name = "Demo"
version = "1.0.0"
description = "demo plugin"
category = "network"

[engine]
type = "cli"
binary = "cat"
argv = ["cat", "{file}"]
timeout_seconds = 30

[[fields]]
id = "target"
label = "Target"
type = "string"
required = true

[[fields]]
id = "file"
label = "File"
type = "string"

[parser]
type = "passthrough"

[safety]
level = "safe"
allowed_targets = ["127.0.0.1"]
"#;

    fn write(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    #[test]
    fn loads_valid_manifest_and_checks_binaries() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "demo.toml", VALID);
        let reg = PluginRegistry::load_dir(tmp.path());
        assert!(reg.issues().is_empty(), "{:?}", reg.issues());
        assert_eq!(reg.len(), 1);
        let p = reg.get("demo").unwrap();
        assert!(p.available, "cat should be on PATH");
        assert_eq!(p.missing_binaries.len(), 0);
    }

    #[test]
    fn invalid_manifest_is_skipped_with_issue() {
        let tmp = tempfile::tempdir().unwrap();
        // references unknown field in argv → cross-validation error
        let bad = VALID.replacen("\"cat\", \"{file}\"", "\"cat\", \"{nonexistent}\"", 1);
        write(tmp.path(), "bad.toml", &bad);
        let reg = PluginRegistry::load_dir(tmp.path());
        assert_eq!(reg.len(), 0);
        assert_eq!(reg.issues().len(), 1);
        assert!(reg.issues()[0].error.contains("nonexistent"));
    }

    #[test]
    fn duplicate_ids_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "a.toml", VALID);
        write(tmp.path(), "b.toml", VALID);
        let reg = PluginRegistry::load_dir(tmp.path());
        assert_eq!(reg.len(), 1);
        assert!(reg.issues().iter().any(|i| i.error.contains("duplicate")));
    }

    #[test]
    fn missing_binary_marks_unavailable() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = VALID
            .replace(
                "binary = \"cat\"",
                "binary = \"definitely-not-a-real-tool-xyz\"",
            )
            .replace(
                "argv = [\"cat\", \"{file}\"]",
                "argv = [\"definitely-not-a-real-tool-xyz\", \"{file}\"]",
            );
        write(tmp.path(), "demo.toml", &missing);
        let reg = PluginRegistry::load_dir(tmp.path());
        assert!(reg.issues().is_empty(), "{:?}", reg.issues());
        let p = reg.get("demo").unwrap();
        assert!(!p.available);
        assert_eq!(p.missing_binaries, vec!["definitely-not-a-real-tool-xyz"]);
    }

    #[test]
    fn missing_dir_is_reported_not_fatal() {
        let reg = PluginRegistry::load_dir(Path::new("/nonexistent/plugins-dir"));
        assert!(reg.is_empty());
        assert_eq!(reg.issues().len(), 1);
    }

    #[test]
    fn path_like_binary_names_refused() {
        assert!(!binary_available("/bin/cat"));
        assert!(!binary_available("../cat"));
        assert!(!binary_available(""));
    }

    #[test]
    fn non_toml_files_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "notes.txt", "hello");
        let reg = PluginRegistry::load_dir(tmp.path());
        assert!(reg.is_empty());
        assert!(reg.issues().is_empty());
    }
}
