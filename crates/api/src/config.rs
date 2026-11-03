//! Environment-driven server configuration.

use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Config {
    pub addr: SocketAddr,
    pub db_url: String,
    pub jwt_secret: String,
    pub plugins_dir: std::path::PathBuf,
    /// Built frontend bundle served as the SPA.
    pub frontend_dir: std::path::PathBuf,
    pub data_dir: std::path::PathBuf,
    /// Where async report-job artifacts are written.
    pub reports_dir: std::path::PathBuf,
    pub admin_email: String,
    pub admin_password: Option<String>,
    /// Capabilities that no plugin may require (e.g. `docker,cloud`).
    pub denied_capabilities: Vec<String>,
    pub allow_register: bool,
    /// Optional CORS origin (e.g. `http://localhost:5173` for split dev).
    pub cors_origin: Option<String>,
    /// Set the Secure attribute on auth cookies (enable when serving HTTPS).
    pub cookie_secure: bool,
    /// Global cap on simultaneously *running* tasks.
    pub max_concurrent_tasks: usize,
    /// How often the recurring-scan scheduler wakes to process due
    /// schedules (seconds).
    pub schedule_tick_secs: u64,
    /// Phase 0 (Max-Parity Plan) — provider-agnostic LLM endpoint. Parsed
    /// now, consumed by the Phase 3 AI layer (enrichment, classifier,
    /// Mini-Specter). Unused until then.
    pub ai_base_url: Option<String>,
    /// Phase 0 — API key for the LLM endpoint. Never logged.
    pub ai_api_key: Option<String>,
    /// Optional explicit at-rest encryption key; when unset a key file is
    /// generated under `data_dir` (see `secuscan_core::crypto`).
    pub enc_key: Option<String>,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// Secure startup is the default. Only an explicitly selected development
/// environment may create an ephemeral JWT key, and only on loopback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Environment {
    Production,
    Development,
}

impl Environment {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "production" => Ok(Self::Production),
            "development" => Ok(Self::Development),
            _ => Err("SECUSCAN_ENV must be 'production' or 'development'".to_string()),
        }
    }
}

/// A 64-character hex key carries 32 bytes when generated randomly.
/// Format checks cannot establish entropy; reject obvious low-diversity
/// patterns and require operators to use a cryptographic generator.
fn validate_jwt_secret(secret: &str) -> Result<(), String> {
    let invalid = "SECUSCAN_JWT_SECRET must be a persistent, randomly generated \
64-character hex value (32 bytes); run 'openssl rand -hex 32'";

    if secret.len() != 64 || !secret.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid.to_string());
    }

    let decoded = hex::decode(secret).map_err(|_| invalid.to_string())?;
    let distinct: std::collections::HashSet<u8> = decoded.iter().copied().collect();
    // Reject conspicuous patterns that a simple distinct-byte count misses,
    // e.g. 0123456789abcdef repeated or byte sequences 00..1f.
    // No content-only check can prove a secret came from a CSPRNG.
    let periodic = (1..=decoded.len() / 2).any(|period| {
        decoded.len() % period == 0
            && decoded
                .iter()
                .enumerate()
                .all(|(index, byte)| *byte == decoded[index % period])
    });
    let ascending = decoded
        .windows(2)
        .all(|pair| pair[0].wrapping_add(1) == pair[1]);
    let descending = decoded
        .windows(2)
        .all(|pair| pair[0].wrapping_sub(1) == pair[1]);
    if distinct.len() < 8 || periodic || ascending || descending {
        return Err(format!(
            "{invalid}; low-diversity, repeated, or sequential keys are rejected"
        ));
    }
    Ok(())
}

fn resolve_jwt_secret(
    configured: Option<&str>,
    environment: Environment,
    addr: SocketAddr,
) -> Result<String, String> {
    if let Some(secret) = configured.filter(|value| !value.is_empty()) {
        validate_jwt_secret(secret)?;
        return Ok(secret.to_string());
    }

    if environment == Environment::Production {
        return Err(
            "SECUSCAN_JWT_SECRET is required in production. Generate one with \
'openssl rand -hex 32' and persist it securely across restarts"
                .to_string(),
        );
    }
    if !addr.ip().is_loopback() {
        return Err(
            "SECUSCAN_ENV=development without a JWT secret is only allowed on a \
loopback SECUSCAN_ADDR; configure a strong secret for network access"
                .to_string(),
        );
    }

    tracing::warn!(
        "SECUSCAN_ENV=development: SECUSCAN_JWT_SECRET is unset; using an ephemeral \
signing key. Sessions will be invalidated on restart"
    );
    Ok(secuscan_db::generate_token("jwtsecret"))
}

impl Config {
    pub fn from_env() -> Result<Config, String> {
        let addr: SocketAddr = env_or("SECUSCAN_ADDR", "0.0.0.0:8080")
            .parse()
            .map_err(|_| "SECUSCAN_ADDR must be a valid socket address".to_string())?;
        let environment = Environment::parse(&env_or("SECUSCAN_ENV", "production"))?;
        let data_dir = std::path::PathBuf::from(env_or("SECUSCAN_DATA_DIR", "./data"));
        let reports_dir = std::env::var("SECUSCAN_REPORTS_DIR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| data_dir.join("reports"));
        let db_url = env_or(
            "SECUSCAN_DB_URL",
            &format!(
                "sqlite://{}?mode=rwc",
                data_dir.join("secuscan.db").display()
            ),
        );
        let configured_secret = std::env::var("SECUSCAN_JWT_SECRET").ok();
        let jwt_secret = resolve_jwt_secret(configured_secret.as_deref(), environment, addr)?;

        Ok(Config {
            addr,
            db_url,
            jwt_secret,
            plugins_dir: std::path::PathBuf::from(env_or("SECUSCAN_PLUGINS_DIR", "./plugins")),
            frontend_dir: std::path::PathBuf::from(env_or(
                "SECUSCAN_FRONTEND_DIR",
                "./frontend/dist",
            )),
            data_dir,
            reports_dir,
            admin_email: env_or("SECUSCAN_ADMIN_EMAIL", "admin@secuscan.local"),
            admin_password: std::env::var("SECUSCAN_ADMIN_PASSWORD")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            denied_capabilities: std::env::var("SECUSCAN_DENIED_CAPABILITIES")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            allow_register: env_or("SECUSCAN_ALLOW_REGISTER", "false") == "true",
            cors_origin: std::env::var("SECUSCAN_CORS_ORIGIN")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            cookie_secure: env_or("SECUSCAN_COOKIE_SECURE", "false") == "true",
            max_concurrent_tasks: env_or("SECUSCAN_MAX_CONCURRENT_TASKS", "8")
                .parse()
                .unwrap_or(8),
            schedule_tick_secs: env_or("SECUSCAN_SCHEDULE_TICK_SECS", "30")
                .parse()
                .unwrap_or(30),
            ai_base_url: std::env::var("SECUSCAN_AI_BASE_URL")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            ai_api_key: std::env::var("SECUSCAN_AI_API_KEY")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            enc_key: std::env::var("SECUSCAN_ENC_KEY")
                .ok()
                .filter(|s| !s.trim().is_empty()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(input: &str) -> SocketAddr {
        input.parse().unwrap()
    }

    fn example_valid_key() -> String {
        // A public, deterministic unit-test fixture; NEVER use as a real key.
        // Its digest looks irregular but has no secrecy or operational entropy.
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(
            b"public SecuScan unit-test fixture; not a production signing key",
        ))
    }

    #[test]
    fn production_rejects_missing_or_empty_secret() {
        for value in [None, Some(""), Some("   ")] {
            let err = resolve_jwt_secret(value, Environment::Production, addr("0.0.0.0:8080"))
                .unwrap_err();
            assert!(err.contains("SECUSCAN_JWT_SECRET"));
        }
    }

    #[test]
    fn rejects_known_placeholder_short_and_low_diversity_secrets() {
        for value in [
            "change-me-openssl-rand-hex-32".to_string(),
            "dev-jwt-secret".to_string(),
            "a".repeat(64),
            "00".repeat(32),
            "0123456789abcdef".repeat(4),
            hex::encode((0_u8..32).collect::<Vec<_>>()),
            hex::encode((0_u8..32).rev().collect::<Vec<_>>()),
        ] {
            assert!(validate_jwt_secret(&value).is_err());
        }
    }

    #[test]
    fn strong_key_is_stable_across_config_reload() {
        let key = example_valid_key();
        let first =
            resolve_jwt_secret(Some(&key), Environment::Production, addr("0.0.0.0:8080")).unwrap();
        let second =
            resolve_jwt_secret(Some(&key), Environment::Production, addr("0.0.0.0:8080")).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn dev_ephemeral_secret_requires_loopback_and_explicit_mode() {
        assert!(resolve_jwt_secret(None, Environment::Development, addr("0.0.0.0:8080")).is_err());
        let key =
            resolve_jwt_secret(None, Environment::Development, addr("127.0.0.1:8080")).unwrap();
        assert!(!key.is_empty());
        assert!(resolve_jwt_secret(None, Environment::Production, addr("127.0.0.1:8080")).is_err());
    }

    #[test]
    fn invalid_environment_rejected() {
        assert!(Environment::parse("prod").is_err());
        assert_eq!(
            Environment::parse("production").unwrap(),
            Environment::Production
        );
        assert_eq!(
            Environment::parse("development").unwrap(),
            Environment::Development
        );
    }
}
