//! Authentication: argon2 password hashing, JWT access tokens, refresh
//! cookies, API keys, and the `CurrentUser` extractor.

pub mod extractor;

use crate::error::{ApiError, ApiResult};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Access-token lifetime.
pub const ACCESS_TTL_SECS: i64 = 30 * 60;
/// Refresh-token lifetime (7 days).
pub const REFRESH_TTL_SECS: i64 = 7 * 24 * 3600;
/// Refresh cookie name.
pub const REFRESH_COOKIE: &str = "secuscan_refresh";

// ---------------------------------------------------------------------------
// Passwords (Argon2id)
// ---------------------------------------------------------------------------

pub fn hash_password(password: &str) -> ApiResult<String> {
    if password.len() < 8 {
        return Err(ApiError::BadRequest(
            "password must be at least 8 characters".into(),
        ));
    }
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| ApiError::Internal(format!("password hashing failed: {e}")))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// JWT access tokens
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: String,
    pub role: String,
    pub typ: String, // always "access"
    pub iat: i64,
    pub exp: i64,
}

pub fn issue_access_token(secret: &str, user_id: &str, role: &str) -> ApiResult<String> {
    let now = chrono::Utc::now().timestamp();
    let claims = AccessClaims {
        sub: user_id.to_string(),
        role: role.to_string(),
        typ: "access".into(),
        iat: now,
        exp: now + ACCESS_TTL_SECS,
    };
    jsonwebtoken::encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| ApiError::Internal(format!("token signing failed: {e}")))
}

pub fn verify_access_token(secret: &str, token: &str) -> ApiResult<AccessClaims> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.leeway = 30;
    let data = jsonwebtoken::decode::<AccessClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_| ApiError::Unauthorized("invalid or expired access token".into()))?;
    if data.claims.typ != "access" {
        return Err(ApiError::Unauthorized("wrong token type".into()));
    }
    Ok(data.claims)
}

// ---------------------------------------------------------------------------
// Refresh tokens (opaque, hashed at rest, rotating)
// ---------------------------------------------------------------------------

pub fn new_refresh_token() -> String {
    let mut bytes = [0u8; 48];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("scsr_{}", secuscan_db::generate_token_from(&bytes))
}

pub fn refresh_expiry_iso() -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(REFRESH_TTL_SECS))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_roundtrip() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("wrong", &h));
    }

    #[test]
    fn short_passwords_rejected() {
        assert!(hash_password("short").is_err());
    }

    #[test]
    fn garbage_hash_fails_closed() {
        assert!(!verify_password("x", "not-a-hash"));
    }

    #[test]
    fn access_token_roundtrip() {
        let secret = "test-secret";
        let tok = issue_access_token(secret, "user-1", "admin").unwrap();
        let claims = verify_access_token(secret, &tok).unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.role, "admin");
        assert!(verify_access_token("other-secret", &tok).is_err());
    }

    #[test]
    fn refresh_token_shape() {
        let t = new_refresh_token();
        assert!(t.starts_with("scsr_"));
        assert!(t.len() > 40);
    }
}
