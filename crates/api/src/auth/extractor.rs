//! `CurrentUser` extractor: resolves `Authorization: Bearer <jwt>` or
//! `X-API-Key: <key>` into a live user row.

use crate::auth::verify_access_token;
use crate::state::AppState;
use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use secuscan_db::models::UserRow;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct CurrentUser(pub UserRow);

impl CurrentUser {
    pub fn is_admin(&self) -> bool {
        self.0.role == "admin"
    }

    pub fn require_admin(&self) -> Result<(), crate::error::ApiError> {
        if self.is_admin() {
            Ok(())
        } else {
            Err(crate::error::ApiError::Forbidden(
                "administrator role required".into(),
            ))
        }
    }

    /// Viewers are read-only: they may browse tasks/findings but not start
    /// scans, triage, or manage workflows.
    pub fn require_scanner(&self) -> Result<(), crate::error::ApiError> {
        if self.0.role == "viewer" {
            Err(crate::error::ApiError::Forbidden(
                "viewer role is read-only — ask an administrator for the scanner role".into(),
            ))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl FromRequestParts<Arc<AppState>> for CurrentUser {
    type Rejection = crate::error::ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // 1) Bearer JWT
        if let Some(auth) = parts.headers.get(axum::http::header::AUTHORIZATION) {
            let value = auth
                .to_str()
                .map_err(|_| crate::error::ApiError::Unauthorized("bad Authorization header".into()))?;
            if let Some(token) = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer ")) {
                let claims = verify_access_token(&state.config.jwt_secret, token)?;
                let user = secuscan_db::repo::users::find_by_id(&state.db, &claims.sub)
                    .await
                    .map_err(crate::error::ApiError::from)?
                    .ok_or_else(|| crate::error::ApiError::Unauthorized("user no longer exists".into()))?;
                return Ok(CurrentUser(user));
            }
        }

        // 2) X-API-Key
        if let Some(key) = parts.headers.get("x-api-key") {
            let raw = key
                .to_str()
                .map_err(|_| crate::error::ApiError::Unauthorized("bad API key header".into()))?;
            let api_key = secuscan_db::repo::api_keys::verify(&state.db, raw)
                .await
                .map_err(crate::error::ApiError::from)?
                .ok_or_else(|| crate::error::ApiError::Unauthorized("invalid API key".into()))?;
            let user = secuscan_db::repo::users::find_by_id(&state.db, &api_key.user_id)
                .await
                .map_err(crate::error::ApiError::from)?
                .ok_or_else(|| crate::error::ApiError::Unauthorized("user no longer exists".into()))?;
            return Ok(CurrentUser(user));
        }

        Err(crate::error::ApiError::Unauthorized(
            "missing credentials (Bearer token or X-API-Key)".into(),
        ))
    }
}
