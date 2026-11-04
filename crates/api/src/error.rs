//! Uniform API error → HTTP JSON response.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("too many requests: {0}")]
    TooManyRequests(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        // Never distinguish an absent resource ID from an existing resource
        // concealed by membership or ownership authorization (IDOR probing).
        let message = match &self {
            // This guidance is produced only *after* a current task has
            // passed access control. It does not reveal a guessed object ID.
            ApiError::NotFound(m) if m.starts_with("no earlier completed run") => m.clone(),
            ApiError::NotFound(_) => "not found".to_string(),
            _ => self.to_string(),
        };
        let body = Json(json!({
            "error": { "code": status.as_u16(), "message": message }
        }));
        (status, body).into_response()
    }
}

impl From<secuscan_db::DbError> for ApiError {
    fn from(e: secuscan_db::DbError) -> Self {
        match e {
            secuscan_db::DbError::NotFound(m) => ApiError::NotFound(m),
            secuscan_db::DbError::Conflict(m) => ApiError::Conflict(m),
            secuscan_db::DbError::Invalid(m) => ApiError::BadRequest(m),
            secuscan_db::DbError::Sqlx(e) => {
                tracing::error!("database error: {e}");
                ApiError::Internal("database error".into())
            }
        }
    }
}

impl From<secuscan_core::CoreError> for ApiError {
    fn from(e: secuscan_core::CoreError) -> Self {
        match e {
            secuscan_core::CoreError::Input(m) => ApiError::BadRequest(m),
            secuscan_core::CoreError::Manifest(m)
            | secuscan_core::CoreError::Template(m)
            | secuscan_core::CoreError::Parse(m) => ApiError::BadRequest(m),
            other => ApiError::Internal(other.to_string()),
        }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
