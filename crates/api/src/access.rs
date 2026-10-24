//! Shared authorization helpers for v3+ resources.
//!
//! Non-admins may only see or mutate rows they created. We return
//! `NotFound` (not Forbidden) so an IDOR probe cannot confirm that
//! another user's object exists.

use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};

pub fn is_owner_or_admin(user: &CurrentUser, created_by: &str) -> bool {
    user.is_admin() || created_by == user.0.id
}

pub fn require_owner(user: &CurrentUser, created_by: &str) -> ApiResult<()> {
    if is_owner_or_admin(user, created_by) {
        Ok(())
    } else {
        Err(ApiError::NotFound("not found".into()))
    }
}
