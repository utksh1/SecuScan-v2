//! Branding HTTP routes — single per-instance row controlling report look.

use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use axum::extract::{Multipart, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        .route("/branding", axum::routing::get(get_one).patch(update))
        .route("/branding/logo", axum::routing::post(upload_logo))
}

fn branding_to_json(b: &secuscan_db::models::BrandingRow) -> Value {
    json!({
        "id": b.id,
        "org_name": b.org_name,
        "has_logo": b.logo_png.is_some(),
        "logo_size": b.logo_png.as_ref().map(|v| v.len() as u64),
        "primary_color": b.primary_color,
        "accent_color": b.accent_color,
        "footer_text": b.footer_text,
        "updated_at": b.updated_at,
        "updated_by": b.updated_by,
    })
}

async fn get_one(
    State(state): State<SharedState>,
    _user: CurrentUser,
) -> ApiResult<Json<Value>> {
    let row = secuscan_db::repo::branding::get(&state.db).await?;
    Ok(Json(branding_to_json(&row)))
}

#[derive(Deserialize)]
struct UpdateBrandingRequest {
    org_name: String,
    primary_color: String,
    accent_color: String,
    footer_text: String,
}

async fn update(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<UpdateBrandingRequest>,
) -> ApiResult<StatusCode> {
    user.require_admin()?;
    if req.org_name.trim().is_empty() || req.org_name.len() > 120 {
        return Err(ApiError::BadRequest("org_name must be 1..=120 characters".into()));
    }
    if !is_hex_color(&req.primary_color) || !is_hex_color(&req.accent_color) {
        return Err(ApiError::BadRequest(
            "primary_color and accent_color must be 6-character hex (no #)".into()
        ));
    }
    if req.footer_text.len() > 500 {
        return Err(ApiError::BadRequest("footer_text must be <= 500 characters".into()));
    }
    // Preserve existing logo on text-only updates.
    let existing = secuscan_db::repo::branding::get(&state.db).await?;
    secuscan_db::repo::branding::update(
        &state.db,
        &req.org_name,
        existing.logo_png.as_deref(),
        &req.primary_color,
        &req.accent_color,
        &req.footer_text,
        Some(&user.0.id),
    ).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn upload_logo(
    State(state): State<SharedState>,
    user: CurrentUser,
    mut mp: Multipart,
) -> ApiResult<StatusCode> {
    user.require_admin()?;
    let mut logo_bytes: Option<Vec<u8>> = None;
    while let Some(field) = mp.next_field().await
        .map_err(|e| ApiError::BadRequest(format!("multipart error: {e}")))?
    {
        if field.name() == Some("logo") {
            let bytes = field.bytes().await
                .map_err(|e| ApiError::BadRequest(format!("read field: {e}")))?;
            if bytes.len() > 256 * 1024 {
                return Err(ApiError::BadRequest("logo must be <= 256KB".into()));
            }
            // Sanity-check PNG magic bytes.
            if bytes.len() < 8 || &bytes[0..8] != b"\x89PNG\r\n\x1a\n" {
                return Err(ApiError::BadRequest("logo must be a valid PNG file".into()));
            }
            logo_bytes = Some(bytes.to_vec());
        }
    }
    let logo = logo_bytes.ok_or_else(|| ApiError::BadRequest("missing `logo` field".into()))?;
    let existing = secuscan_db::repo::branding::get(&state.db).await?;
    secuscan_db::repo::branding::update(
        &state.db,
        &existing.org_name,
        Some(&logo),
        &existing.primary_color,
        &existing.accent_color,
        &existing.footer_text,
        Some(&user.0.id),
    ).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn is_hex_color(s: &str) -> bool {
    s.len() == 6 && s.chars().all(|c| c.is_ascii_hexdigit())
}
