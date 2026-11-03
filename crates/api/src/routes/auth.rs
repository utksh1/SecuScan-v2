//! Auth routes: login / refresh / logout / me / register / API keys.

use crate::auth::{
    hash_password, issue_access_token, new_refresh_token, refresh_expiry_iso, verify_password,
    REFRESH_COOKIE, REFRESH_TTL_SECS,
};
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::Json;
use axum_extra::extract::cookie::{Cookie, SameSite};
use secuscan_db::repo;
use secuscan_db::sha256_hex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        .route("/auth/login", axum::routing::post(login))
        .route("/auth/refresh", axum::routing::post(refresh))
        .route("/auth/logout", axum::routing::post(logout))
        .route("/auth/me", axum::routing::get(me))
        .route("/auth/register", axum::routing::post(register))
        .route("/auth/api-keys", axum::routing::post(create_api_key))
        .route("/auth/api-keys", axum::routing::get(list_api_keys))
        .route("/auth/api-keys/:id", axum::routing::delete(revoke_api_key))
        .route("/auth/password", axum::routing::post(change_password))
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct UserDto {
    id: String,
    email: String,
    name: String,
    role: String,
    created_at: String,
}

impl UserDto {
    fn from_row(u: &secuscan_db::models::UserRow) -> Self {
        UserDto {
            id: u.id.clone(),
            email: u.email.clone(),
            name: u.name.clone(),
            role: u.role.clone(),
            created_at: u.created_at.clone(),
        }
    }
}

// --- brute-force protection -------------------------------------------------

fn login_limiter() -> &'static Mutex<HashMap<String, VecDeque<Instant>>> {
    static LIMITER: std::sync::OnceLock<Mutex<HashMap<String, VecDeque<Instant>>>> =
        std::sync::OnceLock::new();
    LIMITER.get_or_init(|| Mutex::new(HashMap::new()))
}

const LOGIN_WINDOW: Duration = Duration::from_secs(60);
const LOGIN_MAX_ATTEMPTS: usize = 30;

fn check_login_rate(key: &str) -> ApiResult<()> {
    let mut map = login_limiter().lock().expect("login limiter");
    let q = map.entry(key.to_string()).or_default();
    let now = Instant::now();
    while let Some(front) = q.front() {
        if now.duration_since(*front) >= LOGIN_WINDOW {
            q.pop_front();
        } else {
            break;
        }
    }
    if q.len() >= LOGIN_MAX_ATTEMPTS {
        return Err(ApiError::TooManyRequests(
            "too many login attempts — wait a minute and retry".into(),
        ));
    }
    q.push_back(now);
    Ok(())
}

fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "local".to_string())
}

// --- handlers ----------------------------------------------------------------

async fn login(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> ApiResult<(HeaderMap, Json<serde_json::Value>)> {
    check_login_rate(&format!(
        "{}|{}",
        client_ip(&headers),
        req.email.to_ascii_lowercase()
    ))?;
    // Constant-ish time: verify against a dummy hash when the user is
    // unknown, so response timing does not reveal account existence.
    const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$YXNhbHQxc2FsdDEyc2FsdA$P13Xq8bX0ZGHGkMZYyYqXlOjSOnDZpS1LzIMiIpEymM";
    let user = repo::users::find_by_email(&state.db, &req.email).await?;
    let (user, hash) = match user {
        Some(u) => {
            let hash = u.password_hash.clone();
            (Some(u), hash)
        }
        None => (None, DUMMY_HASH.to_string()),
    };
    let password_ok = verify_password(&req.password, &hash);
    let user = match (user, password_ok) {
        (Some(u), true) => u,
        _ => return Err(ApiError::Unauthorized("invalid email or password".into())),
    };
    let access = issue_access_token(&state.config.jwt_secret, &user.id, &user.role)?;
    let refresh = new_refresh_token();
    repo::users::insert_refresh_token(
        &state.db,
        &secuscan_db::new_id(),
        &user.id,
        &sha256_hex(&refresh),
        &refresh_expiry_iso(),
    )
    .await?;

    let cookie = Cookie::build((REFRESH_COOKIE, refresh))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(state.config.cookie_secure)
        .max_age(time::Duration::seconds(REFRESH_TTL_SECS))
        .build();
    let mut hm = HeaderMap::new();
    if let Ok(v) = header::HeaderValue::from_str(&cookie.to_string()) {
        hm.insert(header::SET_COOKIE, v);
    }
    Ok((
        hm,
        Json(serde_json::json!({
            "access_token": access,
            "token_type": "bearer",
            "user": UserDto::from_row(&user),
        })),
    ))
}

async fn refresh(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> ApiResult<(HeaderMap, Json<serde_json::Value>)> {
    let raw = extract_refresh_cookie(&headers)
        .ok_or_else(|| ApiError::Unauthorized("missing refresh cookie".into()))?;
    let hash = sha256_hex(&raw);
    let stored = repo::users::find_refresh_token(&state.db, &hash)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("invalid or expired refresh token".into()))?;
    let user = repo::users::find_by_id(&state.db, &stored.user_id)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("user no longer exists".into()))?;

    // Rotation: invalidate the presented token, issue a fresh pair.
    repo::users::delete_refresh_token(&state.db, &hash).await?;
    let access = issue_access_token(&state.config.jwt_secret, &user.id, &user.role)?;
    let new_refresh = new_refresh_token();
    repo::users::insert_refresh_token(
        &state.db,
        &secuscan_db::new_id(),
        &user.id,
        &sha256_hex(&new_refresh),
        &refresh_expiry_iso(),
    )
    .await?;

    let cookie = Cookie::build((REFRESH_COOKIE, new_refresh))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(state.config.cookie_secure)
        .max_age(time::Duration::seconds(REFRESH_TTL_SECS))
        .build();
    let mut hm = HeaderMap::new();
    if let Ok(v) = header::HeaderValue::from_str(&cookie.to_string()) {
        hm.insert(header::SET_COOKIE, v);
    }
    Ok((
        hm,
        Json(serde_json::json!({
            "access_token": access,
            "token_type": "bearer",
            "user": UserDto::from_row(&user),
        })),
    ))
}

fn extract_refresh_cookie(headers: &HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in cookies.split(';') {
        let mut it = pair.trim().splitn(2, '=');
        let name = it.next()?.trim();
        if name == REFRESH_COOKIE {
            return it
                .next()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty());
        }
    }
    None
}

async fn logout(State(state): State<SharedState>, headers: HeaderMap) -> ApiResult<StatusCode> {
    if let Some(raw) = extract_refresh_cookie(&headers) {
        repo::users::delete_refresh_token(&state.db, &sha256_hex(&raw)).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn me(
    crate::auth::extractor::CurrentUser(user): crate::auth::extractor::CurrentUser,
) -> Json<UserDto> {
    Json(UserDto::from_row(&user))
}

#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    name: String,
    password: String,
}

async fn register(
    State(state): State<SharedState>,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<(StatusCode, Json<UserDto>)> {
    if !state.config.allow_register {
        return Err(ApiError::Forbidden(
            "registration is disabled on this instance — ask an administrator for an account"
                .into(),
        ));
    }
    if req.name.trim().is_empty() || req.name.len() > 100 {
        return Err(ApiError::BadRequest(
            "name must be 1..=100 characters".into(),
        ));
    }
    let hash = hash_password(&req.password)?;
    let user = repo::users::create(&state.db, &req.email, &req.name, &hash, "scanner").await?;
    Ok((StatusCode::CREATED, Json(UserDto::from_row(&user))))
}

// --- API keys -------------------------------------------------------------

#[derive(Deserialize)]
struct CreateApiKeyRequest {
    name: String,
}

async fn create_api_key(
    State(state): State<SharedState>,
    crate::auth::extractor::CurrentUser(user): crate::auth::extractor::CurrentUser,
    Json(req): Json<CreateApiKeyRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    if req.name.trim().is_empty() || req.name.len() > 100 {
        return Err(ApiError::BadRequest(
            "name must be 1..=100 characters".into(),
        ));
    }
    let created = repo::api_keys::create(&state.db, &user.id, &req.name).await?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": created.row.id,
            "name": created.row.name,
            "prefix": created.row.prefix,
            "scope": created.row.scope,
            "created_at": created.row.created_at,
            // shown exactly once:
            "key": created.raw,
        })),
    ))
}

async fn list_api_keys(
    State(state): State<SharedState>,
    crate::auth::extractor::CurrentUser(user): crate::auth::extractor::CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    let keys = repo::api_keys::list_for_user(&state.db, &user.id).await?;
    let items: Vec<serde_json::Value> = keys
        .into_iter()
        .map(|k| {
            serde_json::json!({
                "id": k.id,
                "name": k.name,
                "prefix": k.prefix,
                "scope": k.scope,
                "issued_by": k.issued_by,
                "created_at": k.created_at,
                "last_used_at": k.last_used_at,
                "revoked_at": k.revoked_at,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "items": items })))
}

async fn revoke_api_key(
    State(state): State<SharedState>,
    crate::auth::extractor::CurrentUser(user): crate::auth::extractor::CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let ok = repo::api_keys::revoke(&state.db, &id, &user.id).await?;
    if ok {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound(format!("api key {id}")))
    }
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<SharedState>,
    crate::auth::extractor::CurrentUser(user): crate::auth::extractor::CurrentUser,
    Json(req): Json<ChangePasswordRequest>,
) -> ApiResult<StatusCode> {
    if !verify_password(&req.current_password, &user.password_hash) {
        return Err(ApiError::Unauthorized(
            "current password is incorrect".into(),
        ));
    }
    let hash = hash_password(&req.new_password)?;
    repo::users::update_password(&state.db, &user.id, &hash).await?;
    // Revoke all sessions: the password that minted them is no longer valid.
    repo::users::delete_all_refresh_tokens_for_user(&state.db, &user.id).await?;
    Ok(StatusCode::NO_CONTENT)
}
