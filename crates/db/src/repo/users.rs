//! User accounts.

use crate::models::UserRow;
use crate::{new_id, now, DbError, DbResult};
use sqlx::SqlitePool;

pub async fn create(
    pool: &SqlitePool,
    email: &str,
    name: &str,
    password_hash: &str,
    role: &str,
) -> DbResult<UserRow> {
    let email = email.trim().to_ascii_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(DbError::Invalid("email must be a valid address".into()));
    }
    if !matches!(role, "admin" | "scanner" | "viewer") {
        return Err(DbError::Invalid(format!("unknown role `{role}`")));
    }
    let existing = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE email = ?1")
        .bind(&email)
        .fetch_one(pool)
        .await?;
    if existing > 0 {
        return Err(DbError::Conflict(format!(
            "email `{email}` is already registered"
        )));
    }
    let row = UserRow {
        id: new_id(),
        email,
        name: name.trim().to_string(),
        password_hash: password_hash.to_string(),
        role: role.to_string(),
        created_at: now(),
    };
    sqlx::query(
        "INSERT INTO users (id, email, name, password_hash, role, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&row.id)
    .bind(&row.email)
    .bind(&row.name)
    .bind(&row.password_hash)
    .bind(&row.role)
    .bind(&row.created_at)
    .execute(pool)
    .await?;
    Ok(row)
}

pub async fn find_by_email(pool: &SqlitePool, email: &str) -> DbResult<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE email = ?1")
        .bind(email.trim().to_ascii_lowercase())
        .fetch_optional(pool)
        .await
        .map_err(Into::into)
}

pub async fn find_by_id(pool: &SqlitePool, id: &str) -> DbResult<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(Into::into)
}

pub async fn find_by_name(pool: &SqlitePool, name: &str) -> DbResult<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE name = ?1 COLLATE NOCASE LIMIT 1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .map_err(Into::into)
}

pub async fn list(pool: &SqlitePool) -> DbResult<Vec<UserRow>> {
    sqlx::query_as::<_, UserRow>("SELECT * FROM users ORDER BY created_at ASC")
        .fetch_all(pool)
        .await
        .map_err(Into::into)
}

pub async fn count(pool: &SqlitePool) -> DbResult<i64> {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
        .map_err(Into::into)
}

pub async fn update_password(pool: &SqlitePool, id: &str, password_hash: &str) -> DbResult<()> {
    let res = sqlx::query("UPDATE users SET password_hash = ?1 WHERE id = ?2")
        .bind(password_hash)
        .bind(id)
        .execute(pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(DbError::NotFound(format!("user {id}")));
    }
    Ok(())
}

pub async fn update_role(pool: &SqlitePool, id: &str, role: &str) -> DbResult<()> {
    if !matches!(role, "admin" | "scanner" | "viewer") {
        return Err(DbError::Invalid(format!("unknown role `{role}`")));
    }
    let res = sqlx::query("UPDATE users SET role = ?1 WHERE id = ?2")
        .bind(role)
        .bind(id)
        .execute(pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(DbError::NotFound(format!("user {id}")));
    }
    Ok(())
}

pub async fn delete(pool: &SqlitePool, id: &str) -> DbResult<()> {
    let res = sqlx::query("DELETE FROM users WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(DbError::NotFound(format!("user {id}")));
    }
    Ok(())
}

// --- refresh tokens -------------------------------------------------------

pub async fn insert_refresh_token(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
    token_hash: &str,
    expires_at: &str,
) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(id)
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at)
    .bind(now())
    .execute(pool)
    .await?;
    Ok(())
}

/// Returns the token row when valid (exists, not expired).
pub async fn find_refresh_token(
    pool: &SqlitePool,
    token_hash: &str,
) -> DbResult<Option<crate::models::RefreshTokenRow>> {
    let row = sqlx::query_as::<_, crate::models::RefreshTokenRow>(
        "SELECT * FROM refresh_tokens WHERE token_hash = ?1",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    match row {
        Some(r) if r.expires_at > now() => Ok(Some(r)),
        _ => Ok(None),
    }
}

pub async fn delete_refresh_token(pool: &SqlitePool, token_hash: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM refresh_tokens WHERE token_hash = ?1")
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_all_refresh_tokens_for_user(pool: &SqlitePool, user_id: &str) -> DbResult<u64> {
    let res = sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

pub async fn delete_expired_refresh_tokens(pool: &SqlitePool) -> DbResult<u64> {
    let res = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at <= ?1")
        .bind(now())
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}
