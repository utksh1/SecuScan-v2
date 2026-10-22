//! First-run seeding: create the initial admin account.

use crate::auth::hash_password;
use secuscan_db::repo;
use sqlx::SqlitePool;
use std::sync::Arc;

use crate::config::Config;

/// Seed the administrator account when the users table is empty.
pub async fn seed_admin(pool: &SqlitePool, config: &Arc<Config>) {
    match repo::users::count(pool).await {
        Ok(0) => {}
        Ok(_) => return, // already seeded
        Err(e) => {
            tracing::error!("cannot count users during seeding: {e}");
            return;
        }
    }
    let (email, password, generated) = match &config.admin_password {
        Some(p) => (config.admin_email.clone(), p.clone(), false),
        None => {
            let p = secuscan_db::generate_token("admin");
            (config.admin_email.clone(), p, true)
        }
    };
    match hash_password(&password) {
        Ok(hash) => {
            match repo::users::create(pool, &email, "Administrator", &hash, "admin").await {
                Ok(_) => {
                    if generated {
                        tracing::info!(
                            "┌──────────────────────────────────────────────────────────┐\n\
                         │  First run: created the initial administrator account.   │\n\
                         │  Email:    {email:<46}│\n\
                         │  Password: {password:<46}│\n\
                         │  Store it now — it will not be shown again.             │\n\
                         └──────────────────────────────────────────────────────────┘"
                        );
                    } else {
                        tracing::info!("seeded administrator account {email}");
                    }
                }
                Err(e) => tracing::error!("failed to seed admin: {e}"),
            }
        }
        Err(e) => tracing::error!("failed to hash seeded admin password: {e}"),
    }
}
