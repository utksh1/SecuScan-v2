//! Branding: single per-instance row controlling report look-and-feel.

use crate::models::BrandingRow;
use crate::{DbError, DbResult};
use sqlx::SqlitePool;

pub async fn get(db: &SqlitePool) -> DbResult<BrandingRow> {
    sqlx::query_as::<_, BrandingRow>("SELECT * FROM branding WHERE id = 1")
        .fetch_one(db)
        .await
        .map_err(Into::into)
}

pub async fn update(
    db: &SqlitePool,
    org_name: &str,
    logo_png: Option<&[u8]>,
    primary_color: &str,
    accent_color: &str,
    footer_text: &str,
    updated_by: Option<&str>,
) -> DbResult<BrandingRow> {
    let now = crate::now();
    sqlx::query(
        "UPDATE branding SET org_name = ?, logo_png = ?, primary_color = ?, accent_color = ?,
                             footer_text = ?, updated_at = ?, updated_by = ?
         WHERE id = 1",
    )
    .bind(org_name)
    .bind(logo_png)
    .bind(primary_color)
    .bind(accent_color)
    .bind(footer_text)
    .bind(&now)
    .bind(updated_by)
    .execute(db)
    .await?;
    get(db).await.map_err(Into::into)
}
