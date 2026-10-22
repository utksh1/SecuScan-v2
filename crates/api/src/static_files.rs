//! Static SPA hosting: serves `frontend/dist` when present, falling back to
//! `index.html` for client-side routes. When the frontend has not been
//! built, a minimal HTML notice is served instead.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use tower_http::services::ServeDir;

const NOT_BUILT: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>SecuScan</title>
<style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.card{max-width:34rem;padding:2rem;border:1px solid #1e293b;border-radius:12px;background:#111c33}
code{background:#1e293b;padding:.15rem .4rem;border-radius:4px}</style></head>
<body><div class="card">
<h1>SecuScan API is running</h1>
<p>The web frontend has not been built yet. Build it with:</p>
<p><code>cd frontend &amp;&amp; npm ci &amp;&amp; npm run build</code></p>
<p>Then restart the server, or use the REST API directly at
<code>/api/v1</code> (see docs/API.md).</p>
</div></body></html>"#;

/// Build the SPA fallback router for a built frontend directory.
pub fn spa_service(dist_dir: &std::path::Path) -> axum::Router {
    let index_path = dist_dir.join("index.html");
    if index_path.is_file() {
        let serve_dir = ServeDir::new(dist_dir).not_found_service(axum::routing::get(move || {
            let path = index_path.clone();
            async move { serve_file_or_notice(&path).await }
        }));
        axum::Router::new().fallback_service(serve_dir)
    } else {
        tracing::warn!(
            "frontend not built at `{}` — serving an API-only notice page",
            dist_dir.display()
        );
        axum::Router::new().fallback(axum::routing::get(|| async {
            (
                StatusCode::OK,
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                )],
                NOT_BUILT,
            )
        }))
    }
}

async fn serve_file_or_notice(path: &std::path::Path) -> impl IntoResponse {
    match tokio::fs::read(path).await {
        Ok(bytes) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            )],
            bytes,
        )
            .into_response(),
        Err(_) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            )],
            NOT_BUILT.as_bytes().to_vec(),
        )
            .into_response(),
    }
}
