//! OpenAPI 3.1 spec publication (v3.1.2, reworked in v3.1.3).
//!
//! Three endpoints serve the spec so external clients (curl, Postman,
//! Swagger UI, code generators) can discover and exercise every route
//! without reading source:
//!
//! - `GET /openapi.json` -- JSON spec. This is the single source of
//!   truth, committed at `docs/openapi.json` and embedded at compile
//!   time (no runtime file I/O, no external spec generator).
//! - `GET /openapi.yaml` -- the same spec serialized to YAML at runtime
//!   via `serde_yaml` (kept for human-friendly consumption and tooling
//!   that prefers YAML; no stale duplicate artifact to maintain).
//! - `GET /openapi`      -- tiny HTML landing page with a Swagger-UI
//!   viewer (loaded from cdn.jsdelivr.net).
//!
//! To update the spec: edit `docs/openapi.json`, rebuild. A CLI export
//! (`secuscan-cli export-openapi`) prints the embedded JSON for SDK
//! generation pipelines.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

/// The OpenAPI 3.1 spec, embedded at compile time as JSON.
const OPENAPI_JSON: &str = include_str!("../../../../docs/openapi.json");

pub fn router() -> axum::Router<crate::state::SharedState> {
    axum::Router::new()
        .route("/openapi.json", axum::routing::get(openapi_json))
        .route("/openapi.yaml", axum::routing::get(openapi_yaml))
        .route("/openapi", axum::routing::get(openapi_landing))
}

/// Parse the embedded spec once and reuse it across requests.
fn spec() -> Result<serde_json::Value, String> {
    serde_json::from_str(OPENAPI_JSON).map_err(|e| format!("embedded openapi.json is invalid: {e}"))
}

/// JSON spec.
async fn openapi_json() -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    spec()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
}

/// YAML spec, serialized from the embedded JSON on each request (the
/// conversion is microseconds-cheap compared to a network round trip).
async fn openapi_yaml() -> Response {
    match spec() {
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        Ok(v) => match serde_yaml::to_string(&v) {
            Ok(yaml) => (
                StatusCode::OK,
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/yaml; charset=utf-8"),
                    ),
                    (
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("public, max-age=300"),
                    ),
                ],
                yaml,
            )
                .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot serialize spec to YAML: {e}"),
            )
                .into_response(),
        },
    }
}

/// Tiny HTML landing page. Links to the JSON + YAML endpoints and
/// loads Swagger UI from the jsdelivr CDN so users can browse the spec
/// interactively without installing anything.
async fn openapi_landing() -> Response {
    // `r##"..."##` because the body contains `"#swagger-ui` (which would
    // close `r#"..."#`).
    let html = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SecuScan v2 API</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
  <style>body { margin: 0; }</style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: "/api/v1/openapi.json",
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis],
        layout: "BaseLayout",
      });
    };
  </script>
  <noscript>
    This page needs JavaScript. Direct links:
    <a href="/api/v1/openapi.json">openapi.json</a>,
    <a href="/api/v1/openapi.yaml">openapi.yaml</a>.
  </noscript>
</body>
</html>"##;
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        html,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_json_parses_and_has_expected_top_level_keys() {
        let v = spec().expect("embedded openapi.json must parse");
        let obj = v.as_object().expect("spec must be a JSON object");
        for key in ["openapi", "info", "servers", "tags", "paths", "components"] {
            assert!(obj.contains_key(key), "spec missing top-level key `{key}`");
        }
        assert_eq!(v["openapi"], "3.1.0");
        let n_paths = obj["paths"].as_object().map(|m| m.len()).unwrap_or(0);
        assert!(n_paths >= 80, "expected >=80 paths, got {n_paths}");
        let n_schemas = obj["components"]["schemas"]
            .as_object()
            .map(|m| m.len())
            .unwrap_or(0);
        assert!(n_schemas >= 20, "expected >=20 schemas, got {n_schemas}");
    }

    #[test]
    fn yaml_serialization_round_trips_the_spec() {
        let v = spec().expect("embedded spec must parse");
        let yaml = serde_yaml::to_string(&v).expect("spec must serialize to YAML");
        assert!(
            yaml.starts_with("openapi: 3.1"),
            "YAML must start with `openapi: 3.1`"
        );
        // Round-trip: YAML -> JSON Value must equal the original spec.
        let back: serde_json::Value = serde_yaml::from_str(&yaml).expect("YAML must re-parse");
        assert_eq!(back, v, "YAML round-trip must preserve the spec");
    }
}
