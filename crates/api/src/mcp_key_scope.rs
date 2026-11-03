//! Server-side permission boundary for restricted MCP API credentials.
//!
//! This middleware wraps the *entire* v1 API router. It verifies the scoped
//! key against SQLite before routing; no client-controlled request flag can
//! grant access to a mutation endpoint.
//!
//! A valid unscoped legacy API key keeps its existing permissions for
//! backwards compatibility. Invalid/revoked keys fail closed.
use crate::error::ApiError;
use crate::state::SharedState;
use axum::extract::{Request, State};
use axum::http::{header, Method};
use axum::middleware::Next;
use axum::response::Response;
use secuscan_db::repo;

pub async fn enforce(
    State(state): State<SharedState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let Some(key) = request.headers().get("x-api-key") else {
        return Ok(next.run(request).await);
    };
    // Never allow two credentials to compete for precedence. The client must
    // not attach an unrestricted JWT alongside a scoped key.
    if request.headers().contains_key(header::AUTHORIZATION) {
        return Err(ApiError::Unauthorized(
            "send either Authorization or X-API-Key, not both".into(),
        ));
    }

    let raw = key
        .to_str()
        .map_err(|_| ApiError::Unauthorized("invalid API key header".into()))?;
    let record = repo::api_keys::verify(&state.db, raw)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("invalid or revoked API key".into()))?;
    match record.scope.as_str() {
        "full" => Ok(next.run(request).await),
        "mcp_scan" => {
            if !mcp_route_allowed(request.method(), request.uri().path()) {
                return Err(ApiError::Forbidden(
                    "MCP-scoped API key cannot call this endpoint; an approved MCP scan is required"
                        .into(),
                ));
            }
            Ok(next.run(request).await)
        }
        // Unknown future scope must never implicitly become full access.
        _ => Err(ApiError::Forbidden("unsupported API key scope".into())),
    }
}

/// An explicit method+path allowlist. All POST/PATCH/PUT/DELETE are denied
/// except the one-time approved scan route. GET is granted only to the
/// specific inspection endpoints used by the MCP read-only tools.
///
/// Axum may strip /api/v1 when nesting routers; accept both forms. Queries
/// are excluded by uri().path() and therefore cannot affect permission.
fn mcp_route_allowed(method: &Method, original_path: &str) -> bool {
    let path = original_path.strip_prefix("/api/v1").unwrap_or(original_path);
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if method == Method::POST {
        return parts.as_slice() == ["mcp", "scans"];
    }
    if method != Method::GET {
        return false;
    }
    matches!(parts.as_slice(),
        (["health"])
        | (["plugins"])
        | (["tasks"])
        | (["findings"])
        | (["workspaces"])
        | (["robots"])
        | (["attack-surface"])
        | (["reports"])
        | (["vpn-profiles"]) => true,
        (["plugins", _])
        | (["findings", _])
        | (["tasks", _])
        | (["sniper", "runs", _])
        | (["robots", "runs", _]) => true,
        (["plugins", _, "schema"])
        | (["tasks", _, "findings"])
        | (["workspaces", _, "targets"]) => true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_mutations_except_exact_approved_scan() {
        let rejected = [
            (Method::POST, "/api/v1/tasks"),
            (Method::POST, "/api/v1/tasks/id/retry"),
            (Method::DELETE, "/api/v1/tasks/id"),
            (Method::POST, "/api/v1/workflows/id/run"),
            (Method::POST, "/api/v1/schedules"),
            (Method::POST, "/api/v1/robots/id/run"),
            (Method::POST, "/api/v1/sniper/run"),
            (Method::POST, "/api/v1/workspaces"),
            (Method::POST, "/api/v1/tasks/id/reports"),
            (Method::POST, "/api/v1/mcp/scan-approvals"),
            (Method::POST, "/api/v1/admin/mcp-keys"),
            (Method::POST, "/api/v1/vpn-profiles/id/test"),
            (Method::PUT, "/api/v1/plugins/id/enabled"),
            (Method::PATCH, "/api/v1/findings/id"),
            (Method::GET, "/api/v1/admin/users"),
            (Method::GET, "/api/v1/auth/api-keys"),
            (Method::GET, "/api/v1/workflows/id"),
            (Method::GET, "/api/v1/mcp/scan-approvals"),
            (Method::POST, "/api/v1/mcp/scans/extra"),
            (Method::POST, "/api/v1/tasks/../mcp/scans"),
        ];
        for (method, path) in rejected {
            assert!(!mcp_route_allowed(&method, path), "{method} {path}");
        }
        assert!(mcp_route_allowed(&Method::POST, "/api/v1/mcp/scans"));
        assert!(mcp_route_allowed(&Method::POST, "/mcp/scans"));
        assert!(!mcp_route_allowed(&Method::GET, "/api/v1/mcp/scans"));
    }

    #[test]
    fn read_allowlist_is_exact_not_a_wildcard() {
        let allowed = [
            "/api/v1/plugins",
            "/api/v1/plugins/port-scanner/schema",
            "/api/v1/tasks",
            "/api/v1/tasks/id",
            "/api/v1/tasks/id/findings",
            "/api/v1/findings/id",
            "/api/v1/workspaces",
            "/api/v1/workspaces/id/targets",
            "/api/v1/robots/runs/id",
            "/api/v1/sniper/runs/id",
            "/api/v1/attack-surface",
            "/api/v1/reports",
        ];
        for path in allowed {
            assert!(mcp_route_allowed(&Method::GET, path), "{path}");
        }
        assert!(!mcp_route_allowed(&Method::GET, "/api/v1/robots/id/run"));
        assert!(!mcp_route_allowed(&Method::GET, "/api/v1/unknown"));
    }
}
