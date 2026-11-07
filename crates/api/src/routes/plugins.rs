//! Plugin catalog routes: list, schema, command preview, enable/disable.

use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use secuscan_core::manifest::{EngineSpec, FieldSpec, FieldType, PluginManifest};
use secuscan_core::template::preview_command;
use secuscan_core::validate::normalize_inputs;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        .route("/plugins", axum::routing::get(list))
        .route("/plugins/:id", axum::routing::get(get_one))
        .route("/plugins/:id/schema", axum::routing::get(schema))
        .route("/plugins/:id/preview", axum::routing::post(preview))
        .route("/plugins/:id/enabled", axum::routing::put(set_enabled))
}

/// Serialize a manifest into the UI-facing plugin JSON.
pub fn manifest_to_json(m: &PluginManifest, enabled: bool) -> Value {
    let engine = match &m.engine {
        EngineSpec::Cli {
            binary,
            argv,
            timeout_seconds,
            output_format,
            ok_exit_codes,
        } => json!({
            "type": "cli",
            "binary": binary,
            "argv": argv,
            "timeout_seconds": timeout_seconds,
            "output_format": match output_format {
                secuscan_core::manifest::OutputFormat::Text => "text",
                secuscan_core::manifest::OutputFormat::JsonLines => "json_lines",
            },
            "ok_exit_codes": ok_exit_codes,
        }),
        EngineSpec::Native {
            native,
            timeout_seconds,
        } => json!({
            "type": "native",
            "native": native,
            "timeout_seconds": timeout_seconds,
        }),
    };
    json!({
        "id": m.plugin.id,
        "name": m.plugin.name,
        "version": m.plugin.version,
        "description": m.plugin.description,
        "long_description": m.plugin.long_description,
        "category": m.plugin.category,
        "author": m.plugin.author,
        "license": m.plugin.license,
        "icon": m.plugin.icon,
        "difficulty": m.plugin.difficulty,
        "tags": m.plugin.tags,
        "engine": engine,
        "fields": m.fields.iter().map(field_to_json).collect::<Vec<_>>(),
        "presets": m.presets,
        "preset_meta": m.preset_meta,
        "safety": {
            "level": m.safety.level.label(),
            "requires_consent": m.safety.requires_consent,
            "consent_message": m.safety.consent_message,
            "allowed_targets": m.safety.allowed_targets,
            "max_concurrent": m.safety.max_concurrent,
            "max_per_hour": m.safety.max_per_hour,
            "capabilities": m.safety.capabilities,
        },
        "dependencies": { "binaries": m.dependencies.binaries },
        "available": m.available,
        "missing_binaries": m.missing_binaries,
        "enabled": enabled,
        "source": m.source.display().to_string(),
    })
}

fn field_to_json(f: &FieldSpec) -> Value {
    json!({
        "id": f.id,
        "label": f.label,
        "type": field_type_label(f.ftype),
        "required": f.required,
        "default": f.default,
        "placeholder": f.placeholder,
        "help": f.help,
        "pattern": f.pattern,
        "message": f.message,
        "options": f.options.iter().map(|o| json!({"value": o.value, "label": o.label})).collect::<Vec<_>>(),
        "min": f.min,
        "max": f.max,
    })
}

fn field_type_label(t: FieldType) -> &'static str {
    match t {
        FieldType::String => "string",
        FieldType::Text => "text",
        FieldType::Integer => "integer",
        FieldType::Boolean => "boolean",
        FieldType::Select => "select",
    }
}

async fn enabled_map(state: &SharedState) -> BTreeMap<String, bool> {
    secuscan_db::repo::misc::enabled_map(&state.db)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect()
}

async fn list(State(state): State<SharedState>, _user: CurrentUser) -> ApiResult<Json<Value>> {
    let enabled = enabled_map(&state).await;
    let registry = state.registry.read().await;
    let items: Vec<Value> = registry
        .all()
        .iter()
        .map(|m| {
            let is_enabled = *enabled.get(&m.plugin.id).unwrap_or(&true);
            manifest_to_json(m, is_enabled)
        })
        .collect();
    Ok(Json(json!({
        "items": items,
        "issues": registry.issues().iter().map(|i| json!({
            "file": i.file,
            "plugin_id": i.plugin_id,
            "error": i.error,
        })).collect::<Vec<_>>(),
    })))
}

async fn get_one(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let enabled = enabled_map(&state).await;
    let registry = state.registry.read().await;
    let m = registry
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("plugin {id}")))?;
    Ok(Json(manifest_to_json(
        m,
        *enabled.get(&id).unwrap_or(&true),
    )))
}

async fn schema(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let registry = state.registry.read().await;
    let m = registry
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("plugin {id}")))?;
    Ok(Json(json!({
        "id": m.plugin.id,
        "fields": m.fields.iter().map(field_to_json).collect::<Vec<_>>(),
        "presets": m.presets,
        "preset_meta": m.preset_meta,
    })))
}

#[derive(serde::Deserialize)]
struct PreviewRequest {
    #[serde(default)]
    inputs: BTreeMap<String, Value>,
    #[serde(default)]
    preset: Option<String>,
}

async fn preview(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<PreviewRequest>,
) -> ApiResult<Json<Value>> {
    let manifest = {
        let registry = state.registry.read().await;
        registry
            .get(&id)
            .ok_or_else(|| ApiError::NotFound(format!("plugin {id}")))?
            .clone()
    };
    let mut inputs = req.inputs;
    if let Some(preset_name) = req.preset {
        if let Some(preset) = manifest.presets.get(&preset_name) {
            for (k, v) in preset {
                inputs.entry(k.clone()).or_insert_with(|| v.clone());
            }
        } else {
            return Err(ApiError::BadRequest(format!(
                "unknown preset `{preset_name}`"
            )));
        }
    }
    let normalized = normalize_inputs(&manifest, &inputs)?;
    let command = match &manifest.engine {
        EngineSpec::Cli { .. } => Some(preview_command(&manifest.engine, &normalized)?),
        EngineSpec::Native { native, .. } => Some(format!("native:{native}")),
    };
    Ok(Json(json!({
        "command": command,
        "inputs": normalized,
    })))
}

#[derive(serde::Deserialize)]
struct SetEnabledRequest {
    enabled: bool,
}

async fn set_enabled(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<SetEnabledRequest>,
) -> ApiResult<StatusCode> {
    user.require_admin()?;
    {
        let registry = state.registry.read().await;
        if registry.get(&id).is_none() {
            return Err(ApiError::NotFound(format!("plugin {id}")));
        }
    }
    secuscan_db::repo::misc::set_plugin_enabled(&state.db, &id, req.enabled).await?;
    Ok(StatusCode::NO_CONTENT)
}
