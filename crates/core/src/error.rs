use thiserror::Error;

/// Errors produced by the core crate.
#[derive(Debug, Error)]
pub enum CoreError {
    /// A plugin manifest failed structural or cross-reference validation.
    #[error("invalid manifest: {0}")]
    Manifest(String),

    /// User-supplied task inputs failed validation against a plugin schema.
    #[error("invalid input: {0}")]
    Input(String),

    /// A command template could not be rendered (unknown field, unsafe value…).
    #[error("command template error: {0}")]
    Template(String),

    /// Tool output could not be parsed.
    #[error("parse error: {0}")]
    Parse(String),

    /// Target rejected by the safety/network policy.
    #[error("target rejected: {0}")]
    Target(String),

    /// Manifest file could not be read or deserialized.
    #[error("manifest load error: {0}")]
    Load(String),
}

pub type CoreResult<T> = Result<T, CoreError>;
