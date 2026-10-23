//! Repositories: async functions over `SqlitePool`. All queries are
//! parameterized; no string interpolation of user data anywhere.

pub mod api_keys;
pub mod attack_surface;
pub mod auth_profiles;
pub mod branding;
pub mod collab;
pub mod finding_dedup;
pub mod findings;
pub mod misc;
pub mod notifications;
pub mod oob;
pub mod reports;
pub mod robots;
pub mod schedules;
pub mod tasks;
pub mod users;
pub mod v300_misc;
pub mod workflows;
pub mod workspaces;

pub use workspaces::WorkspaceScope;
