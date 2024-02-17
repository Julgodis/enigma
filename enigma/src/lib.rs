use std::{net::SocketAddr, path::Path};

#[cfg(test)]
mod tests;

pub mod error;
pub mod password;
pub mod session;
pub mod user;

pub use error::Error;
pub use session::VerifySession;
pub type Result<T> = std::result::Result<T, Error>;

pub struct Database {
    database: kodama_api::Database,
}

impl Database {
    pub fn new(database_path: impl AsRef<Path>) -> Result<Self> {
        let database = kodama_api::DatabaseBuilder::new(database_path)
            .with_kodama(
                "enigma",
                "database",
                SocketAddr::from(([127, 0, 0, 1], 40092)),
            )
            .with_migration("001", include_str!("../../schema/001.sql"))
            .build()?;

        Ok(Database { database })
    }
}

use chrono::{DateTime, Utc};

#[cfg(feature = "axum")]
mod axum_feature;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub user: User,
    pub session_token: String,
    pub expiry_date: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub track: TrackInformation,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrackInformation {
    pub device: Option<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub location: Option<String>,
    pub os: Option<String>,
    pub browser: Option<String>,
    pub screen_resolution: Option<String>,
    pub timezone: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub permissions: Vec<Permission>,
}

impl User {
    pub fn has_permission(&self, site: &str, permission: &str) -> bool {
        self.permissions
            .iter()
            .any(|p| p.site == site && p.permission == permission)
    }

}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Permission {
    pub site: String,
    pub permission: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct SessionCreate {
    pub username: String,
    pub password: String,

    pub device: Option<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub location: Option<String>,
    pub os: Option<String>,
    pub browser: Option<String>,
    pub screen_resolution: Option<String>,
    pub timezone: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct SessionVerify {
    pub session_token: String,
}