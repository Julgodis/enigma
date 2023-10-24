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

#[derive(Debug, serde::Serialize)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum Response {
    UserOrPasswordIncorrect,
    SessionCreated(Session),
    SessionVerified(Session),
    SessionNotFound,
    SessionExpired,
    Error(String),
}
