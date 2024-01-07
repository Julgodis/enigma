use chrono::DateTime;
use chrono::Days;
use chrono::Utc;
use enigma_api::Session;
use enigma_api::TrackInformation;
use kodama_api::query;
use kodama_api::query::param;
use kodama_api::query::IntoQuery;
use kodama_api::query::Query;
use kodama_api::DatabaseQuery;
use kodama_api::FromRow;
use kodama_api::Transaction;
use rusqlite::params;

use crate::Error;
use crate::Result;

use super::Database;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifySession {
    Session(Session),
    SessionNotFound,
    SessionExpired,
}

impl VerifySession {
    pub fn unwrap_session(self) -> Session {
        match self {
            VerifySession::Session(session) => session,
            _ => panic!("session not found or expired"),
        }
    }
}

impl Database {
    fn tx_create_session_token(
        tx: &Transaction<'_>,
        user_id: i64,
        track: TrackInformation,
    ) -> Result<String> {
        tracing::trace!("[database] tx_create_session_token");
        tracing::trace!("  user_id: {:?}", user_id);
        tracing::trace!("  track: {:?}", track);

        // try to create a session token
        let token_query = Query::select_from("sessions")
            .all_columns()
            .condition(query::eq("session_token", param(1)))
            .into_query();
        let mut token = uuid::Uuid::new_v4().to_string();
        let mut retries = 0;
        loop {
            let session_token = token_query.select_maybe::<()>(tx, params![token])?;
            if session_token.is_none() {
                break;
            } else if retries > 10 {
                return Err(Error::SessionCreationFailed);
            } else {
                token = uuid::Uuid::new_v4().to_string();
                retries += 1;
            }
        }

        let expiry_date = Utc::now()
            .checked_add_days(Days::new(7))
            .ok_or(Error::SessionCreationFailed)?;

        tracing::trace!("  token: {:?}", token);
        tracing::trace!("  expiry_date: {:?}", expiry_date);

        let insert_query = Query::insert_into("sessions")
            .column("user_id", param(1))
            .column("session_token", param(2))
            .column("expiry_date", param(3))
            .column("track_device", param(4))
            .column("track_user_agent", param(5))
            .column("track_ip_address", param(6))
            .column("track_location", param(7))
            .column("track_os", param(8))
            .column("track_browser", param(9))
            .column("track_screen_resolution", param(10))
            .column("track_timezone", param(11))
            .into_query();

        insert_query.insert(
            tx,
            params![
                user_id,
                token,
                expiry_date,
                track.device,
                track.user_agent,
                track.ip_address,
                track.location,
                track.os,
                track.browser,
                track.screen_resolution,
                track.timezone
            ],
        )?;

        Ok(token)
    }

    fn tx_get_session(tx: &Transaction<'_>, session_token: &str) -> Result<Session> {
        tracing::trace!("[database] tx_get_session: {:?}", session_token);

        struct InnerSession {
            user_id: i64,
            session_token: String,
            expiry_date: DateTime<Utc>,
            created_at: DateTime<Utc>,
            track_device: Option<String>,
            track_user_agent: Option<String>,
            track_ip_address: Option<String>,
            track_location: Option<String>,
            track_os: Option<String>,
            track_browser: Option<String>,
            track_screen_resolution: Option<String>,
            track_timezone: Option<String>,
        }

        impl FromRow for InnerSession {
            fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
                Ok(Self {
                    user_id: row.get("user_id")?,
                    session_token: row.get("session_token")?,
                    expiry_date: row.get("expiry_date")?,
                    created_at: row.get("created_at")?,
                    track_device: row.get("track_device")?,
                    track_user_agent: row.get("track_user_agent")?,
                    track_ip_address: row.get("track_ip_address")?,
                    track_location: row.get("track_location")?,
                    track_os: row.get("track_os")?,
                    track_browser: row.get("track_browser")?,
                    track_screen_resolution: row.get("track_screen_resolution")?,
                    track_timezone: row.get("track_timezone")?,
                })
            }
        }

        let inner_session = {
            let query = Query::select_from("sessions")
                .all_columns()
                .condition(query::eq("session_token", param(1)))
                .into_query();

            query
                .select_maybe::<InnerSession>(tx, params![session_token])?
                .ok_or(Error::SessionNotFound)?
        };

        let user = Self::tx_get_user_by_id(tx, inner_session.user_id)?;
        let session = Session {
            user,
            session_token: inner_session.session_token,
            expiry_date: inner_session.expiry_date,
            created_at: inner_session.created_at,
            track: TrackInformation {
                device: inner_session.track_device,
                user_agent: inner_session.track_user_agent,
                ip_address: inner_session.track_ip_address,
                location: inner_session.track_location,
                os: inner_session.track_os,
                browser: inner_session.track_browser,
                screen_resolution: inner_session.track_screen_resolution,
                timezone: inner_session.track_timezone,
            },
        };

        Ok(session)
    }

    fn tx_update_last_used(tx: &Transaction<'_>, session_token: &str) -> Result<()> {
        tracing::trace!("[database] tx_update_last_used: {:?}", session_token);

        let query = Query::update("sessions")
            .set("last_used_at", param(1))
            .condition(query::eq("session_token", param(2)))
            .into_query();

        query.update(tx, params![Utc::now(), session_token])?;

        Ok(())
    }

    pub fn create_session(
        &mut self,
        username: &str,
        password: &str,
        track: TrackInformation,
    ) -> Result<Session> {
        let tx = self.database.transaction()?;

        tracing::trace!("[database] create_session:");
        tracing::trace!("  username: {:?}", username);
        tracing::trace!("  password: [REDACTED]");
        tracing::trace!("  track: {:?}", track);

        let user_id = match Self::tx_verify_password(&tx, username, password) {
            Ok(Some(user_id)) => user_id,
            Ok(None) => return Err(Error::PasswordIncorrect),
            Err(err) => {
                tracing::warn!("failed to verify password: {:?}", err);
                return Err(err);
            }
        };

        let token = Self::tx_create_session_token(&tx, user_id, track)?;
        let session = Self::tx_get_session(&tx, &token)?;

        tx.commit()?;
        Ok(session)
    }

    pub fn verify_session(&mut self, session_token: &str) -> Result<VerifySession> {
        let tx = self.database.transaction()?;

        let session = match Self::tx_get_session(&tx, session_token) {
            Ok(session) => session,
            Err(Error::SessionNotFound) => return Ok(VerifySession::SessionNotFound),
            Err(err) => return Err(err),
        };

        if session.expiry_date < Utc::now() {
            return Ok(VerifySession::SessionExpired);
        }

        Self::tx_update_last_used(&tx, session_token)?;

        tx.commit()?;
        Ok(VerifySession::Session(session))
    }

    pub fn delete_session(&mut self, session_token: &str) -> Result<()> {
        let tx = self.database.transaction()?;

        {
            tracing::trace!("[database] delete_session: {:?}", session_token);
            let query = Query::delete_from("sessions")
                .condition(query::eq("session_token", param(1)))
                .into_query();

            query.delete(&tx, params![session_token])?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn delete_expired_sessions(&mut self) -> Result<()> {
        let tx = self.database.transaction()?;

        {
            tracing::trace!("[database] delete_expired_sessions");
            let query = Query::delete_from("sessions")
                .condition(query::lt("expiry_date", param(1)))
                .into_query();

            query.delete(&tx, params![Utc::now()])?;
        }

        tx.commit()?;
        Ok(())
    }
}
