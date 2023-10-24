use chrono::Days;
use chrono::Utc;
use enigma_api::Session;
use enigma_api::TrackInformation;
use rusqlite::params;

use crate::Error;
use crate::Result;

use super::Database;
use super::Tx;

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
    fn tx_create_session_token(tx: &Tx, user_id: i64, track: TrackInformation) -> Result<String> {
        tracing::trace!("[database] tx_create_session_token");
        tracing::trace!("  user_id: {:?}", user_id);
        tracing::trace!("  track: {:?}", track);

        // try to create a session token
        let mut token = uuid::Uuid::new_v4().to_string();
        let mut retries = 0;
        loop {
            let mut stmt = tx
                .inner()
                .prepare("SELECT * FROM sessions WHERE session_token = ?")?;
            let mut rows = stmt.query(params![token])?;
            if rows.next()?.is_none() {
                break;
            }
            if retries > 10 {
                return Err(Error::SessionCreationFailed);
            }
            token = uuid::Uuid::new_v4().to_string();
            retries += 1;
        }

        let expiry_date = Utc::now()
            .checked_add_days(Days::new(7))
            .ok_or(Error::SessionCreationFailed)?;

        tracing::trace!("  token: {:?}", token);
        tracing::trace!("  expiry_date: {:?}", expiry_date);

        let mut stmt = tx.inner().prepare("INSERT INTO sessions (user_id, session_token, expiry_date, track_device, track_user_agent, track_ip_address, track_location, track_os, track_browser, track_screen_resolution, track_timezone) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")?;
        let _ = stmt.execute(params![
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
        ])?;
        Ok(token.to_string())
    }

    fn tx_get_session(tx: &Tx, session_token: &str) -> Result<Session> {
        tracing::trace!("[database] tx_get_session: {:?}", session_token);

        let mut stmt = tx
            .inner()
            .prepare("SELECT * FROM sessions WHERE session_token = ?")?;
        let mut rows = stmt.query(params![session_token])?;

        let row = rows.next()?.ok_or(Error::SessionNotFound)?;
        let user_id = row.get("user_id")?;
        let session_token = row.get("session_token")?;
        let expiry_date = row.get("expiry_date")?;
        let created_at = row.get("created_at")?;
        let track = TrackInformation {
            device: row.get("track_device")?,
            user_agent: row.get("track_user_agent")?,
            ip_address: row.get("track_ip_address")?,
            location: row.get("track_location")?,
            os: row.get("track_os")?,
            browser: row.get("track_browser")?,
            screen_resolution: row.get("track_screen_resolution")?,
            timezone: row.get("track_timezone")?,
        };

        let user = Self::tx_get_user_by_id(tx, user_id)?;
        let session = Session {
            user,
            session_token,
            expiry_date,
            created_at,
            track,
        };

        Ok(session)
    }

    fn tx_update_last_used(tx: &Tx, session_token: &str) -> Result<()> {
        tracing::trace!("[database] tx_update_last_used: {:?}", session_token);
        let mut stmt = tx
            .inner()
            .prepare("UPDATE sessions SET last_used_at = ? WHERE session_token = ?")?;
        stmt.execute(params![Utc::now(), session_token])?;
        Ok(())
    }

    pub fn create_session(
        &mut self,
        username: &str,
        password: &str,
        track: TrackInformation,
    ) -> Result<Session> {
        let mut tx = self.transaction()?;

        tracing::trace!("[database] create_session:");
        tracing::trace!("  username: {:?}", username);
        tracing::trace!("  password: [REDACTED]");
        tracing::trace!("  track: {:?}", track);

        let (user_id, password_hash) = Self::tx_get_user_password(&tx, username)?;
        if !Self::verify_password(password, &password_hash)? {
            return Err(Error::PasswordIncorrect);
        }

        let token = Self::tx_create_session_token(&tx, user_id, track)?;
        let session = Self::tx_get_session(&tx, &token)?;

        tx.commit()?;
        Ok(session)
    }

    pub fn verify_session(&mut self, session_token: &str) -> Result<VerifySession> {
        let mut tx = self.transaction()?;

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
        let mut tx = self.transaction()?;

        {
            tracing::trace!("[database] delete_session: {:?}", session_token);
            let mut stmt = tx
                .inner()
                .prepare("DELETE FROM sessions WHERE session_token = ?")?;
            stmt.execute(params![session_token])?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn delete_expired_sessions(&mut self) -> Result<()> {
        let mut tx = self.transaction()?;

        {
            tracing::trace!("[database] delete_expired_sessions");
            let mut stmt = tx
                .inner()
                .prepare("DELETE FROM sessions WHERE expiry_date < ?")?;
            stmt.execute(params![Utc::now()])?;
        }

        tx.commit()?;
        Ok(())
    }
}
