use pbkdf2::password_hash::SaltString;
use rusqlite::Connection;
use std::path::Path;

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
    conn: Connection,
    password_salt: SaltString,
}

impl Database {
    pub fn new(db_path: impl AsRef<Path>, salt: &str) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        let password_salt = SaltString::from_b64(salt).map_err(Error::Pbkdf2)?;
        let database = Database {
            conn,
            password_salt,
        };
        database.init()?;
        Ok(database)
    }

    pub fn init(&self) -> Result<()> {
        self.conn
            .execute_batch(include_str!("../../schema/schema.sql"))?;
        Ok(())
    }

    pub fn transaction(&mut self) -> Result<Tx<'_>> {
        let tx = self.conn.transaction()?;
        Tx::new(tx)
    }
}

pub struct Tx<'a> {
    tx: rusqlite::Transaction<'a>,
}

impl<'a> Tx<'a> {
    pub fn new(tx: rusqlite::Transaction<'a>) -> Result<Self> {
        tracing::trace!("[database] BEGIN TRANSACTION");
        Ok(Tx { tx })
    }

    pub fn commit(&mut self) -> Result<()> {
        tracing::trace!("[database] COMMIT TRANSACTION");
        self.tx.set_drop_behavior(rusqlite::DropBehavior::Commit);
        Ok(())
    }

    pub fn inner(&self) -> &rusqlite::Transaction<'a> {
        &self.tx
    }
}

impl Drop for Tx<'_> {
    fn drop(&mut self) {
        tracing::trace!("[database] DROP TRANSACTION");
    }
}
