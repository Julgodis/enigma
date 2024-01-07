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
