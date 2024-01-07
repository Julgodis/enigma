use pbkdf2::password_hash::{PasswordHasher, PasswordVerifier, SaltString};
use pbkdf2::{password_hash::PasswordHash, Pbkdf2};

use crate::Result;
use crate::{Database, Error};

impl Database {
    pub fn hash_password(&self, password_salt: &SaltString, password: &str) -> Result<String> {
        let password_hash = Pbkdf2
            .hash_password(password.as_bytes(), password_salt)
            .map_err(Error::Pbkdf2)?
            .to_string();

        Ok(password_hash)
    }

    pub fn verify_password(
        password: &str,
        password_hash: &str,
        _password_salt: &SaltString,
        _password_method: &str,
    ) -> Result<bool> {
        let parsed_hash = PasswordHash::new(password_hash).map_err(Error::Pbkdf2)?;
        Ok(Pbkdf2
            .verify_password(password.as_bytes(), &parsed_hash)
            .map(|_| true)
            .unwrap_or(false))
    }
}
