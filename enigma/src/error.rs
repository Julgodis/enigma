#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("pbkdf2 error: {0}")]
    Pbkdf2(pbkdf2::password_hash::Error),

    #[error("user not found")]
    UserNotFound,
    #[error("password incorrect")]
    PasswordIncorrect,
    #[error("session creation failed")]
    SessionCreationFailed,
    #[error("session not found")]
    SessionNotFound,
}
