#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database error: {0}")]
    Database(#[from] enigma::Error),
    #[error("dotenvy error: {0}")]
    Dotenvy(#[from] dotenvy::Error),
}
