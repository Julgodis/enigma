use anyhow::Context;
use axum::{
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use enigma::{Database, VerifySession};
use enigma_api::{SessionCreate, SessionVerify, TrackInformation};
use std::{net::SocketAddr, path::PathBuf};

mod error;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().expect("unable to load .env file");

    tracing_subscriber::fmt::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .init();

    tracing::info!("enigma (v{})", env!("CARGO_PKG_VERSION"));

    let listen = dotenvy::var("ENIGMA_LISTEN")
        .context("ENIGMA_LISTEN not set")?
        .parse::<SocketAddr>()?;

    // Build our application with a single route
    let app = Router::new()
        .route("/session/create", post(session_create))
        .route("/session/verify", post(session_verify))
        .route("/qr/generate", get(generate_qr))
        .route("/qr/auth", get(authenticate_qr));

    // Run it with hyper on a specified address
    tracing::debug!("listening on {}", listen);
    axum::Server::bind(&listen)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

fn initialize_database() -> Result<Database> {
    let database_path = dotenvy::var("ENIGMA_DATABASE_PATH")?
        .parse::<PathBuf>()
        .expect("parse::<PathBuf> will never fail");
    let salt = dotenvy::var("ENIGMA_PASSWORD_SALT")?;
    let database = Database::new(database_path, &salt)?;
    Ok(database)
}

#[axum_macros::debug_handler]
async fn session_create(Json(input): Json<SessionCreate>) -> Result<enigma_api::Response> {
    let mut database = initialize_database()?;

    let SessionCreate {
        username,
        password,
        device,
        user_agent,
        ip_address,
        location,
        os,
        browser,
        screen_resolution,
        timezone,
    } = input;

    let track = TrackInformation {
        device,
        user_agent,
        ip_address,
        location,
        os,
        browser,
        screen_resolution,
        timezone,
    };

    let session = database.create_session(&username, &password, track);
    match session {
        Ok(session) => Ok(enigma_api::Response::SessionCreated(session)),
        Err(enigma::Error::UserNotFound | enigma::Error::PasswordIncorrect) => {
            Ok(enigma_api::Response::UserOrPasswordIncorrect)
        },
        Err(err) => Err(err.into()),
    }
}

#[axum_macros::debug_handler]
async fn session_verify(Json(input): Json<SessionVerify>) -> Result<enigma_api::Response> {
    let mut database = initialize_database()?;
    match database.verify_session(&input.session_token)? {
        VerifySession::Session(session) => Ok(enigma_api::Response::SessionVerified(session)),
        VerifySession::SessionNotFound => Ok(enigma_api::Response::SessionNotFound),
        VerifySession::SessionExpired => Ok(enigma_api::Response::SessionExpired),
    }
}

async fn generate_qr() -> impl axum::response::IntoResponse {
    // Handle QR code generation
    "QR code generated"
}

async fn authenticate_qr() -> impl axum::response::IntoResponse {
    // Handle authentication via QR code
    "QR code authenticated"
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        tracing::error!("{:?}", self);
        Json(enigma_api::Response::Error(self.to_string())).into_response()
    }
}
