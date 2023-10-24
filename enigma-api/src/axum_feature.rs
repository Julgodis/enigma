use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

impl IntoResponse for crate::Response {
    fn into_response(self) -> Response {
        match &self {
            Self::Error(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response(),
            _ => Json(self).into_response(),
        }
    }
}
