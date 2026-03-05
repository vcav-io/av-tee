use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RelayError {
    #[error("Contract validation failed: {0}")]
    ContractValidation(String),

    #[error("Prompt assembly error: {0}")]
    PromptAssembly(String),

    #[error("Provider error: {0}")]
    Provider(String),

    #[error("Output schema validation failed: {0}")]
    OutputValidation(String),

    #[error("Receipt signing failed: {0}")]
    ReceiptSigning(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Session not found")]
    SessionNotFound,
}

impl RelayError {
    fn status_code(&self) -> StatusCode {
        match self {
            RelayError::ContractValidation(_) | RelayError::PromptAssembly(_) => {
                StatusCode::BAD_REQUEST
            }
            RelayError::Provider(_) => StatusCode::BAD_GATEWAY,
            RelayError::OutputValidation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            RelayError::ReceiptSigning(_) | RelayError::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            RelayError::SessionNotFound => StatusCode::NOT_FOUND,
        }
    }
}

impl IntoResponse for RelayError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        // Sanitize 5xx errors — never expose internal details to clients
        let user_message = match &self {
            RelayError::ReceiptSigning(_) | RelayError::Internal(_) => "internal error".to_string(),
            _ => self.to_string(),
        };
        let body = serde_json::json!({
            "error": user_message,
        });
        (status, axum::Json(body)).into_response()
    }
}
