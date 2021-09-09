use derive_more::Display;

/// Represent errors in the application
///
/// All `ServiceError`s can be transformed to http errors.
#[derive(Debug, Display)]
pub enum ServiceError {
    #[display(fmt = "Bad Request: '{}'\n{}", _0, _1)]
    BadRequest(&'static str, String),

    #[display(fmt = "Internal Server Error: '{}'\n{}", _0, _1)]
    InternalServerError(&'static str, String),

    #[display(fmt = "Not Found")]
    NotFound,

    #[display(fmt = "Unauthorized")]
    Unauthorized,
}

/// Helper for `ServiceError` result
pub type ServiceResult<T> = Result<T, ServiceError>;

impl From<std::io::Error> for ServiceError {
    fn from(error: std::io::Error) -> Self {
        ServiceError::InternalServerError("IO error", format!("{}", error))
    }
}

impl From<serde_json::Error> for ServiceError {
    fn from(error: serde_json::Error) -> Self {
        ServiceError::InternalServerError("Serialization error", format!("{}", error))
    }
}

impl From<std::string::FromUtf8Error> for ServiceError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        ServiceError::InternalServerError("Utf8Encoding error", format!("{}", error))
    }
}

impl From<block_modes::InvalidKeyIvLength> for ServiceError {
    fn from(error: block_modes::InvalidKeyIvLength) -> Self {
        ServiceError::InternalServerError("Encryption error", format!("{}", error))
    }
}

impl From<block_modes::BlockModeError> for ServiceError {
    fn from(error: block_modes::BlockModeError) -> Self {
        ServiceError::InternalServerError("Encryption error", format!("{}", error))
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for ServiceError {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        ServiceError::InternalServerError("Websocket error", format!("{}", error))
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for ServiceError {
    fn from(error: tokio::sync::mpsc::error::SendError<T>) -> Self {
        ServiceError::InternalServerError("Internal communication error", format!("{}", error))
    }
}

impl From<grpc::Error> for ServiceError {
    fn from(error: grpc::Error) -> Self {
        ServiceError::InternalServerError("Grpc error", format!("{}", error))
    }
}

impl From<uuid::Error> for ServiceError {
    fn from(error: uuid::Error) -> Self {
        ServiceError::InternalServerError("Uuid parse error", format!("{}", error))
    }
}

impl From<tokio::task::JoinError> for ServiceError {
    fn from(error: tokio::task::JoinError) -> Self {
        ServiceError::InternalServerError("Tokio join error", format!("{}", error))
    }
}

impl From<crate::nfc_module::nfc::NfcError> for ServiceError {
    fn from(error: crate::nfc_module::nfc::NfcError) -> Self {
        ServiceError::InternalServerError("NFC error", format!("{:?}", error))
    }
}

#[cfg(target_os = "linux")]
impl From<pcsc::Error> for ServiceError {
    fn from(error: pcsc::Error) -> Self {
        ServiceError::InternalServerError("NFC error", format!("{}", error))
    }
}
