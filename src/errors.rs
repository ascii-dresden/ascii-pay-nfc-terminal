#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RemoteErrorType {
    NotFound,
    BadRequest,
    Unauthorized,
    Internal,
    Unavailable,
}

/// Represent errors in the application
///
/// All `ServiceError`s can be transformed to http errors.
#[derive(Debug)]
pub enum ServiceError {
    BadRequest(&'static str, String),

    InternalError(&'static str, String),

    RemoteError(RemoteErrorType, String),

    NotFound,

    Unauthorized,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Helper for `ServiceError` result
pub type ServiceResult<T> = Result<T, ServiceError>;

impl From<std::io::Error> for ServiceError {
    fn from(error: std::io::Error) -> Self {
        ServiceError::InternalError("IO error", format!("{error}"))
    }
}

impl From<std::fmt::Error> for ServiceError {
    fn from(error: std::fmt::Error) -> Self {
        ServiceError::InternalError("fmt error", format!("{error}"))
    }
}

impl From<serde_json::Error> for ServiceError {
    fn from(error: serde_json::Error) -> Self {
        ServiceError::InternalError("Serialization error", format!("{error}"))
    }
}

impl From<std::string::FromUtf8Error> for ServiceError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        ServiceError::InternalError("Utf8Encoding error", format!("{error}"))
    }
}

impl From<block_modes::InvalidKeyIvLength> for ServiceError {
    fn from(error: block_modes::InvalidKeyIvLength) -> Self {
        ServiceError::InternalError("Encryption error", format!("{error}"))
    }
}

impl From<block_modes::BlockModeError> for ServiceError {
    fn from(error: block_modes::BlockModeError) -> Self {
        ServiceError::InternalError("Encryption error", format!("{error}"))
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for ServiceError {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        ServiceError::InternalError("Websocket error", format!("{error}"))
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for ServiceError {
    fn from(error: tokio::sync::mpsc::error::SendError<T>) -> Self {
        ServiceError::InternalError("Internal communication error", format!("{error}"))
    }
}

impl From<tokio::task::JoinError> for ServiceError {
    fn from(error: tokio::task::JoinError) -> Self {
        ServiceError::InternalError("Tokio join error", format!("{error}"))
    }
}

impl From<crate::nfc_module::nfc::NfcError> for ServiceError {
    fn from(error: crate::nfc_module::nfc::NfcError) -> Self {
        ServiceError::InternalError("NFC error", format!("{error:?}"))
    }
}

#[cfg(target_os = "linux")]
impl From<pcsc::Error> for ServiceError {
    fn from(error: pcsc::Error) -> Self {
        ServiceError::InternalError("NFC error", format!("{}", error))
    }
}
