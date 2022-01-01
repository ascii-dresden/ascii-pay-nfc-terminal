use derive_more::Display;
use grpcio::RpcStatusCode;

#[derive(Debug, Display, PartialEq, Eq, Clone, Copy)]
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
#[derive(Debug, Display)]
pub enum ServiceError {
    #[display(fmt = "Bad Request: '{}'\n{}", _0, _1)]
    BadRequest(&'static str, String),

    #[display(fmt = "Internal Error: '{}'\n{}", _0, _1)]
    InternalError(&'static str, String),

    #[display(fmt = "{}: {}", _0, _1)]
    RemoteError(RemoteErrorType, String),

    #[display(fmt = "Not Found")]
    NotFound,

    #[display(fmt = "Unauthorized")]
    Unauthorized,
}

/// Helper for `ServiceError` result
pub type ServiceResult<T> = Result<T, ServiceError>;

impl From<std::io::Error> for ServiceError {
    fn from(error: std::io::Error) -> Self {
        ServiceError::InternalError("IO error", format!("{}", error))
    }
}

impl From<std::fmt::Error> for ServiceError {
    fn from(error: std::fmt::Error) -> Self {
        ServiceError::InternalError("fmt error", format!("{}", error))
    }
}

impl From<serde_json::Error> for ServiceError {
    fn from(error: serde_json::Error) -> Self {
        ServiceError::InternalError("Serialization error", format!("{}", error))
    }
}

impl From<std::string::FromUtf8Error> for ServiceError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        ServiceError::InternalError("Utf8Encoding error", format!("{}", error))
    }
}

impl From<block_modes::InvalidKeyIvLength> for ServiceError {
    fn from(error: block_modes::InvalidKeyIvLength) -> Self {
        ServiceError::InternalError("Encryption error", format!("{}", error))
    }
}

impl From<block_modes::BlockModeError> for ServiceError {
    fn from(error: block_modes::BlockModeError) -> Self {
        ServiceError::InternalError("Encryption error", format!("{}", error))
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for ServiceError {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        ServiceError::InternalError("Websocket error", format!("{}", error))
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for ServiceError {
    fn from(error: tokio::sync::mpsc::error::SendError<T>) -> Self {
        ServiceError::InternalError("Internal communication error", format!("{}", error))
    }
}

impl From<grpcio::Error> for ServiceError {
    fn from(error: grpcio::Error) -> Self {
        if let grpcio::Error::RpcFailure(status) = &error {
            match status.code() {
                RpcStatusCode::NOT_FOUND => {
                    ServiceError::RemoteError(RemoteErrorType::NotFound, status.message().into())
                }
                RpcStatusCode::INVALID_ARGUMENT => {
                    ServiceError::RemoteError(RemoteErrorType::BadRequest, status.message().into())
                }
                RpcStatusCode::UNAUTHENTICATED => ServiceError::RemoteError(
                    RemoteErrorType::Unauthorized,
                    status.message().into(),
                ),
                RpcStatusCode::INTERNAL => {
                    ServiceError::RemoteError(RemoteErrorType::Internal, status.message().into())
                }
                RpcStatusCode::UNAVAILABLE => ServiceError::RemoteError(
                    RemoteErrorType::Unavailable,
                    "Could not connect to payment service!".into(),
                ),
                _ => ServiceError::InternalError("Grpc error", format!("{}", error)),
            }
        } else {
            ServiceError::InternalError("Grpc error", format!("{}", error))
        }
    }
}

impl From<uuid::Error> for ServiceError {
    fn from(error: uuid::Error) -> Self {
        ServiceError::InternalError("Uuid parse error", format!("{}", error))
    }
}

impl From<tokio::task::JoinError> for ServiceError {
    fn from(error: tokio::task::JoinError) -> Self {
        ServiceError::InternalError("Tokio join error", format!("{}", error))
    }
}

impl From<crate::nfc_module::nfc::NfcError> for ServiceError {
    fn from(error: crate::nfc_module::nfc::NfcError) -> Self {
        ServiceError::InternalError("NFC error", format!("{:?}", error))
    }
}

#[cfg(target_os = "linux")]
impl From<pcsc::Error> for ServiceError {
    fn from(error: pcsc::Error) -> Self {
        ServiceError::InternalServerError("NFC error", format!("{}", error))
    }
}
