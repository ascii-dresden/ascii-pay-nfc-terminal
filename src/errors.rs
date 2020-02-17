use actix_web::http::header::ToStrError;
use actix_web::{error::ResponseError, Error as ActixError, HttpResponse};
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

impl ServiceError {
    pub fn actix(self) -> ActixError {
        self.into()
    }
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

impl From<ToStrError> for ServiceError {
    fn from(error: ToStrError) -> Self {
        ServiceError::BadRequest(
            "Request contained invalid CRON_SECRET header value",
            format!("{}", error),
        )
    }
}

impl From<reqwest::Error> for ServiceError {
    fn from(error: reqwest::Error) -> Self {
        ServiceError::InternalServerError("Http request failed", format!("{}", error))
    }
}

/*
/// nightly - allow `?` on Option<T> to unwrap
impl From<std::option::NoneError> for ServiceError {
    fn from(error: std::option::NoneError) -> ServiceError {
        ServiceError::InternalServerError("None error", format!("{}", error))
    }
}
*/

/// Transform `ServiceError` to `HttpResponse`
impl ResponseError for ServiceError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ServiceError::InternalServerError(ref source, ref cause) => {
                HttpResponse::InternalServerError().json(json!({
                    "message": "Internal Server Error, Please try again later",
                    "source": source,
                    "cause": cause
                }))
            }
            ServiceError::BadRequest(ref source, ref cause) => {
                HttpResponse::BadRequest().json(json!({
                    "message": "Internal Server Error, Please try again later",
                    "source": source,
                    "cause": cause
                }))
            }
            ServiceError::NotFound => HttpResponse::NotFound().json("NotFound"),
            ServiceError::Unauthorized => HttpResponse::Unauthorized().json("Unauthorized"),
        }
    }
}
