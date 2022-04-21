lazy_static::lazy_static! {
    pub static ref QR_SCANNER: String = std::env::var("QR_SCANNER").unwrap_or_else(|_| "".to_owned());
    pub static ref SSL_ROOT_CERT: String = std::env::var("SSL_ROOT_CERT").unwrap_or_else(|_| "certificates/root.pem".to_owned());
    pub static ref SSL_CERT : String = std::env::var("SSL_CERT").unwrap_or_else(|_| "certificates/client.crt".to_owned());
    pub static ref SSL_PRIVATE_KEY: String = std::env::var("SSL_PRIVATE_KEY").unwrap_or_else(|_| "certificates/ascii-pay-client.pem".to_owned());
}
