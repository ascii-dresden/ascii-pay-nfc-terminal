lazy_static::lazy_static! {
    pub static ref QR_SCANNER: String = std::env::var("QR_SCANNER").unwrap_or_else(|_| "".to_owned());
}
