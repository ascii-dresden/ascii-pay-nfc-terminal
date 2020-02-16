lazy_static::lazy_static! {
    /// Host name of the application. The web server only listens to request with a matching host name.
    ///
    /// Field name: `HOST`
    pub static ref HOST: String = std::env::var("HOST").unwrap_or_else(|_| "localhost".to_owned());
}

lazy_static::lazy_static! {
    /// The application port.
    ///
    /// Field name: `PORT`
    pub static ref PORT: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "".to_string())
        .parse::<u16>()
        .unwrap_or(8000);
}

lazy_static::lazy_static! {
    pub static ref QR_SCANNER: String = std::env::var("QR_SCANNER").unwrap_or_else(|_| "".to_owned());
}

lazy_static::lazy_static! {
    pub static ref SERVER_DOMAIN: String = std::env::var("SERVER_DOMAIN").unwrap_or_else(|_| "localhost".to_owned());
}

lazy_static::lazy_static! {
    pub static ref LOCAL_DOMAIN: String = std::env::var("LOCAL_DOMAIN").unwrap_or_else(|_| "localhost".to_owned());
}

lazy_static::lazy_static! {
    pub static ref BASE_URL: String = std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_owned());
}
