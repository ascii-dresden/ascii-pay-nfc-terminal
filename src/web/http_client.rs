use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_json::Value;
use std::marker::Sized;
use std::time::Duration;

use crate::{env, ServiceResult};

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum IdentificationRequest {
    Barcode {
        code: String,
    },
    Nfc {
        id: String,
    },
    NfcSecret {
        id: String,
        challenge: String,
        response: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum IdentificationResponse {
    Account {
        account: Value,
    },
    Product {
        product: Value,
    },
    AuthenticationNeeded {
        id: String,
        key: String,
        challenge: String,
    },
    WriteKey {
        id: String,
        key: String,
        secret: String,
    },
    NotFound,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum Authentication {
    Barcode {
        code: String,
    },
    Nfc {
        id: String,
    },
    NfcSecret {
        id: String,
        challenge: String,
        response: String,
    },
}

#[derive(Debug, Serialize)]
pub struct TokenRequest {
    pub amount: i32,
    pub method: Authentication,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum TokenResponse {
    Authorized {
        token: String,
    },
    AuthenticationNeeded {
        id: String,
        key: String,
        challenge: String,
    },
}

pub fn send_request<T, R>(url: &str, body: T) -> ServiceResult<R>
where
    T: Serialize + Sized,
    R: DeserializeOwned,
{
    let client = reqwest::blocking::Client::new();

    let response = client
        .post(url)
        .timeout(Duration::from_secs(10))
        .json(&body)
        .send()?;

    Ok(response.json()?)
}

pub fn send_identify(body: IdentificationRequest) -> ServiceResult<IdentificationResponse> {
    let client = reqwest::blocking::Client::new();

    let url = format!("{}/api/v1/identify", env::BASE_URL.as_str());

    let response = client
        .post(&url)
        .timeout(Duration::from_secs(10))
        .json(&body)
        .send()?;

    if response.status().as_u16() == 404 {
        return Ok(IdentificationResponse::NotFound);
    }

    Ok(response.json()?)
}

pub fn send_token_request(body: TokenRequest) -> ServiceResult<TokenResponse> {
    let url = format!("{}/api/v1/transaction/token", env::BASE_URL.as_str());
    send_request(&url, body)
}
