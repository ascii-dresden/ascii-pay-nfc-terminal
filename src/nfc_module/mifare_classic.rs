use std::sync::mpsc::Sender;

use crate::http_client::*;
use crate::nfc::{utils, NfcCard, NfcResult};
use crate::Message;

fn get_id(card: &NfcCard) -> NfcResult<Vec<u8>> {
    card.transmit(&hex!("FF CA 00 00 00"))
}

pub fn handle(sender: &Sender<Message>, card: &NfcCard) -> NfcResult<()> {
    let atr = card.get_atr()?;
    let card_id = format!(
        "{}:{}",
        utils::bytes_to_string(&atr),
        utils::bytes_to_string(&get_id(card)?),
    );

    let response = if let Some(response) = send_identify(IdentificationRequest::Nfc {
        id: card_id.clone(),
    }) {
        response
    } else {
        return Ok(());
    };

    match response {
        IdentificationResponse::Account { account } => {
            if sender.send(Message::Account { account }).is_err() {
                // TODO Error
            }
        }
        IdentificationResponse::Product { product } => {
            if sender.send(Message::Product { product }).is_err() {
                // TODO Error
            }
        }
        IdentificationResponse::NotFound => {
            if sender
                .send(Message::NfcCard {
                    id: card_id,
                    name: super::identify_atr(&atr)
                        .get(0)
                        .cloned()
                        .unwrap_or_else(|| "".to_owned()),
                    writeable: false,
                })
                .is_err()
            {
                // TODO Error
            }
        }
        _ => {}
    };

    Ok(())
}

pub fn handle_payment(sender: &Sender<Message>, card: &NfcCard, amount: i32) -> NfcResult<()> {
    let card_id = format!(
        "{}:{}",
        utils::bytes_to_string(&card.get_atr()?),
        utils::bytes_to_string(&get_id(card)?),
    );

    let response = if let Some(response) = send_token_request(TokenRequest {
        amount,
        method: Authentication::Nfc {
            id: card_id.clone(),
        },
    }) {
        response
    } else {
        return Ok(());
    };

    match response {
        TokenResponse::Authorized { token } => {
            if sender.send(Message::PaymentToken { token }).is_err() {
                // TODO Error
            }
        }
        _ => {}
    };

    Ok(())
}
