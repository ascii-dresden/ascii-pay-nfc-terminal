use std::sync::mpsc::Sender;

use crate::http_client::*;
use crate::nfc::{utils, NfcCard, NfcResult};
use crate::utils::CheckedSender;
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

    let response = if let Ok(response) = send_identify(IdentificationRequest::Nfc {
        id: card_id.clone(),
    }) {
        response
    } else {
        return Ok(());
    };

    match response {
        IdentificationResponse::Account { account } => {
            sender.send_checked(Message::Account { account });
        }
        IdentificationResponse::Product { product } => {
            sender.send_checked(Message::Product { product })
        }
        IdentificationResponse::NotFound => sender.send_checked(Message::NfcCard {
            id: card_id,
            name: super::identify_atr(&atr)
                .get(0)
                .cloned()
                .unwrap_or_else(|| "".to_owned()),
            writeable: false,
        }),
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

    let response = if let Ok(response) = send_token_request(TokenRequest {
        amount,
        method: Authentication::Nfc { id: card_id },
    }) {
        response
    } else {
        return Ok(());
    };

    if let TokenResponse::Authorized { token } = response {
        sender.send_checked(Message::PaymentToken { token })
    }

    Ok(())
}
