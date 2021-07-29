use std::sync::mpsc::Sender;

use super::nfc_card_handler::NfcCardHandler;
use crate::nfc::{utils, NfcCard, NfcResult};
use crate::utils::CheckedSender;
use crate::web::http_client::*;
use crate::Message;

const MIFARE_CLASSIC_ID_REQUEST: [u8; 5] = hex!("FF CA 00 00 00");

pub struct MiFareClassicHandler {
    card: NfcCard,
}

impl MiFareClassicHandler {
    fn get_card_id(&self) -> NfcResult<String> {
        let atr = self.card.get_atr()?;
        let id = self.card.transmit(&MIFARE_CLASSIC_ID_REQUEST)?;

        Ok(format!(
            "{}:{}",
            utils::bytes_to_string(&atr),
            utils::bytes_to_string(&id),
        ))
    }
}

impl NfcCardHandler for MiFareClassicHandler {
    fn check_combatibitility(atr: &[u8]) -> bool {
        match atr {
            b"\x3B\x8F\x80\x01\x80\x4F\x0C\xA0\x00\x00\x03\x06\x03\x00\x01\x00\x00\x00\x00\x6A" => {
                println!("Insert 'MiFare Classic' card");
                true
            }
            b"\x3B\x8C\x80\x01\x59\x75\x62\x69\x6B\x65\x79\x4E\x45\x4F\x72\x33\x58" => {
                println!("Insert 'Yubikey Neo' card");
                true
            }
            _ => false,
        }
    }

    fn new(card: NfcCard) -> Self {
        Self { card }
    }

    fn finish(self) -> NfcCard {
        self.card
    }

    fn handle_authentication(&self, sender: &Sender<Message>) -> NfcResult<()> {
        let card_id = self.get_card_id()?;

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
            IdentificationResponse::NotFound => {
                let atr = self.card.get_atr()?;
                sender.send_checked(Message::NfcCard {
                    id: card_id,
                    name: super::identify_atr(&atr)
                        .get(0)
                        .cloned()
                        .unwrap_or_else(|| "".to_owned()),
                    writeable: false,
                })
            }
            _ => {}
        };

        Ok(())
    }

    fn handle_payment(&self, sender: &Sender<Message>, amount: i32) -> NfcResult<()> {
        let card_id = self.get_card_id()?;

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
}
