use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use crate::nfc::{NfcCard, NfcResult};
use crate::{ApplicationContext, Message};

mod nfc_card_handler;
pub use nfc_card_handler::NfcCardHandler;
mod mifare_classic_handler;
pub use mifare_classic_handler::MiFareClassicHandler;
mod mifare_desfire_handler;
pub use mifare_desfire_handler::MiFareDESFireHandler;
mod unsupported_card_handler;
pub use unsupported_card_handler::UnsupportedCardHandler;

mod nfc_reader;

pub use nfc_reader::identify_atr;

pub enum NfcCardHandlerWrapper {
    MiFareDESFire(MiFareDESFireHandler),
    MiFareClassic(MiFareClassicHandler),
    UnsupportedCard(UnsupportedCardHandler),
}

impl NfcCardHandler for NfcCardHandlerWrapper {
    fn check_combatibitility(atr: &[u8]) -> bool {
        true
    }

    fn new(card: NfcCard) -> Self {
        if let Ok(atr) = card.get_atr() {
            if MiFareDESFireHandler::check_combatibitility(&atr) {
                return Self::MiFareDESFire(MiFareDESFireHandler::new(card));
            }

            if MiFareClassicHandler::check_combatibitility(&atr) {
                return Self::MiFareClassic(MiFareClassicHandler::new(card));
            }
        }

        Self::UnsupportedCard(UnsupportedCardHandler::new(card))
    }

    fn finish(self) -> NfcCard {
        match self {
            Self::MiFareDESFire(handler) => handler.finish(),
            Self::MiFareClassic(handler) => handler.finish(),
            Self::UnsupportedCard(handler) => handler.finish(),
        }
    }

    fn handle_authentication(&self, sender: &Sender<Message>) -> NfcResult<()> {
        match self {
            Self::MiFareDESFire(handler) => handler.handle_authentication(sender),
            Self::MiFareClassic(handler) => handler.handle_authentication(sender),
            Self::UnsupportedCard(handler) => handler.handle_authentication(sender),
        }
    }

    fn handle_payment(&self, sender: &Sender<Message>, amount: i32) -> NfcResult<()> {
        match self {
            Self::MiFareDESFire(handler) => handler.handle_payment(sender, amount),
            Self::MiFareClassic(handler) => handler.handle_payment(sender, amount),
            Self::UnsupportedCard(handler) => handler.handle_payment(sender, amount),
        }
    }
}

pub fn get_nfc_handler(card: NfcCard) -> impl NfcCardHandler {
    NfcCardHandlerWrapper::new(card)
}

pub fn create(sender: Sender<Message>, context: Arc<Mutex<ApplicationContext>>) {
    nfc_reader::run(sender, context);
}
