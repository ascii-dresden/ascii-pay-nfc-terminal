use std::sync::mpsc::Sender;

use super::nfc_card_handler::NfcCardHandler;
use crate::nfc::{utils, NfcCard, NfcResult};
use crate::nfc_module::identify_atr;
use crate::Message;

const MIFARE_CLASSIC_ID_REQUEST: [u8; 5] = hex!("FF CA 00 00 00");

pub struct UnsupportedCardHandler {
    card: NfcCard,
}

impl NfcCardHandler for UnsupportedCardHandler {
    fn check_combatibitility(atr: &[u8]) -> bool {
        true
    }

    fn new(card: NfcCard) -> Self {
        Self { card }
    }

    fn finish(self) -> NfcCard {
        self.card
    }

    fn handle_authentication(&self, sender: &Sender<Message>) -> NfcResult<()> {
        println!("Trying to authenticate an unsupported nfc card!");
        let atr = self.card.get_atr()?;
        println!("   ATR: {}", utils::bytes_to_string(&atr));

        let ident = identify_atr(&atr);
        for line in ident {
            println!("        {}", line);
        }

        let mifare_classic_id = self.card.transmit(&MIFARE_CLASSIC_ID_REQUEST)?;
        println!(
            "    MiFare Classic ID: {}",
            utils::bytes_to_string(&mifare_classic_id)
        );
        println!("    If this ID does not change between different authentication attempts");
        println!("    but is unique between different cards, support for this card type can");
        println!("    be added via the generic MiFareClassicHandler by adding this ATR:");
        println!("    {}", utils::bytes_to_bytestring(&atr));

        Ok(())
    }

    fn handle_payment(&self, sender: &Sender<Message>, amount: i32) -> NfcResult<()> {
        Ok(())
    }
}
