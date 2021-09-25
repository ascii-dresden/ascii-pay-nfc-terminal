use log::info;
use uuid::Uuid;

use crate::{
    application::ApplicationResponseContext,
    nfc_module::{identify_atr, nfc::utils},
    ServiceResult,
};

use super::nfc::NfcCard;

const MIFARE_CLASSIC_ID_REQUEST: [u8; 5] = hex!("FF CA 00 00 00");

pub struct UnsupportedCardHandler {
    card: NfcCard,
}

impl UnsupportedCardHandler {
    pub fn check_combatibitility(atr: &[u8]) -> bool {
        true
    }

    pub fn new(card: NfcCard) -> Self {
        Self { card }
    }

    pub fn finish(self) -> NfcCard {
        self.card
    }
    pub async fn handle_card_authentication(
        &self,
        context: &ApplicationResponseContext,
    ) -> ServiceResult<()> {
        info!("Trying to authenticate an unsupported nfc card!");
        let atr = self.card.get_atr()?;
        info!("   ATR: {}", utils::bytes_to_string(&atr));

        let ident = identify_atr(&atr).await;
        for line in ident {
            info!("        {}", line);
        }

        let mifare_classic_id = self.card.transmit(&MIFARE_CLASSIC_ID_REQUEST)?;
        info!(
            "    MiFare Classic ID: {}",
            utils::bytes_to_string(&mifare_classic_id)
        );
        info!("    If this ID does not change between different authentication attempts");
        info!("    but is unique between different cards, support for this card type can");
        info!("    be added via the generic MiFareClassicHandler by adding this ATR:");
        info!("    {}", utils::bytes_to_bytestring(&atr));

        Ok(())
    }

    pub async fn handle_card_init(
        &self,
        context: &ApplicationResponseContext,
        account_id: Uuid,
    ) -> ServiceResult<()> {
        Ok(())
    }
}
