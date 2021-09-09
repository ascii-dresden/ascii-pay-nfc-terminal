use uuid::Uuid;

use crate::{application::ApplicationResponseContext, ServiceResult};

use super::{nfc::NfcCard, GenericNfcHandler, MiFareDESFireHandler, UnsupportedCardHandler};

pub enum NfcCardHandlerWrapper {
    MiFareDESFire(MiFareDESFireHandler),
    MiFareClassic(GenericNfcHandler),
    UnsupportedCard(UnsupportedCardHandler),
}

impl NfcCardHandlerWrapper {
    pub fn new(card: NfcCard) -> Self {
        if let Ok(atr) = card.get_atr() {
            if MiFareDESFireHandler::check_combatibitility(&atr) {
                return Self::MiFareDESFire(MiFareDESFireHandler::new(card));
            }

            if GenericNfcHandler::check_combatibitility(&atr) {
                return Self::MiFareClassic(GenericNfcHandler::new(card));
            }
        }

        Self::UnsupportedCard(UnsupportedCardHandler::new(card))
    }

    pub fn finish(self) -> NfcCard {
        match self {
            Self::MiFareDESFire(handler) => handler.finish(),
            Self::MiFareClassic(handler) => handler.finish(),
            Self::UnsupportedCard(handler) => handler.finish(),
        }
    }

    pub async fn handle_card_authentication(
        &self,
        context: &ApplicationResponseContext,
    ) -> ServiceResult<()> {
        match self {
            Self::MiFareDESFire(handler) => handler.handle_card_authentication(context).await,
            Self::MiFareClassic(handler) => handler.handle_card_authentication(context).await,
            Self::UnsupportedCard(handler) => handler.handle_card_authentication(context).await,
        }
    }

    pub async fn handle_card_init(
        &self,
        context: &ApplicationResponseContext,
        account_id: Uuid,
    ) -> ServiceResult<()> {
        match self {
            Self::MiFareDESFire(handler) => handler.handle_card_init(context, account_id).await,
            Self::MiFareClassic(handler) => handler.handle_card_init(context, account_id).await,
            Self::UnsupportedCard(handler) => handler.handle_card_init(context, account_id).await,
        }
    }
}
