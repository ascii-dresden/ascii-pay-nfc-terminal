use crate::{application::ApplicationResponseContext, ServiceResult};

use super::{
    nfc::NfcCard, GenericNfcHandler, Iso14443Handler, MiFareDESFireHandler, UnsupportedCardHandler,
};

pub enum NfcCardHandlerWrapper {
    MiFareDESFire(MiFareDESFireHandler),
    MiFareClassic(GenericNfcHandler),
    Iso14443(Iso14443Handler),
    UnsupportedCard(UnsupportedCardHandler),
}

impl NfcCardHandlerWrapper {
    pub fn new(card: NfcCard) -> Self {
        if let Ok(atr) = card.get_atr() {
            if Iso14443Handler::check_compatibility(&atr) {
                return Self::Iso14443(Iso14443Handler::new(card));
            }

            if MiFareDESFireHandler::check_compatibility(&atr) {
                return Self::MiFareDESFire(MiFareDESFireHandler::new(card));
            }

            if GenericNfcHandler::check_compatibility(&atr) {
                return Self::MiFareClassic(GenericNfcHandler::new(card));
            }
        }

        Self::UnsupportedCard(UnsupportedCardHandler::new(card))
    }

    pub fn finish(self) -> NfcCard {
        match self {
            Self::Iso14443(handler) => handler.finish(),
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
            Self::Iso14443(handler) => handler.handle_card_authentication(context).await,
            Self::MiFareDESFire(handler) => handler.handle_card_authentication(context).await,
            Self::MiFareClassic(handler) => handler.handle_card_authentication(context).await,
            Self::UnsupportedCard(handler) => handler.handle_card_authentication(context).await,
        }
    }

    pub async fn handle_card_identify_response(
        &mut self,
        context: &ApplicationResponseContext,
        card_id: Vec<u8>,
    ) -> ServiceResult<()> {
        match self {
            Self::Iso14443(handler) => {
                handler
                    .handle_card_identify_response(context, card_id)
                    .await
            }
            Self::MiFareDESFire(handler) => {
                handler
                    .handle_card_identify_response(context, card_id)
                    .await
            }
            Self::MiFareClassic(handler) => {
                handler
                    .handle_card_identify_response(context, card_id)
                    .await
            }
            Self::UnsupportedCard(handler) => {
                handler
                    .handle_card_identify_response(context, card_id)
                    .await
            }
        }
    }

    pub async fn handle_card_challenge_response(
        &self,
        context: &ApplicationResponseContext,
        card_id: Vec<u8>,
        challenge: Vec<u8>,
    ) -> ServiceResult<()> {
        match self {
            Self::Iso14443(handler) => {
                handler
                    .handle_card_challenge_response(context, card_id, challenge)
                    .await
            }
            Self::MiFareDESFire(handler) => {
                handler
                    .handle_card_challenge_response(context, card_id, challenge)
                    .await
            }
            Self::MiFareClassic(handler) => {
                handler
                    .handle_card_challenge_response(context, card_id, challenge)
                    .await
            }
            Self::UnsupportedCard(handler) => {
                handler
                    .handle_card_challenge_response(context, card_id, challenge)
                    .await
            }
        }
    }

    pub async fn handle_card_response_response(
        &self,
        context: &ApplicationResponseContext,
        card_id: Vec<u8>,
        session_key: Vec<u8>,
    ) -> ServiceResult<()> {
        match self {
            Self::Iso14443(handler) => {
                handler
                    .handle_card_response_response(context, card_id, session_key)
                    .await
            }
            Self::MiFareDESFire(handler) => {
                handler
                    .handle_card_response_response(context, card_id, session_key)
                    .await
            }
            Self::MiFareClassic(handler) => {
                handler
                    .handle_card_response_response(context, card_id, session_key)
                    .await
            }
            Self::UnsupportedCard(handler) => {
                handler
                    .handle_card_response_response(context, card_id, session_key)
                    .await
            }
        }
    }

    pub async fn handle_card_register(
        &self,
        context: &ApplicationResponseContext,
        card_id: Vec<u8>,
    ) -> ServiceResult<()> {
        match self {
            Self::Iso14443(handler) => handler.handle_card_register(context, card_id).await,
            Self::MiFareDESFire(handler) => handler.handle_card_register(context, card_id).await,
            Self::MiFareClassic(handler) => handler.handle_card_register(context, card_id).await,
            Self::UnsupportedCard(handler) => handler.handle_card_register(context, card_id).await,
        }
    }
}
