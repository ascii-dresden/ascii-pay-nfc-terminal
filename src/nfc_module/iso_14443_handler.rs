use log::info;

use crate::{application::ApplicationResponseContext, ServiceResult};

use super::nfc::{Iso14443Card, NfcCard};

const ASCII_APPLICATION: [u8; 7] = hex!("F0 00 00 00 C0 FF EE");

pub struct Iso14443Handler {
    card: Iso14443Card,
}

impl Iso14443Handler {
    fn get_card_id(&mut self) -> ServiceResult<Vec<u8>> {
        if let Some(id) = self.card.card.get_id() {
            return Ok(id);
        }

        let card_id = self.card.get_id()?;
        self.card.card.set_id(card_id.clone());
        Ok(card_id)
    }

    pub fn check_compatibility(atr: &[u8]) -> bool {
        match atr {
            b"\x3B\x8F\x80\x01\x80\x4F\x0C\xA0\x00\x00\x03\x06\x11\x00\x3B\x00\x00\x00\x00\x42" => {
                info!("Insert 'MiFare DESFire' card");
                true
            }
            b"\x3B\x80\x80\x01\x01" => {
                info!("Insert 'MiFare DESFire' card");
                true
            }
            _ => false,
        }
    }

    pub fn new(card: NfcCard) -> Self {
        Self {
            card: Iso14443Card::new(card),
        }
    }

    pub fn finish(self) -> NfcCard {
        self.card.into()
    }

    pub async fn handle_card_authentication(
        &mut self,
        context: &ApplicationResponseContext,
    ) -> ServiceResult<()> {
        let card_id = self.get_card_id()?;

        context
            .send_nfc_identify_request(card_id, "Generic NFC Card".into())
            .await;

        Ok(())
    }

    pub async fn handle_card_identify_response(
        &mut self,
        context: &ApplicationResponseContext,
        card_id: Vec<u8>,
    ) -> ServiceResult<()> {
        let card_id = self.get_card_id()?;

        let ek_rndB = self.card.authenticate_phase1()?;
        context.send_nfc_challenge_request(card_id, ek_rndB).await;

        Ok(())
    }

    pub async fn handle_card_challenge_response(
        &self,
        context: &ApplicationResponseContext,
        card_id: Vec<u8>,
        challenge: Vec<u8>,
    ) -> ServiceResult<()> {
        let dk_rndA_rndBshifted = challenge.clone();

        let ek_rndAshifted = self.card.authenticate_phase2(&dk_rndA_rndBshifted)?;
        context
            .send_nfc_response_request(card_id, challenge, ek_rndAshifted)
            .await;

        Ok(())
    }

    pub async fn handle_card_response_response(
        &self,
        context: &ApplicationResponseContext,
        card_id: Vec<u8>,
        session_key: Vec<u8>,
    ) -> ServiceResult<()> {
        // Nothing to do
        Ok(())
    }

    pub async fn handle_card_register(
        &self,
        context: &ApplicationResponseContext,
        card_id: Vec<u8>,
    ) -> ServiceResult<()> {
        // Currently not supported
        Ok(())
    }
}
