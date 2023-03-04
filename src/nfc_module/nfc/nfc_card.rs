use pcsc;

use crate::websocket_server::CardTypeDto;

use super::utils::*;

pub struct NfcCard {
    card: pcsc::Card,
    auth_data: Vec<u8>,
    card_type: Option<CardTypeDto>,
}

impl NfcCard {
    pub fn new(card: pcsc::Card) -> Self {
        NfcCard {
            card,
            auth_data: Vec::new(),
            card_type: None,
        }
    }

    pub fn get_attribute(&self, attribute: pcsc::Attribute) -> NfcResult<Vec<u8>> {
        let data_len = self.card.get_attribute_len(attribute)?;

        let mut data_buf = vec![0; data_len];
        let data = self.card.get_attribute(attribute, &mut data_buf)?;

        Ok(data.to_vec())
    }

    pub fn transmit(&self, query: &[u8]) -> NfcResult<Vec<u8>> {
        let mut data_buf = [0; pcsc::MAX_BUFFER_SIZE];
        let data = self.card.transmit(query, &mut data_buf)?;

        Ok(data.to_vec())
    }

    pub fn get_atr(&self) -> NfcResult<Vec<u8>> {
        self.get_attribute(pcsc::Attribute::AtrString)
    }

    pub fn set_card_type(&mut self, card_type: Option<CardTypeDto>) {
        self.card_type = card_type
    }

    pub fn get_card_type(&self) -> Option<CardTypeDto> {
        self.card_type
    }

    pub fn set_auth_data(&mut self, data: Vec<u8>) {
        self.auth_data = data;
    }

    pub fn get_auth_data(&self) -> Vec<u8> {
        self.auth_data.clone()
    }
}
