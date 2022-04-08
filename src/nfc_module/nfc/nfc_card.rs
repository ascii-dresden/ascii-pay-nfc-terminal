use pcsc;

use super::utils::*;

pub struct NfcCard {
    card: pcsc::Card,
}

impl NfcCard {
    pub fn new(card: pcsc::Card) -> Self {
        NfcCard { card }
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
}
