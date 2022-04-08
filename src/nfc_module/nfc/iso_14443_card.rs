use log::info;

use super::utils::*;
use super::NfcCard;

pub struct Iso14443Card {
    pub card: NfcCard,
}

impl Iso14443Card {

    pub fn new(card: NfcCard) -> Self {
        Iso14443Card { card }
    }

    fn transmit(&self, command: u8, data: &[u8]) -> NfcResult<(bool, Vec<u8>)> {
        let mut raw = Vec::<u8>::with_capacity(data.len() + 1);

        raw.push(command);
        raw.extend(data);

        self.transmit_raw(&raw)
    }

    fn transmit_raw(&self, data: &[u8]) -> NfcResult<(bool, Vec<u8>)> {
        info!(
            "  Send Command: l={}, data={:2X?}",
            data.len(),
            data
        );

        let mut data = self.card.transmit(data)?;

        if data.is_empty() {
            return Err(NfcError::UnknownError);
        }

        info!("   --> l={}, data={:2X?}", data.len(), data);
        let status = data.remove(0) == 0x00;
        info!("   --> {:2X?}, l={}, data={:2X?}", status, data.len(), data);

        Ok((status, data))
    }

    pub fn get_id(&self) -> NfcResult<Vec<u8>> {
        let (success, id) = self.transmit_raw(&[
            0x00, // Class
            0xA4, // INS
            0x04, // P1
            0x00, // P2
            0x07, // Lc
            0xF0,
            0x00,
            0x00,
            0x00,
            0xC0,
            0xFF,
            0xEE,
        ])?;

        if !success {
            return Err(NfcError::UnknownError)
        }

        Ok(id)
    }

    #[allow(non_snake_case)]
    pub fn authenticate_phase1(&self) -> NfcResult<Vec<u8>> {
        let (success, ek_rndB) = self.transmit(0x10, &[])?;
        if !success {
            return Err(NfcError::UnknownError)
        }

        Ok(ek_rndB)
    }

    #[allow(non_snake_case)]
    pub fn authenticate_phase2(&self, dk_rndA_rndBshifted: &[u8]) -> NfcResult<Vec<u8>> {
        let (success, ek_rndAshifted_card) = self.transmit(0x11, dk_rndA_rndBshifted)?;
        if !success {
            return Err(NfcError::UnknownError)
        }

        Ok(ek_rndAshifted_card)
    }

    pub fn init(&self, key: &[u8]) -> NfcResult<()> {
        let (success, _) = self.transmit(0x20, key)?;
        if !success {
            return Err(NfcError::UnknownError)
        }

        Ok(())
    }
}

impl From<Iso14443Card> for NfcCard {
    fn from(card: Iso14443Card) -> Self {
        card.card
    }
}
