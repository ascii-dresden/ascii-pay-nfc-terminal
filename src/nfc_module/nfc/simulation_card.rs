use crate::nfc_module::nfc::utils::bytes_to_string;

use super::NfcResult;

pub struct SimulationCard {}

impl SimulationCard {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {}
    }

    pub fn get_attribute(&self, attribute: pcsc::Attribute) -> NfcResult<Vec<u8>> {
        println!("[SimulationCard::get_attribute] {attribute:?}");

        match attribute {
            pcsc::Attribute::AtrString => {
                Ok(hex!("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 6A").into())
            }
            _ => Ok(Vec::new()),
        }
    }

    pub fn transmit(&self, query: &[u8]) -> NfcResult<Vec<u8>> {
        println!("[SimulationCard::transmit] {}", bytes_to_string(query));

        if query == hex!("FF CA 00 00 00") {
            return Ok(hex!("7b 3b b7 87 88 10 20 42").into());
        }

        Ok(Vec::new())
    }
}
