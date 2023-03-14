use pcsc;

use crate::websocket_server::CardTypeDto;

use super::{simulation_card::SimulationCard, utils::*};

enum NfcCardImpl {
    Pcsc(pcsc::Card),
    Simulation(SimulationCard),
}

pub struct NfcCard {
    card: NfcCardImpl,
    id: Option<Vec<u8>>,
    auth_data: Vec<u8>,
    card_type: Option<CardTypeDto>,
}

impl NfcCard {
    pub fn new(card: pcsc::Card) -> Self {
        NfcCard {
            card: NfcCardImpl::Pcsc(card),
            id: None,
            auth_data: Vec::new(),
            card_type: None,
        }
    }
    pub fn simulate(card: SimulationCard) -> Self {
        NfcCard {
            card: NfcCardImpl::Simulation(card),
            id: None,
            auth_data: Vec::new(),
            card_type: None,
        }
    }

    pub fn get_attribute(&self, attribute: pcsc::Attribute) -> NfcResult<Vec<u8>> {
        match self.card {
            NfcCardImpl::Pcsc(ref card) => {
                let data_len = card.get_attribute_len(attribute)?;

                let mut data_buf = vec![0; data_len];
                let data = card.get_attribute(attribute, &mut data_buf)?;

                Ok(data.to_vec())
            }
            NfcCardImpl::Simulation(ref card) => card.get_attribute(attribute),
        }
    }

    pub fn transmit(&self, query: &[u8]) -> NfcResult<Vec<u8>> {
        match self.card {
            NfcCardImpl::Pcsc(ref card) => {
                println!("transmit {:X?}", query);
                let mut data_buf = [0; pcsc::MAX_BUFFER_SIZE];
                let data = card.transmit(query, &mut data_buf)?;

                Ok(data.to_vec())
            }
            NfcCardImpl::Simulation(ref card) => card.transmit(query),
        }
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

    pub fn set_id(&mut self, id: Vec<u8>) {
        self.id = Some(id);
    }

    pub fn get_id(&self) -> Option<Vec<u8>> {
        self.id.clone()
    }
}
