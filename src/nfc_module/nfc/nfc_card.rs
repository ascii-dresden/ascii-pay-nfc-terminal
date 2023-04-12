use std::time::{SystemTime, UNIX_EPOCH};

use pcsc;

use crate::websocket_server::CardTypeDto;

use super::{simulation_card::SimulationCard, utils::*};

enum NfcCardImpl {
    Pcsc(pcsc::Card),
    Simulation(SimulationCard),
    Timeout(u64)
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
            NfcCardImpl::Timeout(_) => NfcResult::Err(NfcError::CommunicationError),
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
            NfcCardImpl::Timeout(_) => NfcResult::Err(NfcError::CommunicationError),
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
        if let NfcCardImpl::Simulation(_) = self.card {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        self.id.clone()
    }

    pub fn remove_card(&mut self) {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.card = NfcCardImpl::Timeout(time + 8);
    }

    pub fn has_timeout_occurred(&self) -> bool {
        match self.card {
            NfcCardImpl::Pcsc(_) => false,
            NfcCardImpl::Simulation(_) => false,
            NfcCardImpl::Timeout(timeout) => {
                let time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                time > timeout
            },
        }
    }
}
